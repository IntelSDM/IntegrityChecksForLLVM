#include "IntegrityPass.h"

#include "llvm/ADT/Twine.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace llvm;

llvm::cl::opt<bool> IntegrityEnable("obfintegrity", llvm::cl::init(true), llvm::cl::desc("Master Toggle"));

static constexpr unsigned MinWindow = 128;
static constexpr unsigned MaxSitesPerFn = 256;

// These symbol strings MUST match IntegrityRuntime.cpp's exported function name byte for byte. The pass declares IntegrityHashWindow as external and the runtime defines it, so a rename on one side alone produces an unresolved external at link time
static constexpr const char* HashHelperName = "IntegrityHashWindow";
static constexpr const char* ConstTableName = "IntegrityConstTable";

// bug: these section names MUST match IntegrityStamp.cpp's MetaSectionName / TableSectionName byte for byte pass writes records to these fixed names at compile time and the stamper looks them up by name directly, so a rename on one side alone makes the stamper find nothing to stamp
static constexpr const char* MetaSectionName = ".int1";
static constexpr const char* TableSectionName = ".int2";

static unsigned NextSiteIdx = 0;

// bug: a zero key would make enc == plaintext XOR h and leak plaintext whenever the window hash is known — the final `x ? x : 1` guards against the Weyl step landing on zero
static uint64_t NextSiteKey()
{
    static uint64_t state = 0x243F6A8885A308D3ULL;
    state += 0x9E3779B97F4A7C15ULL;
    uint64_t x = state;
    x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ULL;
    x ^= x >> 27; x *= 0x94D049BB133111EBULL;
    x ^= x >> 31;
    return x ? x : 1;
}

static bool HasAnnotationTag(Function& f, const char* tag)
{
    Module* m = f.getParent();
    GlobalVariable* ga = m->getGlobalVariable("llvm.global.annotations");
    if (!ga) return false;

    ConstantArray* ca = dyn_cast<ConstantArray>(ga->getOperand(0));
    if (!ca) return false;

    for (unsigned i = 0; i < ca->getNumOperands(); ++i)
    {
        ConstantStruct* cs = dyn_cast<ConstantStruct>(ca->getOperand(i));
        if (!cs) continue;
        if (cs->getOperand(0)->stripPointerCasts() != &f) continue;

        auto* strgv = dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
        if (!strgv || !strgv->hasInitializer()) continue;

        auto* cds = dyn_cast<ConstantDataSequential>(strgv->getInitializer());
        if (!cds || !cds->isString()) continue;

        if (cds->getAsCString() == tag) return true;
    }
    return false;
}

static bool HasIntegrityAnnotation(Function& f)
{
    return HasAnnotationTag(f, "integrity");
}

static bool HasNoIntegrityAnnotation(Function& f)
{
    return HasAnnotationTag(f, "nointegrity");
}

static bool WantsIntegrity(Function& f)
{
    if (HasNoIntegrityAnnotation(f)) return false;
    return HasIntegrityAnnotation(f);
}

struct Site
{
    Instruction* user;
    unsigned opidx;
    uint64_t plaintext;
    unsigned siteidx;
    uint64_t ksite;
};

static bool IsRewritableConstOp(Instruction& i, unsigned opidx)
{
    if (isa<PHINode>(i)) return false;
    if (isa<BranchInst>(i)) return false;
    if (isa<SwitchInst>(i)) return false;
    if (isa<IndirectBrInst>(i)) return false;
    if (isa<LandingPadInst>(i)) return false;
    if (isa<FuncletPadInst>(i)) return false;
    if (isa<DbgInfoIntrinsic>(i)) return false;

    if (auto* call = dyn_cast<CallBase>(&i))
    {
        if (opidx >= call->arg_size()) return false;
        if (call->paramHasAttr(opidx, Attribute::ImmArg)) return false;
        return true;
    }

    if (auto* gep = dyn_cast<GetElementPtrInst>(&i))
    {
        if (opidx == 0) return false;
        auto gti = gep_type_begin(gep);
        auto end = gep_type_end(gep);
        for (unsigned k = 1; k < opidx && gti != end; ++k, ++gti) {}
        if (gti == end) return false;
        return gti.getStructTypeOrNull() == nullptr;
    }

    return true;
}

static unsigned EstimateBBBytes(BasicBlock& bb)
{
    return static_cast<unsigned>(bb.size() * 4);
}

static Function* GetOrCreateHashHelper(Module& m)
{
    if (Function* existing = m.getFunction(HashHelperName)) return existing;
    LLVMContext& c = m.getContext();
    Type* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);
    PointerType* ptrty = PointerType::get(c, 0);
    FunctionType* fty = FunctionType::get(i64, {ptrty, i32}, false);
    Function* f = Function::Create(fty, GlobalValue::ExternalLinkage, HashHelperName, &m);
    f->addFnAttr(Attribute::NoInline);
    f->addFnAttr(Attribute::NoUnwind);
    f->addFnAttr(Attribute::WillReturn);
    return f;
}

static GlobalVariable* CreateConstTable(Module& m, unsigned n)
{
    LLVMContext& c = m.getContext();
    Type* i64 = Type::getInt64Ty(c);
    ArrayType* at = ArrayType::get(i64, n);
    Constant* zinit = ConstantAggregateZero::get(at);

    if (GlobalVariable* existing = m.getGlobalVariable(ConstTableName))
    {
        existing->eraseFromParent();
    }
    GlobalVariable* gv = new GlobalVariable(m, at, false, GlobalValue::ExternalLinkage, zinit, ConstTableName);
    gv->setSection(TableSectionName);
    gv->setAlignment(Align(8));
    return gv;
}

// This struct layout MUST match IntegrityStamp.cpp's IntegritySiteMeta exactly (same field order and types)
static StructType* GetMetaStructType(Module& m)
{
    LLVMContext& c = m.getContext();
    Type* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);
    return StructType::get(c, {i32, i32, i64, i64, i64});
}

static Constant* MakeLabelDiff(Module& m, Constant* endba, Constant* startba)
{
    LLVMContext& c = m.getContext();
    Type* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);
    Constant* a = ConstantExpr::getPtrToInt(endba, i64);
    Constant* b = ConstantExpr::getPtrToInt(startba, i64);
    return ConstantExpr::getTrunc(ConstantExpr::getSub(a, b), i32);
}

static void EmitSiteMeta(Module& m, const Site& s, BasicBlock* windowbb, BasicBlock* tailbb)
{
    LLVMContext& c = m.getContext();
    Type* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);

    Function* f = windowbb->getParent();
    Constant* startba = BlockAddress::get(f, windowbb);
    Constant* tailba = BlockAddress::get(f, tailbb);
    Constant* startva = ConstantExpr::getPtrToInt(startba, i64);
    Constant* length = MakeLabelDiff(m, tailba, startba);

    StructType* st = GetMetaStructType(m);
    Constant* fields[] = {
        ConstantInt::get(i32, s.siteidx),
        length,
        startva,
        ConstantInt::get(i64, s.plaintext),
        ConstantInt::get(i64, s.ksite),
    };
    Constant* init = ConstantStruct::get(st, fields);

    GlobalVariable* meta = new GlobalVariable(m, st, true, GlobalValue::InternalLinkage, init, Twine("__integrity_meta_") + Twine(s.siteidx));
    meta->setSection(MetaSectionName);
    meta->setAlignment(Align(8));
    appendToUsed(m, {meta});
}

static Value* EmitHashCall(IRBuilder<>& b, Function* hasher, BasicBlock* windowbb, BasicBlock* tailbb)
{
    Module* m = windowbb->getModule();
    Function* f = windowbb->getParent();
    // bug: pass BlockAddress as an absolute ptr arg because MC can't lower (BA - __ImageBase) into an IMAGE_REL_AMD64_ADDR32NB reloc — __ImageBase is undefined to MC and it tries to evaluate the sub as a scalar which fails; on x64 the BA materializes as `lea r, [rip + disp32]` with no reloc inside the window and the stamper recovers the RVA via subtracting the PE's preferred ImageBase
    Constant* startba = BlockAddress::get(f, windowbb);
    Constant* tailba = BlockAddress::get(f, tailbb);
    Value* length = MakeLabelDiff(*m, tailba, startba);
    return b.CreateCall(hasher, {startba, length}, "IntegrityHash");
}

static Value* EmitDecryptAtSite(IRBuilder<>& b, Value* h, GlobalVariable* table, const Site& s)
{
    LLVMContext& c = b.getContext();
    Type* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);
    Type* opt = s.user->getOperand(s.opidx)->getType();

    Value* gep = b.CreateGEP(table->getValueType(), table, {ConstantInt::get(i32, 0), ConstantInt::get(i32, s.siteidx)}, "IntegrityGep");
    Value* enc = b.CreateLoad(i64, gep, "IntegrityEnc");
    Value* xh = b.CreateXor(enc, h, "IntegrityXH");
    Value* ksite = ConstantInt::get(i64, s.ksite);
    Value* dec64 = b.CreateXor(xh, ksite, "IntegrityDec64");
    return (opt->getIntegerBitWidth() == 64) ? dec64 : b.CreateTrunc(dec64, opt, "IntegrityDec");
}

static void CollectBBSites(BasicBlock& bb, std::vector<Site>& out)
{
    for (Instruction& i : bb)
    {
        if (isa<PHINode>(&i)) continue;
        if (i.isTerminator()) continue;
        for (unsigned oi = 0, oe = i.getNumOperands(); oi < oe; ++oi)
        {
            auto* ci = dyn_cast<ConstantInt>(i.getOperand(oi));
            if (!ci) continue;
            if (!IsRewritableConstOp(i, oi)) continue;
            unsigned bw = ci->getBitWidth();
            if (bw < 8 || bw > 64) continue;
            if (ci->isZero() || ci->isOne() || ci->isMinusOne()) continue;

            Site s;
            s.user = &i;
            s.opidx = oi;
            s.plaintext = ci->getZExtValue();
            s.siteidx = 0;
            s.ksite = 0;
            out.push_back(s);
        }
    }
}

static unsigned PlanModule(Module& m)
{
    unsigned planned = 0;
    for (Function& f : m)
    {
        if (f.isDeclaration()) continue;
        if (!WantsIntegrity(f)) continue;

        unsigned perfn = 0;
        for (BasicBlock& bb : f)
        {
            for (Instruction& i : bb)
            {
                if (isa<PHINode>(&i)) continue;
                if (i.isTerminator()) continue;
                for (unsigned oi = 0, oe = i.getNumOperands(); oi < oe; ++oi)
                {
                    auto* ci = dyn_cast<ConstantInt>(i.getOperand(oi));
                    if (!ci) continue;
                    if (!IsRewritableConstOp(i, oi)) continue;
                    unsigned bw = ci->getBitWidth();
                    if (bw < 8 || bw > 64) continue;
                    if (ci->isZero() || ci->isOne() || ci->isMinusOne()) continue;
                    if (perfn >= MaxSitesPerFn) continue;
                    ++perfn;
                    ++planned;
                }
            }
        }
    }
    return planned;
}

static bool ProcessCoalescedBB(BasicBlock& bb, Function* hasher, GlobalVariable* table, std::vector<Site>& sites)
{
    if (sites.empty()) return false;

    Instruction* term = bb.getTerminator();
    if (!term) return false;

    BasicBlock* tailbb = bb.splitBasicBlock(term->getIterator(), "IntegrityTail");
    BasicBlock* windowbb = &bb;

    IRBuilder<> b(&*windowbb->getFirstInsertionPt());
    Value* h = EmitHashCall(b, hasher, windowbb, tailbb);

    Module* m = windowbb->getModule();
    bool anybound = false;
    for (Site& s : sites)
    {
        s.siteidx = NextSiteIdx++;
        s.ksite = NextSiteKey();

        IRBuilder<> bu(s.user);
        Value* dec = EmitDecryptAtSite(bu, h, table, s);
        s.user->setOperand(s.opidx, dec);

        EmitSiteMeta(*m, s, windowbb, tailbb);
        anybound = true;
    }
    return anybound;
}

static bool ProcessPerSiteBB(BasicBlock& bb, Function* hasher, GlobalVariable* table, std::vector<Site>& sites)
{
    if (sites.empty()) return false;

    Module* m = bb.getModule();
    bool anybound = false;
    BasicBlock* currentwindow = &bb;

    for (Site& s : sites)
    {
        BasicBlock* userbb = s.user->getParent();
        if (userbb != currentwindow) currentwindow = userbb;

        BasicBlock::iterator splitpoint = std::next(s.user->getIterator());
        if (splitpoint == currentwindow->end()) continue;
        BasicBlock* tailbb = currentwindow->splitBasicBlock(splitpoint, "IntegrityTail");

        IRBuilder<> b(s.user);
        Value* h = EmitHashCall(b, hasher, currentwindow, tailbb);

        s.siteidx = NextSiteIdx++;
        s.ksite = NextSiteKey();
        Value* dec = EmitDecryptAtSite(b, h, table, s);
        s.user->setOperand(s.opidx, dec);

        EmitSiteMeta(*m, s, currentwindow, tailbb);
        anybound = true;

        currentwindow = tailbb;
    }
    return anybound;
}

static bool ProcessFunction(Function& f, Function* hasher, GlobalVariable* table)
{
    if (f.isDeclaration()) return false;
    if (!WantsIntegrity(f)) return false;

    BasicBlock& entry = f.getEntryBlock();
    BasicBlock::iterator entryfi = entry.getFirstInsertionPt();
    if (entryfi != entry.end()) entry.splitBasicBlock(entryfi, "IntegrityEntryCont");

    std::vector<BasicBlock*> origbbs;
    origbbs.reserve(f.size());
    for (BasicBlock& bb : f) origbbs.push_back(&bb);

    unsigned perfnbound = 0;
    bool mutated = false;

    for (BasicBlock* bb : origbbs)
    {
        if (perfnbound >= MaxSitesPerFn) break;
        if (bb == &f.getEntryBlock()) continue;

        std::vector<Site> sites;
        CollectBBSites(*bb, sites);
        if (sites.empty()) continue;

        if (perfnbound + sites.size() > MaxSitesPerFn)
        {
            unsigned drop = (perfnbound + sites.size()) - MaxSitesPerFn;
            sites.resize(sites.size() - drop);
        }
        if (sites.empty()) continue;

        unsigned est = EstimateBBBytes(*bb);
        bool coalesce = (est < MinWindow);
        bool bound = coalesce ? ProcessCoalescedBB(*bb, hasher, table, sites) : ProcessPerSiteBB(*bb, hasher, table, sites);
        if (bound)
        {
            mutated = true;
            perfnbound += static_cast<unsigned>(sites.size());
        }
    }

    return mutated;
}

bool RunIntegrity(Module& m)
{
    if (!IntegrityEnable) return false;

    unsigned planned = PlanModule(m);
    if (planned == 0) return false;

    NextSiteIdx = 0;

    GlobalVariable* table = CreateConstTable(m, planned);
    Function* hasher = GetOrCreateHashHelper(m);

    bool mutated = false;
    for (Function& f : m) mutated |= ProcessFunction(f, hasher, table);

    return mutated;
}

PreservedAnalyses IntegrityPass::run(Module& m, ModuleAnalysisManager&)
{
    return RunIntegrity(m) ? PreservedAnalyses::none() : PreservedAnalyses::all();
}