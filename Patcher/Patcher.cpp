#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <imagehlp.h>
#pragma comment(lib, "imagehlp.lib")

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

static constexpr size_t OutLen = 32;
static constexpr size_t BlockLen = 64;
static constexpr size_t MaxChunkLen = 1024;
static constexpr size_t MaxDepth = 54;

static constexpr uint32_t IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

static constexpr uint8_t MsgSchedule[7][16] = {
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    { 2,  6,  3, 10,  7,  0,  4, 13,  1, 11, 12,  5,  9, 14, 15,  8},
    { 3,  4, 10, 12, 13,  2,  7, 14,  6,  5,  9,  0, 11, 15,  8,  1},
    {10,  7, 12,  9, 14,  3, 13, 15,  4,  0, 11,  2,  5,  8,  1,  6},
    {12, 13,  9, 11, 15, 10, 14,  8,  7,  2,  5,  3,  0,  1,  6,  4},
    { 9, 14, 11,  5,  8, 12, 15,  1, 13,  3,  0, 10,  2,  6,  4,  7},
    {11, 15,  5,  0,  1,  9,  8,  6, 14, 10,  2, 12,  3,  4,  7, 13},
};

static constexpr uint8_t FlagChunkStart = 1 << 0;
static constexpr uint8_t FlagChunkEnd = 1 << 1;
static constexpr uint8_t FlagParent = 1 << 2;
static constexpr uint8_t FlagRoot = 1 << 3;

static inline uint32_t Load32(const uint8_t* p)
{
    uint32_t w;
    std::memcpy(&w, p, 4);
    return w;
}

static inline void Store32(uint8_t* p, uint32_t w)
{
    std::memcpy(p, &w, 4);
}

static inline uint32_t Rotr32(uint32_t w, unsigned c)
{
    return (w >> c) | (w << ((32 - c) & 31));
}

static inline void GMix(uint32_t* s, size_t a, size_t b, size_t c, size_t d, uint32_t mx, uint32_t my)
{
    s[a] = s[a] + s[b] + mx;
    s[d] = Rotr32(s[d] ^ s[a], 16);
    s[c] = s[c] + s[d];
    s[b] = Rotr32(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b] + my;
    s[d] = Rotr32(s[d] ^ s[a], 8);
    s[c] = s[c] + s[d];
    s[b] = Rotr32(s[b] ^ s[c], 7);
}

static void RoundFn(uint32_t state[16], const uint32_t msg[16], unsigned r)
{
    const uint8_t* sch = MsgSchedule[r];
    GMix(state, 0, 4, 8, 12, msg[sch[0]], msg[sch[1]]);
    GMix(state, 1, 5, 9, 13, msg[sch[2]], msg[sch[3]]);
    GMix(state, 2, 6, 10, 14, msg[sch[4]], msg[sch[5]]);
    GMix(state, 3, 7, 11, 15, msg[sch[6]], msg[sch[7]]);
    GMix(state, 0, 5, 10, 15, msg[sch[8]], msg[sch[9]]);
    GMix(state, 1, 6, 11, 12, msg[sch[10]], msg[sch[11]]);
    GMix(state, 2, 7, 8, 13, msg[sch[12]], msg[sch[13]]);
    GMix(state, 3, 4, 9, 14, msg[sch[14]], msg[sch[15]]);
}

static void CompressPre(uint32_t state[16], const uint32_t cv[8], const uint8_t block[BlockLen], uint8_t blocklen, uint64_t counter, uint8_t flags)
{
    uint32_t m[16];
    for (int i = 0; i < 16; ++i) m[i] = Load32(block + i * 4);
    for (int i = 0; i < 8; ++i) state[i] = cv[i];
    state[8] = IV[0]; state[9] = IV[1]; state[10] = IV[2]; state[11] = IV[3];
    state[12] = static_cast<uint32_t>(counter);
    state[13] = static_cast<uint32_t>(counter >> 32);
    state[14] = static_cast<uint32_t>(blocklen);
    state[15] = static_cast<uint32_t>(flags);
    for (unsigned r = 0; r < 7; ++r) RoundFn(state, m, r);
}

static void CompressInPlace(uint32_t cv[8], const uint8_t block[BlockLen], uint8_t blocklen, uint64_t counter, uint8_t flags)
{
    uint32_t s[16];
    CompressPre(s, cv, block, blocklen, counter, flags);
    for (int i = 0; i < 8; ++i) cv[i] = s[i] ^ s[i + 8];
}

static void CompressXof(const uint32_t cv[8], const uint8_t block[BlockLen], uint8_t blocklen, uint64_t counter, uint8_t flags, uint8_t out[64])
{
    uint32_t s[16];
    CompressPre(s, cv, block, blocklen, counter, flags);
    for (int i = 0; i < 8; ++i)
    {
        Store32(out + i * 4, s[i] ^ s[i + 8]);
        Store32(out + (i + 8) * 4, s[i + 8] ^ cv[i]);
    }
}

struct Output
{
    uint32_t inputcv[8];
    uint64_t counter;
    uint8_t block[BlockLen];
    uint8_t blocklen;
    uint8_t flags;
};

static void OutputChainingValue(const Output& o, uint8_t outcv[32])
{
    uint32_t cvwords[8];
    std::memcpy(cvwords, o.inputcv, 32);
    CompressInPlace(cvwords, o.block, o.blocklen, o.counter, o.flags);
    for (int i = 0; i < 8; ++i) Store32(outcv + i * 4, cvwords[i]);
}

static void OutputRootBytes(const Output& o, uint8_t* out, size_t outlen)
{
    uint64_t counter = 0;
    uint8_t wide[64];
    while (outlen > 0)
    {
        CompressXof(o.inputcv, o.block, o.blocklen, counter, o.flags | FlagRoot, wide);
        size_t take = outlen < 64 ? outlen : 64;
        std::memcpy(out, wide, take);
        out += take;
        outlen -= take;
        ++counter;
    }
}

struct ChunkState
{
    uint32_t cv[8];
    uint64_t chunkcounter;
    uint8_t buf[BlockLen];
    uint8_t buflen;
    uint8_t blockscompressed;
    uint8_t flags;
};

static void ChunkInit(ChunkState& s, const uint32_t key[8], uint8_t flags)
{
    std::memcpy(s.cv, key, 32);
    s.chunkcounter = 0;
    std::memset(s.buf, 0, BlockLen);
    s.buflen = 0;
    s.blockscompressed = 0;
    s.flags = flags;
}

static void ChunkReset(ChunkState& s, const uint32_t key[8], uint64_t newchunkcounter)
{
    std::memcpy(s.cv, key, 32);
    s.chunkcounter = newchunkcounter;
    std::memset(s.buf, 0, BlockLen);
    s.buflen = 0;
    s.blockscompressed = 0;
}

static inline size_t ChunkLen(const ChunkState& s)
{
    return BlockLen * static_cast<size_t>(s.blockscompressed) + static_cast<size_t>(s.buflen);
}

static inline uint8_t ChunkStartFlag(const ChunkState& s)
{
    return s.blockscompressed == 0 ? FlagChunkStart : 0;
}

static size_t ChunkFillBuf(ChunkState& s, const uint8_t* in, size_t inlen)
{
    size_t take = BlockLen - static_cast<size_t>(s.buflen);
    if (take > inlen) take = inlen;
    std::memcpy(s.buf + s.buflen, in, take);
    s.buflen += static_cast<uint8_t>(take);
    return take;
}

static void ChunkUpdate(ChunkState& s, const uint8_t* in, size_t inlen)
{
    if (s.buflen > 0)
    {
        size_t take = ChunkFillBuf(s, in, inlen);
        in += take;
        inlen -= take;
        if (inlen > 0)
        {
            CompressInPlace(s.cv, s.buf, BlockLen, s.chunkcounter, s.flags | ChunkStartFlag(s));
            s.blockscompressed++;
            s.buflen = 0;
            std::memset(s.buf, 0, BlockLen);
        }
    }
    while (inlen > BlockLen)
    {
        CompressInPlace(s.cv, in, BlockLen, s.chunkcounter, s.flags | ChunkStartFlag(s));
        s.blockscompressed++;
        in += BlockLen;
        inlen -= BlockLen;
    }
    ChunkFillBuf(s, in, inlen);
}

static Output ChunkOutput(const ChunkState& s)
{
    Output o;
    std::memcpy(o.inputcv, s.cv, 32);
    std::memcpy(o.block, s.buf, BlockLen);
    o.blocklen = s.buflen;
    o.counter = s.chunkcounter;
    o.flags = s.flags | ChunkStartFlag(s) | FlagChunkEnd;
    return o;
}

static Output ParentOutput(const uint8_t block[BlockLen], const uint32_t key[8], uint8_t flags)
{
    Output o;
    std::memcpy(o.inputcv, key, 32);
    std::memcpy(o.block, block, BlockLen);
    o.blocklen = BlockLen;
    o.counter = 0;
    o.flags = flags | FlagParent;
    return o;
}

struct Hasher
{
    uint32_t key[8];
    ChunkState chunk;
    uint8_t cvstacklen;
    uint8_t cvstack[(MaxDepth + 1) * 32];
};

static void HasherInit(Hasher& h)
{
    std::memcpy(h.key, IV, 32);
    ChunkInit(h.chunk, IV, 0);
    h.cvstacklen = 0;
}

static inline int Popcount64(uint64_t x)
{
    int c = 0;
    while (x)
    {
        c += static_cast<int>(x & 1);
        x >>= 1;
    }
    return c;
}

static void MergeCvStack(Hasher& h, uint64_t totallen)
{
    size_t target = static_cast<size_t>(Popcount64(totallen));
    while (static_cast<size_t>(h.cvstacklen) > target)
    {
        uint8_t* parentnode = &h.cvstack[(h.cvstacklen - 2) * 32];
        Output po = ParentOutput(parentnode, h.key, h.chunk.flags);
        OutputChainingValue(po, parentnode);
        h.cvstacklen--;
    }
}

static void PushCv(Hasher& h, const uint8_t newcv[32], uint64_t chunkcounter)
{
    MergeCvStack(h, chunkcounter);
    std::memcpy(&h.cvstack[h.cvstacklen * 32], newcv, 32);
    h.cvstacklen++;
}

static void HasherUpdate(Hasher& h, const uint8_t* in, size_t inlen)
{
    while (inlen > 0)
    {
        if (ChunkLen(h.chunk) == MaxChunkLen)
        {
            uint8_t cv[32];
            Output o = ChunkOutput(h.chunk);
            OutputChainingValue(o, cv);
            uint64_t totalchunks = h.chunk.chunkcounter + 1;
            PushCv(h, cv, totalchunks);
            ChunkReset(h.chunk, h.key, totalchunks);
        }
        size_t want = MaxChunkLen - ChunkLen(h.chunk);
        size_t take = inlen < want ? inlen : want;
        ChunkUpdate(h.chunk, in, take);
        in += take;
        inlen -= take;
    }
}

static void HasherFinalize(const Hasher& h, uint8_t* out, size_t outlen)
{
    if (h.cvstacklen == 0)
    {
        Output o = ChunkOutput(h.chunk);
        OutputRootBytes(o, out, outlen);
        return;
    }

    Output o;
    size_t cvsremaining;
    if (ChunkLen(h.chunk) > 0)
    {
        cvsremaining = h.cvstacklen;
        o = ChunkOutput(h.chunk);
    }
    else
    {
        cvsremaining = static_cast<size_t>(h.cvstacklen) - 2;
        uint8_t block[BlockLen];
        std::memcpy(block, &h.cvstack[cvsremaining * 32], BlockLen);
        o = ParentOutput(block, h.key, h.chunk.flags);
    }
    while (cvsremaining > 0)
    {
        cvsremaining--;
        uint8_t block[BlockLen];
        std::memcpy(block, &h.cvstack[cvsremaining * 32], 32);
        uint8_t rightcv[32];
        OutputChainingValue(o, rightcv);
        std::memcpy(block + 32, rightcv, 32);
        o = ParentOutput(block, h.key, h.chunk.flags);
    }
    OutputRootBytes(o, out, outlen);
}

// This convention MUST match IntegrityRuntime.cpp byte for byte
static uint64_t HashLow64(const uint8_t* data, size_t len)
{
    Hasher h;
    HasherInit(h);
    HasherUpdate(h, data, len);
    uint8_t out[OutLen];
    HasherFinalize(h, out, OutLen);
    uint64_t r;
    std::memcpy(&r, out, sizeof(r));
    return r;
}

// This struct layout MUST match IntegrityPass.cpp's GetMetaStructType output (StructType::get(C, {i32, i32, i64, i64, i64})) 
#pragma pack(push, 1)
struct IntegritySiteMeta
{
    uint32_t siteidx;
    uint32_t length;
    uint64_t startva;
    uint64_t plaintext;
    uint64_t ksite;
};
#pragma pack(pop)

static_assert(sizeof(IntegritySiteMeta) == 32, "layout must match IntegrityPass StructType exactly");

// These section names MUST match IntegrityPass.cpp's MetaSectionName / TableSectionName
static constexpr const char* MetaSectionName = ".int1";
static constexpr const char* TableSectionName = ".int2";

struct Options
{
    std::string input;
    std::string output;
    bool verbose = false;
};

static void PrintUsage(const char* prog)
{
    std::fprintf(stderr,
        "integritystamp - populate the Integrity const table in a built PE\n"
        "\n"
        "Usage: %s <input.exe> [-o output.exe] [-v]\n"
        "\n"
        "  <input.exe>    PE produced by lld-link after IntegrityPass\n"
        "  -o output.exe  write here (default: overwrite input)\n"
        "  -v, --verbose  per-site log lines\n"
        "\n"
        "The metadata and manifest sections are ALWAYS zeroed after\n"
        "stamping — no plaintext / per-site key / section-name hints ship.\n",
        prog);
}

static bool ParseArgs(int argc, char** argv, Options& opt)
{
    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "-o" && i + 1 < argc)
        {
            opt.output = argv[++i];
        }
        else if (a == "-v" || a == "--verbose")
        {
            opt.verbose = true;
        }
        else if (a == "-h" || a == "--help")
        {
            return false;
        }
        else if (opt.input.empty() && !a.empty() && a[0] != '-')
        {
            opt.input = a;
        }
        else
        {
            std::fprintf(stderr, "integritystamp: unrecognized arg: %s\n", a.c_str());
            return false;
        }
    }
    if (opt.input.empty()) return false;
    if (opt.output.empty()) opt.output = opt.input;
    return true;
}

static bool ReadWholeFile(const std::string& path, std::vector<uint8_t>& out)
{
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize sz = f.tellg();
    if (sz <= 0) return false;
    out.resize(static_cast<size_t>(sz));
    f.seekg(0);
    return bool(f.read(reinterpret_cast<char*>(out.data()), sz));
}

static bool WriteWholeFile(const std::string& path, const std::vector<uint8_t>& data)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return bool(f);
}

static uint32_t RVAToFileOffset(IMAGE_SECTION_HEADER* sections, uint16_t nsec, uint32_t rva)
{
    for (uint16_t i = 0; i < nsec; ++i)
    {
        uint32_t base = sections[i].VirtualAddress;
        uint32_t vsize = sections[i].Misc.VirtualSize;
        if (rva >= base && rva < base + vsize)
        {
            return sections[i].PointerToRawData + (rva - base);
        }
    }
    return UINT32_MAX;
}

static IMAGE_SECTION_HEADER* FindSection(IMAGE_SECTION_HEADER* sections, uint16_t nsec, const char* name)
{
    for (uint16_t i = 0; i < nsec; ++i)
    {
        char n[9] = {};
        std::memcpy(n, sections[i].Name, 8);
        if (std::strcmp(n, name) == 0) return &sections[i];
    }
    return nullptr;
}

int main(int argc, char** argv)
{
    Options opt;
    if (!ParseArgs(argc, argv, opt))
    {
        PrintUsage(argv[0]);
        return 1;
    }

    std::vector<uint8_t> buf;
    if (!ReadWholeFile(opt.input, buf))
    {
        std::fprintf(stderr, "integritystamp: cannot read %s\n", opt.input.c_str());
        return 2;
    }
    if (buf.size() < sizeof(IMAGE_DOS_HEADER))
    {
        std::fprintf(stderr, "integritystamp: file too small to be a PE\n");
        return 3;
    }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::fprintf(stderr, "integritystamp: not an MZ file\n");
        return 3;
    }
    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > buf.size())
    {
        std::fprintf(stderr, "integritystamp: bad e_lfanew\n");
        return 3;
    }

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        std::fprintf(stderr, "integritystamp: not a PE\n");
        return 3;
    }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        std::fprintf(stderr, "integritystamp: only PE32+ (x64) supported\n");
        return 3;
    }

    uint16_t nsec = nt->FileHeader.NumberOfSections;
    auto* sections = IMAGE_FIRST_SECTION(nt);

    auto* metasec = FindSection(sections, nsec, MetaSectionName);
    auto* tablesec = FindSection(sections, nsec, TableSectionName);
    if (!metasec || !tablesec)
    {
        std::printf("integritystamp: no Integrity sections ('%s' / '%s') found — nothing to stamp (not an error)\n", MetaSectionName, TableSectionName);
        return 0;
    }

    uint32_t metabytes = (metasec->Misc.VirtualSize < metasec->SizeOfRawData) ? metasec->Misc.VirtualSize : metasec->SizeOfRawData;
    if (metabytes % sizeof(IntegritySiteMeta) != 0)
    {
        std::fprintf(stderr, "integritystamp: meta section '%s' size %u not a multiple of %zu — pass/stamper layout mismatch, refusing to stamp\n", MetaSectionName, metabytes, sizeof(IntegritySiteMeta));
        return 5;
    }
    size_t nsites = metabytes / sizeof(IntegritySiteMeta);

    uint32_t tablebytes = (tablesec->Misc.VirtualSize < tablesec->SizeOfRawData) ? tablesec->Misc.VirtualSize : tablesec->SizeOfRawData;
    size_t tableslots = tablebytes / sizeof(uint64_t);

    auto* metabase = reinterpret_cast<IntegritySiteMeta*>(buf.data() + metasec->PointerToRawData);
    auto* tablebase = reinterpret_cast<uint64_t*>(buf.data() + tablesec->PointerToRawData);

    const uint64_t preferredbase = nt->OptionalHeader.ImageBase;

    std::printf("integritystamp: input=%s nSites=%zu tableSlots=%zu meta='%s'(RVA=0x%X) table='%s'(RVA=0x%X) preferredbase=0x%llX\n",
        opt.input.c_str(), nsites, tableslots,
        MetaSectionName, metasec->VirtualAddress,
        TableSectionName, tablesec->VirtualAddress,
        static_cast<unsigned long long>(preferredbase));

    size_t stamped = 0;
    size_t skippedbadidx = 0;
    size_t skippedbadrva = 0;

    for (size_t i = 0; i < nsites; ++i)
    {
        const IntegritySiteMeta& m = metabase[i];

        if (m.siteidx >= tableslots)
        {
            if (opt.verbose)
            {
                std::fprintf(stderr, "  site idx=%u out of table range (slots=%zu)\n", m.siteidx, tableslots);
            }
            ++skippedbadidx;
            continue;
        }
        if (m.length == 0)
        {
            if (opt.verbose)
            {
                std::fprintf(stderr, "  site idx=%u length=0, skipping\n", m.siteidx);
            }
            ++skippedbadrva;
            continue;
        }
        if (m.startva < preferredbase)
        {
            if (opt.verbose)
            {
                std::fprintf(stderr, "  site idx=%u start_va=0x%llX < preferredbase=0x%llX\n", m.siteidx, static_cast<unsigned long long>(m.startva), static_cast<unsigned long long>(preferredbase));
            }
            ++skippedbadrva;
            continue;
        }
        uint32_t rva = static_cast<uint32_t>(m.startva - preferredbase);

        uint32_t fileoff = RVAToFileOffset(sections, nsec, rva);
        if (fileoff == UINT32_MAX || static_cast<size_t>(fileoff) + m.length > buf.size())
        {
            if (opt.verbose)
            {
                std::fprintf(stderr, "  site idx=%u rva=0x%08X len=%u out of file\n", m.siteidx, rva, m.length);
            }
            ++skippedbadrva;
            continue;
        }

        uint64_t h = HashLow64(buf.data() + fileoff, m.length);
        uint64_t enc = m.plaintext ^ h ^ m.ksite;
        tablebase[m.siteidx] = enc;

        if (opt.verbose)
        {
            std::printf("  site %5u: rva=0x%08X len=%4u h=0x%016llX pt=0x%016llX k=0x%016llX enc=0x%016llX\n",
                m.siteidx, rva, m.length,
                static_cast<unsigned long long>(h),
                static_cast<unsigned long long>(m.plaintext),
                static_cast<unsigned long long>(m.ksite),
                static_cast<unsigned long long>(enc));
        }
        ++stamped;
    }

    // ALWAYS zero the metadata section post stamp 
    std::memset(metabase, 0, metabytes);
    std::printf("integritystamp: zeroed meta '%s' (%u bytes)\n", MetaSectionName, metabytes);

    DWORD oldsum = 0, newsum = 0;
    CheckSumMappedFile(buf.data(), static_cast<DWORD>(buf.size()), &oldsum, &newsum);
    nt->OptionalHeader.CheckSum = newsum;

    if (!WriteWholeFile(opt.output, buf))
    {
        std::fprintf(stderr, "integritystamp: failed to write %s\n", opt.output.c_str());
        return 6;
    }

    std::printf("integritystamp: wrote %s (stamped=%zu badIdx=%zu badRva=%zu checksum: 0x%08X -> 0x%08X)\n",
        opt.output.c_str(), stamped, skippedbadidx, skippedbadrva,
        static_cast<unsigned>(oldsum),
        static_cast<unsigned>(newsum));

    return (skippedbadidx || skippedbadrva) ? 7 : 0;
}