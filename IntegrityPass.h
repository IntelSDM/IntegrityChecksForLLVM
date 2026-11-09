#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"

struct IntegrityPass : llvm::PassInfoMixin<IntegrityPass>
{
    llvm::PreservedAnalyses run(llvm::Module& m, llvm::ModuleAnalysisManager&);
};

bool RunIntegrity(llvm::Module& m);

extern llvm::cl::opt<bool> IntegrityEnable;