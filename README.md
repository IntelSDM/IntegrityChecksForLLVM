# Integrity Checks
Built for LLVM 19.1 - Windows x64 <br> <br>

Unlike more conventional integrity check systems you find in things like VMProtect, we want to actually have active protections against debuggers. <br>
* What we do is find all the constants in a function
* Assess the size between them
* We then write a constant encryption that is using the blake3 hash of the code between the constants. 
* Therefore if any up and coming breakpoints or hooks are found, we actively break upstream as the constant will be incorrect. 
* Unlike commercial solutions, we get instant relief as we aren't scanning the entire application against a CRC table, we just read about 256bytes of data and decrypt against it.
* This allows us to get realtime results. 

Since we are LLVM based, we can't get the blake3 hash immediately, and we also can't easily just import a blake3 function as link time passing. <br>
You have to include the runtime in your codebase, then use the patcher afterwards to patch the actual blake3 hashes into the function. <br>


<img width="1066" height="562" alt="image" src="https://github.com/user-attachments/assets/c2b20fdd-db6a-46cd-85af-b0704f1dea7f" /> <br>
sub_140001000 Is the blake3 hash, as you can see, knownhash xor blake3(start, length(start-end)) xor balance. <br>
As you can see they do overlap one another too so you can't patch one out to place a hook, You would need to patch all of them in the function, per function inlining sub_140001000 and placing integrity checks on itself would also be a good idea.


## How to use
Move Runtime/B3Runtime.cpp into your code base. Build with the pass. <br>
Build Patcher/Patcher.cpp and pass it the exe. It will then fix up the blake3 hashes used for integrity, then cleans up the indicators. <br>
I must make this clear, The integrity checks verify one another in function but not out of function, you could xor to other integrities to make sure they are valid too. Interfunctionally they check eachother though.<br>

## Annotations
```c
__attribute__((annotate("integrity")))
``` 
* Encrypts Constants With Hashes

## How To Build
* Download [LLVM 19.1](https://github.com/llvm/llvm-project/releases/tag/llvmorg-19.1.0)
* Download [VCPKG](https://github.com/microsoft/vcpkg)
* VCPKG install asmjit
* Open build.bat in a text editor.
* Find the LLVM 19.1 references in the command line, Change them to your file path.
* Find the VCPKG references in the command line, Change them to your file path.
* Run the build script
* Build your application with the ``` -load-pass-plugin ``` Param to the FunctionPass.dll
