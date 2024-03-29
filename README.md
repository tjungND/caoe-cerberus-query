# caoe-cerberus

## System and Dependencies
Our solutions are designed for modern Ubuntu distributions, though other Linux distributions should also work. Requirements are a modern C++ toolchain (C++17 and GCC 9 or later), OpenMP, and [OpenFHE](https://github.com/openfheorg/openfhe-development). OpenFHE v1.0.3 should be installed in the default system directory (`/usr/local/`).

Developers should also have clang-format, cpplint, and black. For further information about how to run the sender and receiver programs, look into the `docs` folder.

## Workflow
Developers must work on separate Git branches and submit merge requests on Gitlab. Before submission, make sure you've used all of clang-format, cpplint, and black on code as applicable, and also have checked compilation with -Wall, -Werror, -pedantic. (-pedantic may not be applicable in many cases, e.g., code using OpenFHE or 128-bit integral types.)

## Organization
Not all of these may be currently present.
- `include` contains C/C++ header files. Header-only library code is preferred.
- `src` contains application source code.
- `utilities` contains source code or scripts for utility programs that are not part of the main applications (e.g., parsing output)
- `containers` contains definition files for Singularity or Docker containers.
- `data` is where intermediate data should be placed.
- `inputs` and `outputs` is where input/output files should go.
- `results` is where timing or other profiling/logging data should go.
- `jobs` is where run scripts for testing/profiling the applications go.

## General Development Guidelines
- Header-only libraries are strongly preferred.
- Use GNU getopt for taking input flags.
- clang-format and cpplint must be run on all C++ code. black must be run on all Python code.
- For C++, use all available compiler warnings and standardization, e.g., `-Wall -Werror -pedantic -std=c++17`
- For C++, use smart pointers and STL outside the critical segments of code, and use them in critical sections if possible
- Use 2-space indentations.

- No “interactive” interfaces - this violates [Rule 2](https://en.wikipedia.org/wiki/Unix_philosophy).
- Programs should be written for modern Ubuntu, unless specified otherwise.
- Use C++17, but avoid excessive metaprogramming, templating, etc.
- Python code and version should be supported for 3.8 or higher.
- For shell scripts, use Bash.
- Time critical portions of code.

:warning: 
## Important Warning: 

This code is designed strictly for academic and research purposes. It has NOT undergone scrutiny by security professionals. No part of this code should be used in any real-world or production setting.
