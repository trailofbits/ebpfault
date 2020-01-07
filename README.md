# ebpfault

This tool is a syscall fault injector built on top of eBPF that has no requirements on the target machine other than a kernel version good enough to support the required features.

| | |
|-|-|
| CI Status | ![](https://github.com/trailofbits/ebpfault/workflows/Linux/badge.svg) |

## Usage

### Sample configuration

The configuration supports both integers and errno value names.

```json
{
  "fault_injectors": [
    {
      "syscall_name": "fchmodat",

      "error_list": [
        {
          "exit_code": "-ENOENT",
          "probability": 50
        },

        {
          "exit_code": -100,
          "probability": 30
        }
      ]
    },

    {
      "syscall_name": "openat",

      "error_list": [
        {
          "exit_code": "-ENOENT",
          "probability": 50
        }
      ]
    }
  ]
}
```

### Against a new process

```
ebpfault --config /path/to/config.json --exec /path/to/program arg1 arg2
```

### Against one or more running processes

```
ebpfault --config /path/to/config.json --pid_list pid1,pid2,pid3,...
```

### System wide, except one or more running processes

```
ebpfault --config /path/to/config.json --except-pid-list --pid_list pid1,pid2,pid3,...
```

## Building

### Prerequisites
* A recent Clang/LLVM installation (8.0 or better), compiled with BPF support
* A recent libc++ or stdc++ library, supporting C++17
* CMake >= 3.16.2. A pre-built binary can be downloaded from the [CMake's download page](https://cmake.org/download/).
* Linux kernel >= 5.x (tested on Ubuntu 19.10)

Please note that LLVM itself must be compiled with libc++ when enabling the `EBPF_COMMON_ENABLE_LIBCPP` option, since ebfpub will directly link against the LLVM libraries.

### Building with the osquery toolchain (preferred)

**This should work fine on any recent Linux distribution.**

The osquery-toolchain needs to be obtained first, but version 1.0.0 does not yet ship with LLVM/Clang libraries. It is possible to download the 1.0.1 prerelease from https://alessandrogar.io/downloads/osquery-toolchain-1.0.1.tar.xz. See the following PR for more information: https://github.com/osquery/osquery-toolchain/pull/14

1. Obtain the source code: `git clone --recursive https://github.com/trailofbits/ebpfault`
2. In case the `--recursive` flag was not provided, run `git submodule update --init --recursive`
3. Enter the source folder: `cd ebpfault`
4. Create the build folder: `mkdir build && cd build`
5. Configure the project: `cmake -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo -DEBPF_COMMON_TOOLCHAIN_PATH:PATH=/path/to/osquery-toolchain -DEBPFAULT_ENABLE_INSTALL:BOOL=true -DEBPF_COMMON_ENABLE_TESTS:BOOL=true -DEBPF_COMMON_ENABLE_SANITIZERS:BOOL=false ..`
6. Build the project: `cmake --build . -j $(($(nproc) + 1))`
7. Run the tests: `cmake --build . --target run-ebpf-common-tests`

### Building with the system toolchain

**Note that this will fail unless clang and the C++ library both support C++17**. Recent distributions should be compatible (tested on Arch Linux, Ubuntu 19.10).

1. Obtain the source code: `git clone --recursive https://github.com/trailofbits/ebpfpub`
2. In case the `--recursive` flag was not provided, run `git submodule update --init --recursive`
3. Enter the source folder: `cd ebpfpub`
4. Create the build folder: `mkdir build && cd build`
5. Configure the project: `cmake -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo -DCMAKE_C_COMPILER:STRING=clang -DCMAKE_CXX_COMPILER:STRING=clang++ -DEBPFAULT_ENABLE_INSTALL:BOOL=true -DEBPF_COMMON_ENABLE_TESTS:BOOL=true -DEBPF_COMMON_ENABLE_SANITIZERS:BOOL=false ..`
6. Build the project: `cmake --build . -j $(($(nproc) + 1))`
7. Run the tests: `cmake --build . --target run-ebpf-common-tests`

### Building the packages

## Prerequisites
* DEB: **dpkg** command
* RPM: **rpm** command
* TGZ: **tar** command

## Steps
Run the following commands:

```
mkdir install
export DESTDIR=`realpath install`

cd build
cmake --build . --target install
```

Configure the packaging project:

```
mkdir package
cd package

cmake -DEBPFAULT_INSTALL_PATH:PATH="${DESTDIR}" /path/to/source_folder/package_generator
cmake --build . --target package
```