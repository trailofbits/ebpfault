# ebpfault

This tool is a syscall fault injector built on top of eBPF that has no requirements on the target machine other than a kernel version good enough to support the required features.

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

### System wide, excluding one or more running processes

```
ebpfault --config /path/to/config.json --except-pid-list --pid_list pid1,pid2,pid3,...
```

## Building

### Prerequisites
* A recent Clang/LLVM installation (9.0 or better), compiled with BPF support
* A recent libc++ or stdc++ library, supporting C++17
* CMake >= 3.21.4. A pre-built binary can be downloaded from the [CMake's download page](https://cmake.org/download/).
* Linux kernel >= 5.x (tested on Ubuntu 19.10) with the `CONFIG_BPF_KPROBE_OVERRIDE` option enabled

### Building

1. Download the osquery-toolchain from the following page: https://github.com/osquery/osquery-toolchain
2. Extract the osquery-toolchain and set the `TOOLCHAIN_PATH` environment variable to its location
3. Obtain the source code: `git clone --recursive https://github.com/trailofbits/ebpfault`
4. In case the `--recursive` flag was not provided, run `git submodule update --init --recursive`
7. Configure the project: `cmake -S ebpfault -B build-ebpfault -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain.cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DEBPFAULT_ENABLE_INSTALL=true`
8. Build the project: `cmake --build build-ebpfault`
