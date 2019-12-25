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
