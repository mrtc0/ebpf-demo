# eBPF Demos

This repository contains the code I used for the demo during my [talk](https://engineercafe.connpass.com/event/309223/).

# Usage

## Requirements

* Ubuntu 22.04 (Kernel >= 5.15)
* Install `bpftool` and other packages

```shell
$ sudo apt install build-essential libbpf-dev clang llvm linux-tools-generic
```

* Kernel was compiled with the following two configurations

```
CONFIG_FUNCTION_ERROR_INJECTION=y
CONFIG_BPF_KPROBE_OVERRIDE=y
```

## Build

```shell
$ make vmlinux.h && make build
```

## Run

Wanna try to trace connections towards "https://example.com" (93.184.216.34):

```shell
$ sudo ./bin/demo tracer
```

Then, in another terminal:

```shell
$ curl https://example.com
```

And observe the output in terminal:

```shell
2024/02/15 13:58:02 event: comm=curl addr=[93 184 216 34]
```

Then to block the connection:

```shell
$ sudo ./bin/demo enforcer
```

Running `curl https://example.com` in the same way will block the connection:

```shell

```