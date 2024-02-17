# eBPF Demos

This repository contains the code I used for the demo during my [talk](https://speakerdeck.com/mrtc0/kododeli-jie-suru-ebpf-sekiyuriteimonitaringu) @ ["eBPF & コンテナ情報交換会 @ 福岡"](https://engineercafe.connpass.com/event/309223/).  
This is a demonstration of using `bpf_override_return()` and `bpf_send_signal()` to stop a process when there is a suspicious network connections.

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
$ make build
```

## Run

Wanna try to trace connections towards "https://example.com" (93.184.216.34):

```shell
$ sudo ./bin/ebpf-demo tracer
```

Then, in another terminal:

```shell
$ curl https://example.com
```

And observe the output in terminal:

```shell
2024/02/17 04:29:53 INFO ⏫ CONNECT comm=curl addr=93.184.216.34
```

Then to block the connection:

```shell
$ sudo ./bin/ebpf-demo enforce
```

Running `curl https://example.com` in the same way will block the connection:

```shell
$ curl https://example.com
Killed
```

```shell
2024/02/17 04:30:32 INFO 🛡 BLOCKED comm=curl addr=93.184.216.34
```

If use `wget` instead of `curl`, it will not be blocked.

```shell
$ wget https://example.com
```
