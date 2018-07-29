# Getting Started

## Requirements

###Syzkaller and Linux
MoonShine has been tested with Syzkaller commit f48c20b8f9b2a6c26629f11cc15e1c9c316572c8 (May 19, 2018). Instructions to setup Syzkaller as well as build Linux disk images for fuzzing can be found [here](https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md).


### Golang
If Syzkaller has been successfully setup, then golang should already be installed, but in the off-chance it hasn't see [here](https://golang.org/doc/install) for instructions. After install golang, add $GOPATH/bin to your $PATH
```bash
export PATH=$PATH:$GOPATH/bin/
```

### Ragel
On Debian systems, do the following:
```bash
sudo apt-get update
sudo apt-get install ragel
```

### Goyacc
```bash
go get golang.org/x/tools/cmd/goyacc
```

### Strace
Strace releases can be found [here](https://github.com/strace/strace/releases). We suggest that you use strace versions >= 4.16 as those are the only versions we have tried so far. Build instructions can be found [here](https://github.com/strace/strace/blob/master/INSTALL).

MoonShine needs to know the coverage achieved by each call in a trace in order to distill traces. We have created a patch ```strace_kcov.patch``` for strace that captures per-call coverage using [kcov](https://lwn.net/Articles/671640/). This patch should be applied to commit a8d2417e97e71ae01095bee1a1e563b07f2d6b41. Follow the below instructions to build strace and apply the patch.
```bash
$ cd ~
$ git clone https://github.com/strace/strace strace
$ git checkout a8d2417e97e71ae01095bee1a1e563b07f2d6b41
$ git apply $GOPATH/src/github.com/shankarapailoor/moonshine/strace_kcov.patch
$ ./bootstrap
...
$ ./configure
....
$ make
```

## Running MoonShine

### Build


```bash
go get -u github.com/shankarapailoor/moonshine
cd $GOPATH/src/github.com/shankarapailoor/moonshine
make
```

### Run
Once MoonShine has been successfully built, we can generate distilled seeds for Syzkaller as follows:

```bash
./bin/moonshine -dir [tracedir] -distill [distillConfig.json]

```
The arguments are explained as follows
* ```-dir``` A directory of traces gathered using strace. Instructions to gather traces using strace can be found [here](docs/tracegen.md). To get started we have provided a tarball with sample traces gathered from the Linux Testing Project (LTP) and KSelftests under example-traces/strace-output.tar.gz
* ```-distill``` Indicates the distillation strategy that MoonShine should use. If the traces in tracedir don't have call coverage information, then this parameter can be ommitted and MoonShine will generate traces "as is".

