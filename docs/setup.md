## Prerequisite
At present, MoonShine can only generate seeds for Syzkaller and is only supported on Linux. 
### Golang
See [here](https://golang.org/doc/install) for instructions to install golang. After successfully installing golang set
```bash
export PATH=$PATH:$GOPATH/bin/
```

### Ragel
```bash
sudo apt-get update
sudo apt-get install ragel
```

### Goyacc
```bash
go get golang.org/x/tools/cmd/goyacc
```

### Strace Installation
At the present, MoonShine can only parse traces gathered from [strace](https://github.com/strace/strace)
#### Version
We suggest that you use strace versions >= 4.16 as those are the only versions we have used so far. You can check the strace version as follows: 

```bash
$ strace -V
strace -- version 4.XX
```
#### Download
Strace can be built from source by following the instructions [here](https://github.com/strace/strace/blob/master/INSTALL).
#### With KCOV
MoonShine comes with a patch ```strace_kcov.patch``` for strace that captures per-call coverage in addition to arguments. This is necessary to perform distillation. Perform the following steps to build strace. 
```bash
$ git clone https://github.com/strace/strace strace
$ git checkout a8d2417e97e71ae01095bee1a1e563b07f2d6b41
$ git apply strace_kcov.patch
$ ./bootstrap
...
$ ./configure
....
$ make
```
