# MoonShine: Seed Generation for OS Fuzzers (USENIX '18)
See the USENIX'18 paper [MoonShine: Optimizing OS Fuzzer Seed Selection with Trace Distillation](http://www.cs.columbia.edu/~suman/docs/moonshine.pdf) for more details.

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
MoonShine requires that traces be gathered from strace. 

Strace can be built from source by following the instructions [here](https://github.com/strace/strace/blob/master/INSTALL).

On Debian it can be installed as follows:

```bash
apt-get update
apt-get install strace
```

We suggest that you use strace versions >= 4.0 as those are the only versions we have used so far. You can check the strace version as follows: 

```bash
$ strace -V
strace -- version 4.XX

```

## Gathering Traces

### Strace Command Line Arguments
MoonShine requires the traces be gathered with the following command line arguments:

```bash
$ strace -o tracefile -s 65500 -v -xx /path/to/executable
```
* -s indicates the maximum amount of data that should be written for each call.
* -v means the arguments should be unabbreviated
* -xx writes strings in hex

Traces with multiple processes should be gathered as follows:

```bash
$ strace -o tracefile -s 65500 -v -xx -f /path/to/executable
```

###