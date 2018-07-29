# MoonShine: Seed Selection for OS Fuzzers (USENIX '18)

MoonShine selects compact and diverse seeds for OS fuzzers by distilling system call traces of real world programs through lightweight static analysis. Please see our USENIX'18 paper [MoonShine: Optimizing OS Fuzzer Seed Selection with Trace Distillation](http://www.cs.columbia.edu/~suman/docs/moonshine.pdf) for more details. MoonShine currently only supports Syzkaller on Linux. 

# Contact
[Shankara Pailoor](shankarapailoor@gmail.com)

# Getting Started

## Requirements

### Syzkaller and Linux
MoonShine has been tested with Syzkaller commit f48c20b8f9b2a6c26629f11cc15e1c9c316572c8 (May 19, 2018). Instructions to setup Syzkaller as well as build Linux disk images for fuzzing can be found [here](https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md). 


### Golang
If Syzkaller has been successfully setup, then golang should already be installed, but in the off-chance it hasn't see [here](https://golang.org/doc/install) for instructions. After installing golang, add $GOPATH/bin to your $PATH
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
Currently, MoonShine can only parse traces gathered with strace. We also suggest that you use strace versions >= 4.16 as those are the only versions we have tried so far. Strace releases can be found [here](https://github.com/strace/strace/releases) and build instructions can be found [here](https://github.com/strace/strace/blob/master/INSTALL).

MoonShine needs to know the coverage achieved by each call in a trace in order to distill traces. We have created a patch ```strace_kcov.patch``` for strace that captures per-call coverage using [kcov](https://lwn.net/Articles/671640/). This patch should be applied to commit a8d2417e97e71ae01095bee1a1e563b07f2d6b41. Follow the below instructions to both build strace and apply the patch.
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
go get -u github.com/shankarapailoor/moonshine/...
cd $GOPATH/src/github.com/shankarapailoor/moonshine
make
```

### Run
Once MoonShine has been successfully built, we can generate distilled seeds for Syzkaller as follows:

```bash
./bin/moonshine -dir [tracedir] -distill [distillConfig.json]

```
The arguments are explained as follows
* ```-dir``` is the directory that contain the traces. Instructions to gather traces using strace can be found [here](docs/tracegen.md). To get started we have provided a tarball with sample traces gathered from the Linux Testing Project (LTP) and KSelftests under getting-started/sampletraces.tar.gz
* ```-distill``` Distillation config file that specifies the distillation strategy (e.g. implicit, explicit only). If the traces in tracedir don't have call coverage information, then this parameter should be ommitted and MoonShine will generate traces "as is". We have provided an example config under getting-started/distill.json
#### Example

```bash
./bin/moonshine -dir getting-started/sampletraces/ -distill getting-started/distill.json
```

MoonShine produces a ```corpus.db``` file that contains the serialized Syzkaller programs. Move the seeds to your Syzkaller workdir.  
 
```bash
cp corpus.db ~/$SYZKALLER_WORKDIR
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
