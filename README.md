# MoonShine: Seed Selection for OS Fuzzers (USENIX '18)

MoonShine selects compact and diverse seeds for OS fuzzers from system call traces of real world programs. Please see our USENIX'18 paper [MoonShine: Optimizing OS Fuzzer Seed Selection with Trace Distillation](http://www.cs.columbia.edu/~suman/docs/moonshine.pdf) for more details. Currently, MoonShine can only generate seeds for Syzkaller on Linux. 

# Contents
* [Getting Started](#getting-started)
    * [Requirements](#requirements)
    * [Build and Run MoonShine](#build-and-run-moonshine)
    * [Collecting Traces](#collecting-traces)
    * [Setup Syzkaller](#syzkaller-and-linux)
* [Project Structure](#project-structure)
* [Trophies](#trophies)
* [Contributors](#contributors)

# Getting Started

The following setup instructions have been tested on Ubuntu 16.04. Let us know if there are issues on other versions or distributions.
## Requirements

### Go
MoonShine is mostly written in Go so the first step is to setup Go. You can either follow the below instructions or follow the [Official Go Installation Guide](https://golang.org/doc/install) . 

```bash
$ wget https://dl.google.com/go/go1.10.3.linux-amd64.tar.gz
$ sudo tar -C /usr/local -xzf go1.10.3.linux-amd64.tar.gz
$ export PATH=$PATH:/usr/local/go/bin
$ go version
go version go1.10.3 linux/amd64
```
After installing Go, setup your Go workspace. Your Go workspace is where all Go project binary and source code is stored. By default, Go expects the workspace to be under ```$HOME/go``` so either create the directory ```$HOME/go``` or install to a custom location and set ```$GOPATH```(**Note**: If you have already setup Syzkaller then this step can be skipped since Syzkaller is a Go project)

### Ragel
MoonShine uses [ragel](http://www.colm.net/open-source/ragel/) (variation of lex) to scan/parse traces.
```bash
sudo apt-get update
sudo apt-get install ragel
```

### Goyacc
MoonShine uses [goyacc](https://godoc.org/golang.org/x/tools/cmd/goyacc) (variation of yacc) to scan/parse traces.
```bash
go get golang.org/x/tools/cmd/goyacc
```
goyacc gets installed in ```$HOME/go/bin``` (or ```$GOPATH/bin``` if workspace is not in the home directory). Make sure this directory is on your $PATH.

```bash
$ export PATH=$PATH:$HOME/go/bin
```

## Build and Run MoonShine

### Build
```bash
go get -u -d github.com/shankarapailoor/moonshine/...
cd $GOPATH/src/github.com/shankarapailoor/moonshine
make
```

### Run
Once MoonShine has been successfully built, we can generate seeds for Syzkaller as follows:

```bash
$ ./bin/moonshine -dir [tracedir] -distill [distillConfig.json]
```
The arguments are explained below:
* ```-dir``` is a directory for traces to be parsed. We have provided a tarball of sample traces on [Google Drive](https://drive.google.com/file/d/1eKLK9Kvj5tsJVYbjB2PlFXUsMQGASjmW/view?usp=sharing) to get started. To run the [example](#example) below, download the tarball, move it to the ```getting-started/``` directory, and unpack. 
* ```-distill``` is a config file that specifies the distillation strategy (e.g. implicit, explicit only). If the traces don't have call coverage information or you simply don't want to distill, then this parameter should be ommitted and MoonShine will generate traces "as is". We have provided an example config under ```getting-started/distill.json```
#### Example

```bash
$ ./bin/moonshine -dir getting-started/sampletraces/ -distill getting-started/distill.json
Total number of Files: 346
Parsing File 1/346: ltp_accept4_01
Parsing File 2/346: ltp_accept_01
...
Total Distilled Progs: 391
Average Program Length: 10
Total contributing calls: 639 out of 43480 in 388 implicitly-distilled programs. Total calls: 3250
```

MoonShine produces a ```corpus.db``` file that contains the serialized Syzkaller programs. Move ```corpus.db``` to your Syzkaller workdir and begin fuzzing!

MoonShine also writes the deserialized syzkaller programs from the traces under ```deserialized``` so that you can manually inspect the conversion. If moonshine was run without distillation, then the programs in the deserialized directory obey the naming convention ```[trace_name]+[id]```. If the original trace consists of 1 task, ```id``` should always be 1, but if there are multiple tasks then each task is assigned a unique id and converted to a separate program. 

```bash
$ ls deserialized/
ltp_accept_011
ltp_accept4_011
...
```

## Syzkaller and Linux
MoonShine has been tested with Syzkaller commit ```f48c20b8f9b2a6c26629f11cc15e1c9c316572c8```. Instructions to setup Syzkaller and to build Linux disk images for fuzzing can be found [here](https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md). Although the instructions say they are for Ubuntu 14.04 it also works for Ubuntu 16.04+.

## Collecting Traces

### Strace
Currently, MoonShine can only parse traces gathered with strace. We also suggest that you use strace versions >= 4.16 as those are the only versions we have tried so far. You can download specific releases at the [Official Strace Release](https://github.com/strace/strace/releases) page. Build instructions can be found [here](https://github.com/strace/strace/blob/master/INSTALL).

### Coverage
MoonShine needs to know the coverage achieved by each call in a trace in order to distill traces. We have created a patch [strace_kcov.patch](/strace_kcov.patch) for strace that captures per-call coverage using [kcov](https://lwn.net/Articles/671640/). This patch should be applied to commit ```a8d2417e97e71ae01095bee1a1e563b07f2d6b41```. Follow the below instructions to both build strace and apply the patch.
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

### Strace Command Line Arguments

#### Required
* -s [val] indicates the maximum amount of data that should be written for each call. We typically set val to 65500.
* -v means the arguments should be unabbreviated
* -xx writes strings in hex

#### Optional
* -f captures traces from children processes (follows forks)
* -k captures per-call coverage (Only supported on patched strace. Requires kernel compiled with CONFIG_KCOV=y)

#### Example
```bash
$ strace -o tracefile -s 65500 -v -xx -f -k /path/to/executable arg1 arg2 .. argN
```
# Project Structure

MoonShine's code is concentrated in 5 directories:

* ```strace_types``` - contains data structures corresponding to high level types present in the strace traces such as call, structs, int, flag, etc.. In essence, this these types are composed to provide in-memory representation of the Trace
* ```scanner``` - scans and parses strace programs into their in-memory representation
* ```parser``` - converts the in-memory trace representation into a Syzkaller program
* ```distiller``` - distills the Syzkaller using the coverage gathered from traces.
* ```implicit-dependencies``` - contains a json of the implicit dependencies found by our Smatch static analysis checkers. 

# Bug Trophy Case
* [Memory Corruption in inotify_handle_event()](https://access.redhat.com/security/cve/cve-2017-7533) (CVE-2017-7533)
* [Memory Corruption in __jfs_setxattr()](https://access.redhat.com/security/cve/cve-2018-12233) (CVE-2018-12233)
* [Denial of Serivce in socket_setattr()](https://access.redhat.com/security/cve/cve-2018-12232) (CVE-2018-12232)
* [Double free in inet_child_forget()](https://lkml.org/lkml/2017/9/8/230)
* [Use after free in move_expired_inodes()](https://lkml.org/lkml/2017/10/31/455)
* [Integer overflow in pipe_set_size()](https://lkml.org/lkml/2017/9/11/458)
* [Integer overflow in posix_cpu_timer_set()](http://lkml.iu.edu/hypermail/linux/kernel/1709.0/02473.html)
* [Deadlock in Reiserfs](https://lkml.org/lkml/2017/9/29/611)

# Citing MoonShine
```
@inproceedings {Pailoor18,
   author = {Shankara Pailoor and Andrew Aday and Suman Jana},
   title = {MoonShine: Optimizing {OS} Fuzzer Seed Selection with Trace Distillation},
   booktitle = {27th {USENIX} Security Symposium ({USENIX} Security 18)},
   year = {2018},
   address = {Baltimore, MD},
   url = {https://www.usenix.org/conference/usenixsecurity18/presentation/pailoor},
   publisher = {{USENIX} Association},
}
```

# Contributors
* Shankara Pailoor - <sp3485@columbia.edu>
* [Suman Jana](https://sumanj.info) - <suman@cs.columbia.edu>
* Andrew Aday - <andrew.aday@columbia.edu>
