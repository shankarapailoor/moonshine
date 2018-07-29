# MoonShine: Seed Selection for OS Fuzzers (USENIX '18)

MoonShine selects compact and diverse seeds for OS fuzzers by distilling system call traces of real world programs. Our approach is described in detail in our USENIX'18 paper [MoonShine: Optimizing OS Fuzzer Seed Selection with Trace Distillation](http://www.cs.columbia.edu/~suman/docs/moonshine.pdf) for more details.

* [Setup Instructions](docs/setup.md)
* [Usage Instructions](docks/usage.md)


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