package main

import (
	. "github.com/shankarapailoor/moonshine/scanner"
	. "github.com/shankarapailoor/moonshine/parser"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/pkg/hash"
	"fmt"
	"os"
	"github.com/google/syzkaller/pkg/db"
	"io/ioutil"
	"path/filepath"
	"strings"
	"strconv"
	"flag"
	"github.com/shankarapailoor/moonshine/strace_types"
	. "github.com/shankarapailoor/moonshine/logging"
	"github.com/google/syzkaller/sys"
	"path"
	"github.com/shankarapailoor/moonshine/tracker"
	"github.com/shankarapailoor/moonshine/distiller"
	"github.com/shankarapailoor/moonshine/configs"
)

var (
	flagFile = flag.String("file", "", "file to parse")
	flagDir = flag.String("dir", "", "director to parse")
	flagDistill = flag.String("distill", "", "Path to distillation config")
)

const (
	OS = "linux"
	Arch = "amd64"
	currentDBVersion = 3

)

func main() {
	fmt.Printf("git revision: %s\n", sys.GitRevision)
	flag.Parse()
	target, err := prog.GetTarget(OS, Arch)
	if err != nil {
		Failf("error getting target: %v", err.Error())
	} else {
		ParseTraces(target)
		pack("serialized", "corpus.db")
	}
}

func progIsTooLarge(prog_ *prog.Prog) bool {
	buff := make([]byte, prog.ExecBufferSize)
	if _, err := prog_.SerializeForExec(buff); err != nil {
		return true
	}
	return false
}

func ParseTraces(target *prog.Target) []*Context {
	ret := make([]*Context, 0)
	names := make([]string, 0)
	distill := false
	if *flagFile != "" {
		names = append(names, *flagFile)
	} else if *flagDir != "" {
		names = getFileNames(*flagDir)
	} else {
		panic("Flag or FlagDir required")
	}

	if *flagDistill != "" {
		distill = true
	}
	seeds := make(distiller.Seeds, 0)
	for _, file := range(names) {
		fmt.Printf("Scanning file: %s\n", file)
		tree := Parse(file)
		if tree == nil {
			fmt.Fprintf(os.Stderr, "File: %s is empty\n", file)
			continue
		}
		ctxs := ParseTree(tree, tree.RootPid, target)
		ret = append(ret, ctxs...)
		i := 0
		for _, ctx := range ctxs {
			ctx.Prog.Target = ctx.Target
			if !distill {
				if err := FillOutMemory(ctx.Prog, ctx.State.Tracker); err != nil {
					fmt.Fprintln(os.Stderr, "Failed to fill out memory\n")
					continue
				}
				if progIsTooLarge(ctx.Prog) {
					fmt.Fprintln(os.Stderr, "Prog is too large\n")
					continue
				}
				i += 1
				s_name := "serialized/" + filepath.Base(file) + strconv.Itoa(i)
				if err := ioutil.WriteFile(s_name, ctx.Prog.Serialize(), 0640); err != nil {
					Failf("failed to output file: %v", err)
				}
			} else {
				newSeeds := ctx.GenerateSeeds()
				for _, seed := range newSeeds {
					seeds.Add(seed)
				}
			}
		}

		fmt.Fprintf(os.Stderr, "Total number of seeds: %d\n", seeds.Len())
	}
	if distill {
		distler := distiller.NewDistiller(config.NewDistillConfig(*flagDistill))
		distler.Add(seeds)
		distilledProgs := distler.Distill(GetProgs(ret))
		for i, prog_ := range distilledProgs {
			if progIsTooLarge(prog_) {
				fmt.Fprintln(os.Stderr, "Prog is too large")
				continue
			}
			if err := prog_.Validate(); err != nil {
				panic(fmt.Sprintf("Error validating program: %s\n", err.Error()))
			}
			s_name := "serialized/" + "distill" + strconv.Itoa(i)
			if err := ioutil.WriteFile(s_name, prog_.Serialize(), 0640); err != nil {
				Failf("failed to output file: %v", err)
			}
		}
	}
	return ret
}



func getFileNames(dir string) []string {
	names := make([]string, 0)
	if infos, err := ioutil.ReadDir(dir); err == nil {
		for _, info := range (infos) {
			name := path.Join(dir, info.Name())
			names = append(names, name)
		}
	} else {
		Failf("Failed to read dir: %s\n", err.Error())
	}
	return names
}

func ParseTree(tree *strace_types.TraceTree, pid int64, target *prog.Target) []*Context {
	fmt.Fprintf(os.Stderr, "Parsing tree for file: %s\n", tree.Filename)
	ctxs := make([]*Context, 0)
	ctx, err := ParseProg(tree.TraceMap[pid], target)
	parsedProg := ctx.Prog
	if err != nil {
		panic("Failed to parse program")
	}

	if len(parsedProg.Calls) == 0 {
		parsedProg = nil
	}

	if parsedProg != nil {
		ctx.Prog = parsedProg
		fmt.Fprintf(os.Stderr, "Appending program: %s %d\n", tree.Filename, pid)
		ctxs = append(ctxs, ctx)
	}
	for _, pid_ := range(tree.Ptree[pid]) {
		if tree.TraceMap[pid_] != nil{
			ctxs = append(ctxs, ParseTree(tree, pid_, target)...)
		}
	}
	return ctxs
}

func FillOutMemory(prog_ *prog.Prog, tracker *tracker.MemoryTracker) error {
	if err := tracker.FillOutMemory(prog_); err != nil {
		return err
	} else {
		totalMemory := tracker.GetTotalMemoryAllocations(prog_)
		if totalMemory == 0 {
			fmt.Printf("length of zero mem prog: %d\n", totalMemory)
		} else {
			mmapCall := prog_.Target.MakeMmap(0, uint64(totalMemory))
			calls := make([]*prog.Call, 0)
			calls = append(append(calls, mmapCall), prog_.Calls...)
			prog_.Calls = calls
		}
		if err := prog_.Validate(); err != nil {
			panic(fmt.Sprintf("Error validating program: %s\n", err.Error()))
		}
	}
	return nil
}


func pack(dir, file string) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		Failf("failed to read dir: %v", err)
	}
	os.Remove(file)
	db, err := db.Open(file)
	db.BumpVersion(currentDBVersion)
	if err != nil {
		Failf("failed to open database file: %v", err)
	}
	for _, file := range files {
		data, err := ioutil.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			Failf("failed to read file %v: %v", file.Name(), err)
		}
		var seq uint64
		key := file.Name()
		if parts := strings.Split(file.Name(), "-"); len(parts) == 2 {
			var err error

			if seq, err = strconv.ParseUint(parts[1], 10, 64); err == nil {
				key = parts[0]
			}
		}
		if sig := hash.String(data); key != sig {
			fmt.Fprintf(os.Stdout, "fixing hash %v -> %v\n", key, sig)
			key = sig
		}
		db.Save(key, data, seq)
	}
	if err := db.Flush(); err != nil {
		Failf("failed to save database file: %v", err)
	}
}
