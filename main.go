package main

import (
	"flag"
	"fmt"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
	"github.com/shankarapailoor/moonshine/configs"
	"github.com/shankarapailoor/moonshine/distiller"
	"github.com/shankarapailoor/moonshine/logging"
	"github.com/shankarapailoor/moonshine/parser"
	"github.com/shankarapailoor/moonshine/scanner"
	"github.com/shankarapailoor/moonshine/straceTypes"
	"github.com/shankarapailoor/moonshine/tracker"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	flagFile    = flag.String("file", "", "file to parse")
	flagDir     = flag.String("dir", "", "director to parse")
	flagDistill = flag.String("distill", "", "Path to distillation config")
)

const (
	//Target OS
	OS = "linux"
	//Target architecture
	Arch = "amd64"
	//Marked as minimized
	currentDBVersion = 3
)

func main() {
	rev := sys.GitRevision
	flag.Parse()
	target, err := prog.GetTarget(OS, Arch)
	if err != nil {
		logging.Failf("error getting target: %v, git revision: %v", err.Error(), rev)
	} else {
		parseTraces(target)
		pack("deserialized", "corpus.db")
	}
}

func progIsTooLarge(p *prog.Prog) bool {
	buff := make([]byte, prog.ExecBufferSize)
	if _, err := p.SerializeForExec(buff); err != nil {
		return true
	}
	return false
}

func parseTraces(target *prog.Target) []*parser.Context {
	ret := make([]*parser.Context, 0)
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
	totalFiles := len(names)
	fmt.Printf("Total Number of Files: %d\n", totalFiles)
	for i, file := range names {
		fmt.Printf("Parsing File %d/%d: %s\n", i+1, totalFiles, path.Base(names[i]))
		tree := scanner.Scan(file)
		if tree == nil {
			fmt.Fprintf(os.Stderr, "File: %s is empty\n", path.Base(file))
			continue
		}
		ctxs := parseTree(tree, tree.RootPid, target)
		ret = append(ret, ctxs...)
		for i, ctx := range ctxs {
			ctx.Prog.Target = ctx.Target
			if !distill {
				if err := fillOutMemory(ctx.Prog, ctx.State.Tracker); err != nil {
					//fmt.Fprintln(os.Stderr, "Failed to fill out memory")
					continue
				}
				if progIsTooLarge(ctx.Prog) {
					fmt.Fprintln(os.Stderr, "Prog is too large")
					continue
				}
				progName := "deserialized/" + filepath.Base(file) + strconv.Itoa(i)
				if err := ioutil.WriteFile(progName, ctx.Prog.Serialize(), 0640); err != nil {
					logging.Failf("failed to output file: %v", err)
				}
			} else {
				newSeeds := ctx.GenerateSeeds()
				for _, seed := range newSeeds {
					seeds.Add(seed)
				}
			}
		}

	}
	if distill {
		fmt.Fprintf(os.Stderr, "Total number of seeds: %d\n", seeds.Len())
		distler := distiller.NewDistiller(config.NewDistillConfig(*flagDistill))
		distler.Add(seeds)
		distilledProgs := distler.Distill(parser.GetProgs(ret))
		for i, p := range distilledProgs {
			if progIsTooLarge(p) {
				fmt.Fprintln(os.Stderr, "Prog is too large")
				continue
			}
			if err := p.Validate(); err != nil {
				panic(fmt.Sprintf("Error validating program: %s\n", err.Error()))
			}
			s_name := "deserialized/" + "distill" + strconv.Itoa(i)
			if err := ioutil.WriteFile(s_name, p.Serialize(), 0640); err != nil {
				logging.Failf("failed to output file: %v", err)
			}
		}
	}
	return ret
}

func getFileNames(dir string) []string {
	names := make([]string, 0)
	if infos, err := ioutil.ReadDir(dir); err == nil {
		for _, info := range infos {
			name := path.Join(dir, info.Name())
			names = append(names, name)
		}
	} else {
		logging.Failf("Failed to read dir: %s\n", err.Error())
	}
	return names
}

func parseTree(tree *straceTypes.TraceTree, pid int64, target *prog.Target) []*parser.Context {
	ctxs := make([]*parser.Context, 0)
	ctx, err := parser.ParseProg(tree.TraceMap[pid], target)
	parsedProg := ctx.Prog
	if err != nil {
		panic("Failed to parse program")
	}

	if len(parsedProg.Calls) == 0 {
		parsedProg = nil
	}

	if parsedProg != nil {
		ctx.Prog = parsedProg
		ctxs = append(ctxs, ctx)
	}
	for _, pid_ := range tree.Ptree[pid] {
		if tree.TraceMap[pid_] != nil {
			ctxs = append(ctxs, parseTree(tree, pid_, target)...)
		}
	}
	return ctxs
}

func fillOutMemory(prog_ *prog.Prog, tracker *tracker.MemoryTracker) error {
	if err := tracker.FillOutMemory(prog_); err != nil {
		return err
	}
	totalMemory := tracker.GetTotalMemoryAllocations(prog_)
	if totalMemory == 0 {
		return fmt.Errorf("length of zero mem prog: %d\n", totalMemory)
	} else {
		mmapCall := prog_.Target.MakeMmap(0, uint64(totalMemory))
		calls := make([]*prog.Call, 0)
		calls = append(append(calls, mmapCall), prog_.Calls...)
		prog_.Calls = calls
	}
	if err := prog_.Validate(); err != nil {
		panic(fmt.Sprintf("Error validating program: %s\n", err.Error()))
	}

	return nil
}

func pack(dir, file string) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		logging.Failf("failed to read dir: %v", err)
	}
	os.Remove(file)
	db, err := db.Open(file)
	db.BumpVersion(currentDBVersion)
	if err != nil {
		logging.Failf("failed to open database file: %v", err)
	}
	fmt.Println("Deserializing programs => deserialized/")
	for _, file := range files {
		data, err := ioutil.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			logging.Failf("failed to read file %v: %v", file.Name(), err)
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
			key = sig
		}
		db.Save(key, data, seq)
	}
	if err := db.Flush(); err != nil {
		logging.Failf("failed to save database file: %v", err)
	}
}
