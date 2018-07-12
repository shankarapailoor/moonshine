package distiller

import (
	"github.com/google/syzkaller/prog"
	"sort"
	"fmt"
	"os"
)

type TraceDistiller struct {
	*DistillerMetadata
}

type Traces []*Trace

type Trace struct {
	Prog *prog.Prog
	Cover []uint64
}

func (t Traces) Len() int {
	return len(t)
}

func (t Traces) Swap(i, j int) {
	t[i], t[j] = t[j], t[i]
}

func (t Traces) Less(i, j int) bool {
	return len(t[i].Cover) < len(t[j].Cover)
}

func (t *Traces) Add(trace *Trace) {
	*t = append(*t, trace)
}



func (d *TraceDistiller) traces(progs []*prog.Prog) Traces {
	traces := make(Traces, 0)
	for _, p := range progs {
		traces.Add(d.trace(p))
	}
	sort.Sort(sort.Reverse(traces))
	return traces
}

func (d *TraceDistiller) trace(p *prog.Prog) *Trace {
	coverMap := make(map[uint64]bool, 0)
	cover := make([]uint64, 0)
	trace := new(Trace)
	for _, call := range p.Calls {
		if s, ok := d.CallToSeed[call]; ok {
			for _, ip := range s.Cover {
				if _, ok := coverMap[ip]; !ok {
					coverMap[ip] = true
				}
			}
		}
	}
	for ip, _ := range coverMap {
		cover = append(cover, ip)
	}
	trace.Cover = cover
	trace.Prog = p
	return trace
}

func (d *TraceDistiller) Add(seeds Seeds) {
	d.Seeds = seeds
	for _, seed := range seeds {
		d.CallToSeed[seed.Call] = seed
		d.UpstreamDependencyGraph[seed] = make(map[int]map[prog.Arg][]prog.Arg, 0)
		seed.ArgMeta = make(map[prog.Arg]bool, 0)
		for call,idx := range seed.DependsOn {
			if _, ok := d.UpstreamDependencyGraph[seed][idx]; !ok {
				d.UpstreamDependencyGraph[seed][idx] = make(map[prog.Arg][]prog.Arg, 0)
			}
			d.CallToIdx[call] = idx
		}
		d.CallToIdx[seed.Call] = seed.CallIdx
	}
}

func (d *TraceDistiller) Distill(progs []*prog.Prog) (distilled []*prog.Prog) {
	fmt.Fprintf(os.Stderr, "Distilling %d programs with trace method\n", len(progs))
	seenIps := make(map[uint64]bool)
	traces := d.traces(progs)
	sort.Sort(sort.Reverse(traces))
	distilledProgs := make([]*prog.Prog, 0)

	for _, trace := range traces {
		if d.Contributes(trace, seenIps) > 0 {
			distilledProgs = append(distilledProgs, trace.Prog)
		}
	}
	for _, prog_ := range distilledProgs {
		if err := d.CallToSeed[prog_.Calls[0]].State.Tracker.FillOutMemory(prog_); err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			continue
		}
		totalMemoryAllocations := d.CallToSeed[prog_.Calls[0]].State.Tracker.GetTotalMemoryAllocations(prog_)
		state := d.CallToSeed[prog_.Calls[0]].State
		mmapCall := state.Target.MakeMmap(0, uint64(totalMemoryAllocations/pageSize)+1)
		calls := make([]*prog.Call, 0)
		calls = append(append(calls, mmapCall), prog_.Calls...)

		prog_.Calls = calls
		distilled = append(distilled, prog_)
	}
	fmt.Fprintf(os.Stderr, "Only: %d programs contribute new coverage\n", len(distilled))
	return
}

func (d *TraceDistiller) Contributes(trace *Trace, seenIps map[uint64]bool) int {
	total := 0
	for _, ip := range trace.Cover {
		if _, ok := seenIps[ip]; !ok {
			seenIps[ip] = true
			total += 1
		}
	}
	return total
}