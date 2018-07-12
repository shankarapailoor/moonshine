package distiller

import (
	"github.com/google/syzkaller/prog"
	"fmt"
	"sort"
	"os"
)

const (
	pageSize = 4 << 10
)
var (
	RADIUS int = 2

)

type WeakDistiller struct {
	*DistillerMetadata
}

func (d *WeakDistiller) Add(seeds Seeds) {
	/* identical to strong distiller */
	d.Seeds = seeds
	for _, seed := range seeds {
		d.CallToSeed[seed.Call] = seed
		d.UpstreamDependencyGraph[seed] = make(map[int]map[prog.Arg][]prog.Arg, 0)
		seed.ArgMeta = make(map[prog.Arg]bool, 0)
		for call, idx := range seed.DependsOn {
			if _, ok := d.UpstreamDependencyGraph[seed][idx]; !ok {
				d.UpstreamDependencyGraph[seed][idx] = make(map[prog.Arg][]prog.Arg, 0)
			}
			d.CallToIdx[call] = idx
		}
		d.CallToIdx[seed.Call] = seed.CallIdx
	}
}


func (d *WeakDistiller) Distill(progs []*prog.Prog) (distilled []*prog.Prog) {
	seenIps := make(map[uint64]bool)
	seeds := d.Seeds
	fmt.Printf("Computing Min Cover with %d seeds\n", len(seeds))
	sort.Sort(sort.Reverse(seeds))
	contributing_progs := 0
	heavyHitters := make(Seeds, 0)
	for _, prog := range progs {
		d.TrackDependencies(prog)
	}
	for _, seed := range seeds {
		var ips int = d.Contributes(seed, seenIps)
		if ips > 0 {
			heavyHitters.Add(seed)
			fmt.Printf("Seed: %s contributes: %d ips out of its total of: %d\n", seed.Call.Meta.Name, ips, len(seed.Cover))
			contributing_progs += 1
		}
	}
	d.Stats(heavyHitters)
	for _, seed := range heavyHitters {
		d.AddToDistilledProg(seed)
	}
	distilledProgs := make(map[*prog.Prog]bool)
	for _, seed := range seeds {
		if _, ok := d.CallToDistilledProg[seed.Call]; ok {
			distilledProgs[d.CallToDistilledProg[seed.Call]] = true
		}
	}
	for prog_, _ := range distilledProgs {
		seed := d.CallToSeed[prog_.Calls[0]]
		state := seed.State
		if err := d.CallToSeed[prog_.Calls[0]].State.Tracker.FillOutMemory(prog_); err != nil {
			fmt.Printf("Error: %s\n", err.Error())
            continue
		}
		totalMemory := state.Tracker.GetTotalMemoryAllocations(prog_)
		mmapCall := state.Target.MakeMmap(0, uint64(totalMemory/pageSize)+1)
		calls := make([]*prog.Call, 0)
		calls = append(append(calls, mmapCall), prog_.Calls...)

		prog_.Calls = calls

		//fmt.Printf("Prog: %v\n", prog)
		distilled = append(distilled, prog_)
	}
	fmt.Fprintf(os.Stderr, "Total Contributing seeds: %d out of %d, in %d weak-distilled programs\n",
		contributing_progs, len(seeds), len(distilled))
	return
}

func (d *WeakDistiller) AddToDistilledProg(seed *Seed) {
	distilledProg := new(prog.Prog)
	distilledProg.Calls = make([]*prog.Call, 0)
	callIndexes := make([]int, 0)

	if d.CallToDistilledProg[seed.Call] != nil {
		return
	}
	seedCalls := d.GetNeighbors(seed)
	totalCalls := d.GetDependents(seedCalls)
	callIndexes = d.uniqueCallIdxs(totalCalls)

	for _, idx := range callIndexes {
		call := seed.Prog.Calls[idx]
		d.CallToDistilledProg[call] = distilledProg
		distilledProg.Calls = append(distilledProg.Calls, call)
	}
	d.BuildDependency(seed, distilledProg)
}

func (d *WeakDistiller) GetNeighbors(seed *Seed) []*prog.Call {
	upperNeighbors := make([]*prog.Call, 0)
	lowerNeighbors := make([]*prog.Call, 0)
	foundLowerNeighbors := false
	foundUpperNeighbors := true
	var i, j int = 0, 0
	for {
		if len(lowerNeighbors) >= RADIUS && len(upperNeighbors) >= RADIUS {
			break
		} else if foundUpperNeighbors && foundLowerNeighbors {
			break
		} else {
			lowIdx := seed.CallIdx - i
			if seed.CallIdx - i < 0 {
				foundLowerNeighbors = true
			} else {
				c := seed.Prog.Calls[lowIdx]
				if _, ok := d.CallToSeed[c]; ok {
					lowerNeighbors = append(lowerNeighbors, seed.Prog.Calls[lowIdx])
				}
			}
			highIdx := seed.CallIdx + j
			if highIdx >= len(seed.Prog.Calls) {
				foundUpperNeighbors = true
			} else {
				c := seed.Prog.Calls[highIdx]
				if _, ok := d.CallToSeed[c]; ok {
					upperNeighbors = append(upperNeighbors, seed.Prog.Calls[highIdx])
				}
			}
		}
		i++; j++
	}
	seedCalls := append(upperNeighbors, lowerNeighbors...)
	seedCalls = append(seedCalls, seed.Call)
	return seedCalls
}

/*
This is the core of the weak distiller. We start with the centroid and get all downstream dependents.
Every call needs its upstream dependents to run correctly so we get those. We then pull all downstream dependents of
those upstreams and if there are any new calls, we pull the upstream of them. We can keep going, but this is a heuristic
 */
func (d *WeakDistiller) GetDependents(seedCalls []*prog.Call) []*prog.Call {
	seenMap := make(map[int]bool, 0)
	upstreamCalls := make([]*prog.Call, 0)
	downstreamCalls := make([]*prog.Call, 0)
	totalCalls := make([]*prog.Call, 0)

	//Get downstream dependents of our centroid
	for _, call := range seedCalls {
		downstreamCalls = append(downstreamCalls, d.GetAllDownstreamDependents(d.CallToSeed[call], seenMap)...)
	}
	downstreamCalls = append(downstreamCalls, seedCalls...)
	//Get all upstream dependent calls for our downstream ones
	for _, dcall := range downstreamCalls {
		if dseed, ok := d.CallToSeed[dcall]; ok {
			upstreamCalls = append(upstreamCalls, d.GetAllUpstreamDependents(dseed, seenMap)...)
		}
	}
	moreCalls := make([]*prog.Call, 0)
	//Get downstream calls for our upstream ones
	for _, dcall := range upstreamCalls {
		if dseed, ok := d.CallToSeed[dcall]; ok {
			moreCalls = append(moreCalls, d.GetAllDownstreamDependents(dseed, seenMap)...)
		}
	}
	//Get all upstream dependencies so our program behaves correctly
	for _, dcall := range moreCalls {
		moreCalls = append(moreCalls, d.GetAllUpstreamDependents(d.CallToSeed[dcall], seenMap)...)
	}

	connectedCalls := append(upstreamCalls, downstreamCalls...)
	connectedCalls = append(connectedCalls, moreCalls...)
	distinctProgs := d.getAllProgs(connectedCalls)
	if len(distinctProgs) > 0 {
		totalCalls = append(d.getCalls(distinctProgs), upstreamCalls...)
	} else {
		totalCalls = connectedCalls
	}
	return totalCalls
}
