package distiller

import (
	"github.com/google/syzkaller/prog"
	"fmt"
	"sort"
	"os"
)

func (d *StrongDistiller) Add(seeds Seeds) {
	/* builds out CallToIdx which is used for sorting calls in distilled programs */
	d.Seeds = seeds
	for _, seed := range seeds {
		d.CallToSeed[seed.Call] = seed
		d.UpstreamDependencyGraph[seed] = make(map[int]map[prog.Arg][]prog.Arg, 0)
		seed.ArgMeta = make(map[prog.Arg]bool, 0)
		for call, idx := range seed.DependsOn {
			if _, ok := d.UpstreamDependencyGraph[seed][idx]; !ok {
				/* Loop over upstream, dependent calls within seed.Prog.
				Dependent call c is the idx'th call in seed.Prog.
				Set d.UpstreamDependencyGraph[idx] = { Arg --> [Args] }
				 */
				d.UpstreamDependencyGraph[seed][idx] = make(map[prog.Arg][]prog.Arg, 0)
			}
			d.CallToIdx[call] = idx  // track position of dependent calls
		}
		d.CallToIdx[seed.Call] = seed.CallIdx  // track position of seed call
	}
}

func (d *StrongDistiller) Distill(progs []*prog.Prog) (distilled []*prog.Prog) {
	seenIps := make(map[uint64]bool)
	seeds := d.Seeds
	fmt.Printf("Computing Min Cover with %d seeds\n", len(seeds))
	sort.Sort(sort.Reverse(seeds))
	contributing_seeds := 0  /* how many seeds contribute new coverage? */
	heavyHitters := make(Seeds, 0)  /* all seeds that contribute new coverage */
	for _, prog := range progs {
		d.TrackDependencies(prog)
	}
	for _, seed := range seeds {
		var ips int = d.Contributes(seed, seenIps)  /* how many unique Ips does seed contribute */
		if ips > 0 {
			heavyHitters.Add(seed)
			fmt.Printf("Seed: %s contributes: %d ips out of its total of: %d\n", seed.Call.Meta.Name, ips, len(seed.Cover))
			contributing_seeds += 1
		}
	}
	d.Stats(heavyHitters)
	for _, seed := range heavyHitters {
		//Pulls upstream dependencies
		//If any upstream dependencies are in a distilled prog we add our call to that
		//and merge all programs that contain our upstream dependencies
		d.AddToDistilledProg(seed)
	}
	//At this point our programs are stored in map: Call->Distilled Program
	//We now want to get the programs
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

		totalMemoryAllocations := d.CallToSeed[prog_.Calls[0]].State.Tracker.GetTotalMemoryAllocations(prog_)
		mmapCall := state.Target.MakeMmap(0, uint64(totalMemoryAllocations))
		calls := make([]*prog.Call, 0)
		calls = append(append(calls, mmapCall), prog_.Calls...)

		prog_.Calls = calls
		prog_.Target = state.Target

		prog_.Calls = calls
		distilled = append(distilled, prog_)
	}
	fmt.Fprintf(os.Stderr, "Total Contributing seeds: %d out of %d, in %d strong-distilled programs\n",
		   contributing_seeds, len(seeds), len(distilled))
	return
}


func (d *StrongDistiller) AddToDistilledProg(seed *Seed) {
	distilledProg := new(prog.Prog)
	distilledProg.Calls = make([]*prog.Call, 0)
	callIndexes := make([]int, 0)
	totalCalls := make([]*prog.Call, 0)

	if d.CallToDistilledProg[seed.Call] != nil {
		return  /* skip call if already in a distilled program */
	}
	seenMap := make(map[int]bool, 0)
	upstreamCalls := make([]*prog.Call, 0)
	/* collect list of all upstream dependent calls, unsorted? */
	upstreamCalls = append(upstreamCalls, d.GetAllUpstreamDependents(seed, seenMap)...)
	upstreamCalls = append(upstreamCalls, seed.Call) // add seed as last call
	distinctProgs := d.getAllProgs(upstreamCalls)
	if len(distinctProgs) > 0 {  // we need to merge!
		// collect all the calls from all distinct progs, plus our upstreamCalls together
		totalCalls = append(d.getCalls(distinctProgs), upstreamCalls...)
	} else {
		totalCalls = upstreamCalls
	}

	callIndexes = d.uniqueCallIdxs(totalCalls)  // dedups and sorts calls by their program idx
	for _, idx := range callIndexes {
		call := seed.Prog.Calls[idx]
		d.CallToDistilledProg[call] = distilledProg  // set calls to point to new, merged program
		distilledProg.Calls = append(distilledProg.Calls, call)
	}
	d.BuildDependency(seed, distilledProg)  // set args to point to dependent args.
}
