package distiller

import (
	"github.com/google/syzkaller/prog"
	"github.com/shankarapailoor/moonshine/configs"
	"github.com/shankarapailoor/moonshine/implicit-dependencies"
)

//Distiller is an interface that allows multiple distillation strategies
type Distiller interface {
	//Distill takes a collection of syzkaller programs and returns a list of distilled programs
	Distill([]*prog.Prog) []*prog.Prog
	//Add adds seeds to the distiller
	Add(Seeds)
	//Stats saves stats of the distillation to a file
	Stats(Seeds)
}

//NewDistiller returns a distillation interface
func NewDistiller(conf *config.DistillConfig) (d Distiller) {
	switch conf.Type {
	case "weak":
		d = NewWeakDistiller(conf)
	case "explicit":
		d = NewExplicitDistiller(conf)
	case "implicit":
		d = NewImplicitDistiller(conf)
	case "trace":
		d = NewTraceDistiller(conf)
	case "random":
		d = NewRandomDistiller(conf)
	default:
		d = NewWeakDistiller(conf)
	}
	return
}

//NewRandomDistiller returns a distiller that randomly selects calls
func NewRandomDistiller(conf *config.DistillConfig) (d *RandomDistiller) {
	d = new(RandomDistiller)
	dm := &Metadata{
		StatFile:                conf.Stats,
		DistilledProgs:          make([]*prog.Prog, 0),
		CallToSeed:              make(map[*prog.Call]*Seed, 0),
		CallToDistilledProg:     make(map[*prog.Call]*prog.Prog, 0),
		CallToIdx:               make(map[*prog.Call]int, 0),
		UpstreamDependencyGraph: make(map[*Seed]map[int]map[prog.Arg][]prog.Arg, 0),
		DownstreamDependents:    make(map[*Seed]map[int]bool, 0),
	}
	d.Metadata = dm
	return
}

//NewTraceDistiller returns a distiller which performs MinSet on a collection of traces
func NewTraceDistiller(conf *config.DistillConfig) (d *TraceDistiller) {
	d = new(TraceDistiller)
	dm := &Metadata{
		StatFile:                conf.Stats,
		DistilledProgs:          make([]*prog.Prog, 0),
		CallToSeed:              make(map[*prog.Call]*Seed, 0),
		CallToDistilledProg:     make(map[*prog.Call]*prog.Prog, 0),
		CallToIdx:               make(map[*prog.Call]int, 0),
		UpstreamDependencyGraph: make(map[*Seed]map[int]map[prog.Arg][]prog.Arg, 0),
		DownstreamDependents:    make(map[*Seed]map[int]bool, 0),
	}
	d.Metadata = dm
	return
}

//NewExplicitDistiller returns a distiller which just tracks explicit dependencies
func NewExplicitDistiller(conf *config.DistillConfig) (d *ExplicitDistiller) {
	d = new(ExplicitDistiller)
	dm := &Metadata{
		StatFile:                conf.Stats,
		DistilledProgs:          make([]*prog.Prog, 0),
		CallToSeed:              make(map[*prog.Call]*Seed, 0),
		CallToDistilledProg:     make(map[*prog.Call]*prog.Prog, 0),
		CallToIdx:               make(map[*prog.Call]int, 0),
		UpstreamDependencyGraph: make(map[*Seed]map[int]map[prog.Arg][]prog.Arg, 0),
		DownstreamDependents:    make(map[*Seed]map[int]bool, 0),
	}
	d.Metadata = dm
	return
}

//NewWeakDistiller returns a distiller which tracks weak dependencies
func NewWeakDistiller(conf *config.DistillConfig) (d *WeakDistiller) {
	d = new(WeakDistiller)
	dm := &Metadata{
		StatFile:                conf.Stats,
		DistilledProgs:          make([]*prog.Prog, 0),
		CallToSeed:              make(map[*prog.Call]*Seed, 0),
		CallToDistilledProg:     make(map[*prog.Call]*prog.Prog, 0),
		CallToIdx:               make(map[*prog.Call]int, 0),
		UpstreamDependencyGraph: make(map[*Seed]map[int]map[prog.Arg][]prog.Arg, 0),
		DownstreamDependents:    make(map[*Seed]map[int]bool, 0),
	}
	d.Metadata = dm
	return
}

//NewImplicitDistiller returns a distiller which tracks implicit dependencies
func NewImplicitDistiller(conf *config.DistillConfig) (d *ImplicitDistiller) {
	d = new(ImplicitDistiller)
	dm := &Metadata{
		StatFile:                conf.Stats,
		DistilledProgs:          make([]*prog.Prog, 0),
		CallToSeed:              make(map[*prog.Call]*Seed, 0),
		CallToDistilledProg:     make(map[*prog.Call]*prog.Prog, 0),
		CallToIdx:               make(map[*prog.Call]int, 0),
		UpstreamDependencyGraph: make(map[*Seed]map[int]map[prog.Arg][]prog.Arg, 0),
		DownstreamDependents:    make(map[*Seed]map[int]bool, 0),
	}
	implDeps := implicit_dependencies.LoadImplicitDependencies(conf.ImplicitDepsFile)
	d.Metadata = dm
	d.implDeps = *implDeps
	return
}
