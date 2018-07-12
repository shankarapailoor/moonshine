package tracker

import (
	. "github.com/google/syzkaller/prog"
)

const (
	maxPages   = 4 << 10
	PageSize   = 4 << 10
	dataOffset = 512 << 20
)

type State struct {
	Target    *Target
	Files     map[string][]*Call
	Resources map[string][]Arg
	Strings   map[string]*Call
	Pages     [maxPages]bool
	Pages_    [maxPages]int
	Tracker	  *MemoryTracker
	CurrentCall *Call
}


func NewState(target *Target) *State {
	s := &State{
		Target:    target,
		Files:     make(map[string][]*Call),
		Resources: make(map[string][]Arg),
		Strings:   make(map[string]*Call),
		Tracker:   NewTracker(),
		CurrentCall: nil,
	}
	return s
}


func (s *State) Analyze(c *Call) {
	ForeachArg(c, func(arg Arg, _ *ArgCtx) {
		switch typ := arg.Type().(type) {
		case *ResourceType:
			a := arg.(*ResultArg)
			if typ.Dir() != DirIn {
				s.Resources[typ.Desc.Name] = append(s.Resources[typ.Desc.Name], a)
				// TODO: negative PIDs and add them as well (that's process groups).
			}
		case *BufferType:
			a := arg.(*DataArg)
			if typ.Dir() != DirOut && len(a.Data()) != 0 {
				val := string(a.Data())
				// Remove trailing zero padding.
				for len(val) >= 2 && val[len(val)-1] == 0 && val[len(val)-2] == 0 {
					val = val[:len(val)-1]
				}
				switch typ.Kind {
				case BufferString:
					s.Strings[val] = c
				case BufferFilename:
					if len(val) < 3 {
						// This is not our file, probalby one of specialFiles.
						return
					}
					/*
					if val[len(val)-1] == 0 {
						val = val[:len(val)-1]
					}*/
					if s.Files[val] == nil {
						s.Files[val] = make([]*Call, 0)
					}
					s.Files[val] = append(s.Files[val], c)
				}
			}
		}
	})
}