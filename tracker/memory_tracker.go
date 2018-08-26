package tracker

import (
	"fmt"
	. "github.com/google/syzkaller/prog"
)

const (
	memAllocMaxMem = 16 << 20
)

type Allocation struct {
	num_bytes uint64
	arg       Arg
}

/*
Memory dependency represents the dependency of a call on a
virtual memory mapping. We assume the dependency is contiguous
as we will allocate pointers for arguments in a separate mmap at the
beginning of the function. Moreover there are no calls which we know of
that take a list of pages as arguments.
*/
type MemDependency struct {
	Callidx int
	arg     Arg
	start   uint64
	end     uint64
}

func NewMemDependency(callidx int, usedBy Arg, start uint64, end uint64) *MemDependency {
	return &MemDependency{
		Callidx: callidx,
		arg:     usedBy,
		start:   start,
		end:     end,
	}
}

type VirtualMapping struct {
	usedBy    []*MemDependency
	createdBy *Call
	callidx   int
	start     uint64
	end       uint64
}

type ShmRequest struct {
	size  uint64
	shmid uint64
	call  *Call
}

func (s *ShmRequest) GetSize() uint64 {
	return s.size
}

func (vm *VirtualMapping) GetUsedBy() []*MemDependency {
	return vm.usedBy
}

func (vm *VirtualMapping) AddDependency(md *MemDependency) {
	vm.usedBy = append(vm.usedBy, md)
}

func (vm *VirtualMapping) GetEnd() uint64 {
	return vm.end
}

func (vm *VirtualMapping) GetStart() uint64 {
	return vm.start
}

func (vm *VirtualMapping) GetCall() *Call {
	return vm.createdBy
}

func (vm *VirtualMapping) GetCallIdx() int {
	return vm.callidx
}

type MemoryTracker struct {
	allocations map[*Call][]*Allocation
	mappings    []*VirtualMapping
	/*
	 We keep the SYSTEM V shared mapping requests because
	 the creation of memory is broken into two steps: shmget, shmat
	 shmget requests for an amount of shared memory and returns an id for it
	 shmat generates the address for the given segment using the id but
	 when we add the address to our tracker we need to know the size.
	 Memory tracker seems like a good place to keep the requests
	*/
	shm_requests []*ShmRequest
}

func NewTracker() *MemoryTracker {
	m := new(MemoryTracker)
	m.allocations = make(map[*Call][]*Allocation, 0)
	m.mappings = make([]*VirtualMapping, 0)
	return m
}

func (m *MemoryTracker) AddShmRequest(call *Call, shmid uint64, size uint64) {
	shm_request := &ShmRequest{
		size:  size,
		shmid: shmid,
		call:  call,
	}
	m.shm_requests = append(m.shm_requests, shm_request)
}

func (m *MemoryTracker) FindShmRequest(shmid uint64) *ShmRequest {
	//Get the latest Request associated with id
	var ret *ShmRequest = nil
	for _, req := range m.shm_requests {
		var req_ *ShmRequest = req
		if req.shmid == shmid {
			ret = req_
		}
	}
	return ret
}

func (m *MemoryTracker) CreateMapping(call *Call, callidx int, arg Arg, start uint64, end uint64) {

	mapping := &VirtualMapping{
		createdBy: call,
		callidx:   callidx,
		start:     start,
		end:       end,
		usedBy:    make([]*MemDependency, 0),
	}
	mapping.usedBy = append(mapping.usedBy, &MemDependency{start: start, end: end, arg: arg})
	m.mappings = append(m.mappings, mapping)
}

func (m *MemoryTracker) Mappings(start uint64, end uint64) []*VirtualMapping {
	/*
		Get all mappings whose totality encompasses start and end.
	*/
	maps := make([]*VirtualMapping, 0)

	for _, mapping := range m.mappings {
		if mapping.start < start && mapping.end >= start {
			maps = append(maps, mapping)
		} else if mapping.start <= end && mapping.end >= end {
			maps = append(maps, mapping)
		}
	}
	return maps
}

func (m *MemoryTracker) FindLatestOverlappingVMA(start uint64) *VirtualMapping {
	var ret *VirtualMapping = nil
	for _, mapping := range m.mappings {
		mapCopy := mapping

		if mapping.start <= start && mapping.end >= start {
			ret = mapCopy
		}
	}
	return ret
}

func (m *MemoryTracker) AddAllocation(call *Call, size uint64, arg Arg) {
	switch arg.(type) {
	case *PointerArg:
	default:
		panic("Adding allocation for non pointer")
	}
	allocation := new(Allocation)
	allocation.arg = arg
	allocation.num_bytes = size
	if _, ok := m.allocations[call]; !ok {
		m.allocations[call] = make([]*Allocation, 0)
	}
	m.allocations[call] = append(m.allocations[call], allocation)
}

func (m *MemoryTracker) TrackDependency(arg Arg, start uint64, end uint64, mapping *VirtualMapping) {
	dependency := &MemDependency{
		arg:   arg,
		start: start,
		end:   end,
	}
	mapping.usedBy = append(mapping.usedBy, dependency)
}

func (m *MemoryTracker) FillOutMemory(prog *Prog) (err error) {
	var offset uint64
	if offset, err = m.fillOutPtrArgs(prog); err != nil {
		return
	}

	if offset%PageSize > 0 {
		offset = (offset/PageSize + 1) * PageSize
	}

	if err = m.fillOutMmaps(prog, offset); err != nil {
		return
	}
	return nil
}

func (m *MemoryTracker) fillOutPtrArgs(prog *Prog) (uint64, error) {
	offset := uint64(0)

	for _, call := range prog.Calls {
		if _, ok := m.allocations[call]; !ok {
			continue
		}
		i := 0
		for _, a := range m.allocations[call] {
			switch arg := a.arg.(type) {
			case *PointerArg:
				arg.Address = offset
				offset += a.num_bytes
				i++
				if arg.Address >= memAllocMaxMem {
					return 0, fmt.Errorf("Unable to allocate space to store arg: %#v"+
						"in Call: %v. Required memory is larger than what is allowed by Syzkaller."+
						"Offending address: %d. Skipping seed generation for this prog...\n",
						arg, call, arg.Address)
				}
			default:
				panic("Pointer Arg Failed")
			}
		}
	}

	if offset%PageSize > 0 {
		offset = (offset/PageSize + 1) * PageSize
	}

	return offset, nil
}

func (m *MemoryTracker) fillOutMmaps(prog *Prog, offset uint64) error {
	for _, mapping := range m.mappings {
		for _, dep := range mapping.usedBy {
			switch arg_ := dep.arg.(type) {
			case *PointerArg:
				//Offset should align with the start of a mapping/end of previous mapping.
				arg_.Address = offset + dep.start - mapping.start

				arg_.Res = nil
				if arg_.Address >= memAllocMaxMem || arg_.Address+arg_.VmaSize > memAllocMaxMem {
					return fmt.Errorf("Unable to allocate space for vma Call: %#v "+
						"Required memory is larger than what is allowed by Syzkaller."+
						"Offending address: %d. Skipping seed generation for this prog...\n",
						mapping.GetCall(), arg_.Address)
				}
			default:
				panic("Mapping needs to be Pointer Arg")
			}
		}
		offset += mapping.GetEnd() - mapping.GetStart()
	}
	return nil
}

func (m *MemoryTracker) GetTotalMemoryAllocations(prog *Prog) uint64 {
	sum := uint64(0)
	for _, call := range prog.Calls {
		if _, ok := m.allocations[call]; !ok {
			continue
		}
		for _, a := range m.allocations[call] {
			sum += a.num_bytes
		}
	}
	if sum%PageSize > 0 {
		sum = (sum/PageSize + 1) * PageSize
	}
	return sum
}

func (m *MemoryTracker) GetTotalVMAAllocations(prog *Prog) uint64 {
	sum := uint64(0)
	callMap := make(map[*Call]bool, 0)
	for _, call := range prog.Calls {
		callMap[call] = true
	}

	for _, mapping := range m.mappings {
		if _, ok := callMap[mapping.createdBy]; ok {
			sum += (mapping.end - mapping.start)
		}
	}
	return sum
}
