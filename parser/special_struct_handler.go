package parser

import (
	"github.com/google/syzkaller/prog"
	"github.com/shankarapailoor/moonshine/straceTypes"
)

type structHandler func(syzType *prog.StructType, straceType straceTypes.Type, ctx *Context) straceTypes.Type

var SpecialStruct_Map = map[string]structHandler{
	"bpf_framed_program": bpfFramedProgramHandler,
}

func PreprocessStruct(syzType *prog.StructType, straceType straceTypes.Type, ctx *Context) straceTypes.Type {
	if structFunc, ok := SpecialStruct_Map[syzType.Name()]; ok {
		return structFunc(syzType, straceType, ctx)
	}
	return straceType
}

func bpfFramedProgramHandler(syzType *prog.StructType, straceType straceTypes.Type, ctx *Context) straceTypes.Type {
	switch a := straceType.(type) {
	case *straceTypes.ArrayType:
		straceStructArgs := make([]straceTypes.Type, len(syzType.Fields))
		arrType := a
		straceStructArgs[1] = arrType
		straceArg0 := GenDefaultStraceType(syzType.Fields[0])
		straceStructArgs[0] = straceArg0
		straceStructArgs = append(straceStructArgs, GenDefaultStraceType(syzType.Fields[1]))
		return straceTypes.NewStructType(straceStructArgs)
	}
	return straceType
}
