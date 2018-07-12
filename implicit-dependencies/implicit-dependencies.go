package implicit_dependencies

import (
	"io/ioutil"
	. "github.com/shankarapailoor/moonshine/logging"
	"encoding/json"
)

type ImplicitDependencies map[string][]string

func LoadImplicitDependencies(location string) (impl_deps *ImplicitDependencies) {
	json_data, e := ioutil.ReadFile(location)
	if e != nil {
		Failf("Unable to read %s", location)
	}
	if e := json.Unmarshal(json_data, &impl_deps); e != nil {
		Failf("Parse error in implicit_dependencies %s", e.Error())
	}
	return
}