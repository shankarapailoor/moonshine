package config

import (
	"encoding/json"
	"github.com/shankarapailoor/moonshine/logging"
	"io/ioutil"
)

type DistillConfig struct {
	Type             string
	Stats            string `json:"stats"`
	ImplicitDepsFile string `json:"implicit_dependencies"`
}

//Creates config for distillation
func NewDistillConfig(location string) (config *DistillConfig) {
	dat, fileErr := ioutil.ReadFile(location)
	if fileErr != nil {
		logging.Failf("Unable to read distill config, exiting")

	}
	if err := json.Unmarshal(dat, &config); err != nil {
		logging.Failf("Unable to marshall distill config: %s", err.Error())
	}
	return
}
