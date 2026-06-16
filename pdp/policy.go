package main

import (
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	Name      string `yaml:"name"`
	Subject   string `yaml:"subject"`
	Resource  string `yaml:"resource"`
	Action    string `yaml:"action"`
	Condition string `yaml:"condition"`
	Effect    string `yaml:"effect"`
	Priority  int    `yaml:"priority"`
}

type PolicyFile struct {
	Policies []Policy `yaml:"policies"`
}

func loadPolicies(path string) ([]Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, err
	}

	sort.Slice(pf.Policies, func(i, j int) bool {
		return pf.Policies[i].Priority < pf.Policies[j].Priority
	})

	return pf.Policies, nil
}

func matchField(policyField, requestField string) bool {
	return policyField == "" || policyField == "*" || policyField == requestField
}
