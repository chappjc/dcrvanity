package main

import "fmt"

type version struct {
	Major, Minor, Patch int
	Label               string
}

var ver = version{
	Major: 0,
	Minor: 1,
	Patch: 2,
	Label: "beta"}

// CommitHash may be set on the build command line:
// go build -ldflags "-X main.CommitHash=`git rev-parse HEAD`"
// var CommitHash string

const appName string = "dcrvanity"

func (v *version) String() string {
	if v.Label != "" {
		return fmt.Sprintf("%d.%d.%d-%s",
			v.Major, v.Minor, v.Patch, v.Label)
	}
	return fmt.Sprintf("%d.%d.%d",
		v.Major, v.Minor, v.Patch)
}
