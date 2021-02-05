package utils

import (
	"fmt"
	"strings"
)

// Version identifies the module version
type Version struct {
	major int
	minor int
	patch int
}

// GetVersion returns the string representing the code version
func (v *Version) GetVersion(state string) string {
	vers := []string{fmt.Sprint(v.major), fmt.Sprint(v.minor), fmt.Sprint(v.patch)}
	if state == "dev" || state == "test" {
		return "v" + strings.Join(vers, ".") + " - " + state
	}
	return "v" + strings.Join(vers, ".")
}

// NewVersion creates a new instance of the version object
func NewVersion(major int, minor int, patch int) *Version {
	return &Version{
		major: major,
		minor: minor,
		patch: patch,
	}
}
