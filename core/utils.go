package core

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"reflect"
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

// UpdateVersion TODO: Implement a method to update the integer values from a string
func (v *Version) UpdateVersion(strver string) error {
	// TODO: check the string for 3 parts with "." separator
	// TODO: convert each string part into integer
	// TODO: update the version properties major, minor and patch with respective integers
	return nil
}

// NewVersion creates a new instance of the version object
func NewVersion(major int, minor int, patch int) *Version {
	return &Version{
		major: major,
		minor: minor,
		patch: patch,
	}
}

// GetSize is a utility tool to compute aprox size of customer struct types
// [source](https://stackoverflow.com/questions/51431933/how-to-get-size-of-struct-containing-data-structures-in-go)
func GetSize(v interface{}) int {
	size := int(reflect.TypeOf(v).Size())
	switch reflect.TypeOf(v).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(v)
		for i := 0; i < s.Len(); i++ {
			size += GetSize(s.Index(i).Interface())
		}
	case reflect.Map:
		s := reflect.ValueOf(v)
		keys := s.MapKeys()
		size += int(float64(len(keys)) * 10.79) // approximation from https://golang.org/src/runtime/hashmap.go
		for i := range keys {
			size += GetSize(keys[i].Interface()) + GetSize(s.MapIndex(keys[i]).Interface())
		}
	case reflect.String:
		size += reflect.ValueOf(v).Len()
	case reflect.Struct:
		s := reflect.ValueOf(v)
		for i := 0; i < s.NumField(); i++ {
			if s.Field(i).CanInterface() {
				size += GetSize(s.Field(i).Interface())
			}
		}
	}
	return size
}

// Generate a new token ID
func genTID(realm string) string {

	newS := realm
	// ns is generated at package initiation time
	r2 := rand.New(ns)
	src := []byte(newS + fmt.Sprintf("%d", *r2))
	dst := make([]byte, hex.EncodedLen(len(src)))
	_ = hex.Encode(dst, src)
	return string(dst)
}
