// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package fb

import "strconv"

type Version int8

const (
	Versionv0 Version = 0
)

var EnumNamesVersion = map[Version]string{
	Versionv0: "v0",
}

var EnumValuesVersion = map[string]Version{
	"v0": Versionv0,
}

func (v Version) String() string {
	if s, ok := EnumNamesVersion[v]; ok {
		return s
	}
	return "Version(" + strconv.FormatInt(int64(v), 10) + ")"
}