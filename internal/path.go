package internal

import (
	"io/fs"
	"runtime"
	"strings"
)

func ValidPath(name string) bool {
	if runtime.GOOS != "windows" && strings.Contains(name, "\\") {
		return false
	}

	return fs.ValidPath(name)
}
