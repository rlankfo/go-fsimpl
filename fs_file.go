package fsimpl

import (
	"io/fs"
	"os"
)

type fileFS struct {
	root fs.FS
}

// FileFS returns a file system (an fs.FS) for the tree of files rooted at the
// directory root. This filesystem is suitable for use with the 'file:' URL
// scheme, and interacts with the local filesystem.
//
// This is effectively a wrapper for os.DirFS, however unlike os.DirFS it also
// implements fs.ReadDirFS and fs.ReadFileFS.
func FileFS(root string) fs.FS {
	return &fileFS{root: os.DirFS(root)}
}

var (
	_ fs.FS         = (*fileFS)(nil)
	_ fs.ReadDirFS  = (*fileFS)(nil)
	_ fs.ReadFileFS = (*fileFS)(nil)
	_ fs.StatFS     = (*fileFS)(nil)
	_ fs.GlobFS     = (*fileFS)(nil)
	_ fs.SubFS      = (*fileFS)(nil)
)

func (f *fileFS) Open(name string) (fs.File, error) {
	return f.root.Open(name)
}

func (f *fileFS) ReadFile(name string) ([]byte, error) {
	return fs.ReadFile(f.root, name)
}

func (f *fileFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return fs.ReadDir(f.root, name)
}

func (f *fileFS) Stat(name string) (fs.FileInfo, error) {
	return fs.Stat(f.root, name)
}

func (f *fileFS) Glob(name string) ([]string, error) {
	return fs.Glob(f.root, name)
}

func (f *fileFS) Sub(name string) (fs.FS, error) {
	return fs.Sub(f.root, name)
}
