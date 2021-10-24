package awssmfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/hairyhenderson/go-fsimpl"
	"github.com/hairyhenderson/go-fsimpl/internal"
)

// withSMClienter is an fs.FS that can be configured to use the given Secrets
// Manager client.
type withSMClienter interface {
	WithSMClient(smclient SecretsManagerClient) fs.FS
}

// WithSMClientFS injects a Secrets Manager client into the filesystem fs, if\
// the filesystem supports it (i.e. has a WithSMClient method). This can be used
// for configuring specialized client options. Note that this should not be used
// at the same time as WithHTTPClient. If you wish only to configure the HTTP
// client, use WithHTTPClient alone.
func WithSMClientFS(smclient SecretsManagerClient, fsys fs.FS) fs.FS {
	if fsys, ok := fsys.(withSMClienter); ok {
		return fsys.WithSMClient(smclient)
	}

	return fsys
}

type awssmFS struct {
	ctx        context.Context
	base       *url.URL
	httpclient *http.Client
	smclient   SecretsManagerClient
	root       string
}

// New provides a filesystem (an fs.FS) backed by the AWS Secrets Manager,
// rooted at the given URL. Note that the URL may be either a regular
// hierarchical URL (like "aws+sm:///foo/bar") or an opaque URI (like
// "aws+sm:foo/bar"), depending on how secrets are organized in Secrets Manager.
//
// A context can be given by using WithContextFS.
func New(u *url.URL) (fs.FS, error) {
	if u.Scheme != "aws+sm" {
		return nil, fmt.Errorf("invalid URL scheme %q", u.Scheme)
	}

	root := u.Path
	if root == "" {
		root = u.Opaque
	}

	return &awssmFS{
		ctx:        context.Background(),
		base:       u,
		root:       root,
		httpclient: http.DefaultClient,
	}, nil
}

// FS is used to register this filesystem with an fsimpl.FSMux
//
//nolint:gochecknoglobals
var FS = fsimpl.FSProviderFunc(New, "aws+sm")

var (
	_ fs.FS                     = (*awssmFS)(nil)
	_ fs.ReadFileFS             = (*awssmFS)(nil)
	_ fs.ReadDirFS              = (*awssmFS)(nil)
	_ fs.SubFS                  = (*awssmFS)(nil)
	_ internal.WithContexter    = (*awssmFS)(nil)
	_ internal.WithHTTPClienter = (*awssmFS)(nil)
	_ withSMClienter            = (*awssmFS)(nil)
)

func (f awssmFS) WithContext(ctx context.Context) fs.FS {
	fsys := f
	fsys.ctx = ctx

	return &fsys
}

func (f awssmFS) WithHTTPClient(client *http.Client) fs.FS {
	fsys := f
	fsys.httpclient = client

	return &fsys
}

func (f awssmFS) WithSMClient(smclient SecretsManagerClient) fs.FS {
	fsys := f
	fsys.smclient = smclient

	return &fsys
}

func (f *awssmFS) getClient(ctx context.Context) (SecretsManagerClient, error) {
	if f.smclient != nil {
		return f.smclient, nil
	}

	opts := [](func(*config.LoadOptions) error){}
	if f.httpclient != nil {
		opts = append(opts, config.WithHTTPClient(f.httpclient))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}

	f.smclient = secretsmanager.NewFromConfig(cfg)

	return f.smclient, nil
}

func (f *awssmFS) Sub(name string) (fs.FS, error) {
	if !internal.ValidPath(name) {
		return nil, &fs.PathError{Op: "sub", Path: name, Err: fs.ErrInvalid}
	}

	if name == "." || name == "" {
		return f, nil
	}

	fsys := *f
	fsys.root = path.Join(fsys.root, name)

	return &fsys, nil
}

func (f *awssmFS) Open(name string) (fs.File, error) {
	if !internal.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}

	smclient, err := f.getClient(f.ctx)
	if err != nil {
		return nil, err
	}

	file := &awssmFile{
		ctx:    f.ctx,
		name:   strings.TrimPrefix(path.Base(name), "."),
		root:   strings.TrimPrefix(path.Join(f.root, path.Dir(name)), "."),
		client: smclient,
	}

	if name == "." {
		file.fi = internal.DirInfo(file.name, time.Time{})

		return file, nil
	}

	return file, nil
}

func (f *awssmFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if !internal.ValidPath(name) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}

	smclient, err := f.getClient(f.ctx)
	if err != nil {
		return nil, err
	}

	dir := &awssmFile{
		ctx:    f.ctx,
		name:   name,
		root:   f.root,
		client: smclient,
		fi:     internal.DirInfo(name, time.Time{}),
	}

	children, err := dir.list()
	if err != nil {
		return nil, &fs.PathError{Op: "readDir", Path: name, Err: err}
	}

	dir.children = children

	return dir.ReadDir(-1)
}

// ReadFile implements fs.ReadFileFS.
//
// This implementation is slightly more performant than calling Open and then
// reading the resulting fs.File.
func (f *awssmFS) ReadFile(name string) ([]byte, error) {
	if !internal.ValidPath(name) {
		return nil, &fs.PathError{Op: "readFile", Path: name, Err: fs.ErrInvalid}
	}

	smclient, err := f.getClient(f.ctx)
	if err != nil {
		return nil, err
	}

	secret, err := smclient.GetSecretValue(f.ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(path.Join(f.root, name)),
	})
	if err != nil {
		return nil, &fs.PathError{Op: "readFile", Path: name, Err: convertAWSError(err)}
	}

	if secret.SecretString != nil {
		return []byte(*secret.SecretString), nil
	}

	return secret.SecretBinary, nil
}

type awssmFile struct {
	ctx    context.Context
	fi     fs.FileInfo
	client SecretsManagerClient
	body   io.Reader
	name   string
	root   string

	children []fs.FileInfo
	diroff   int
}

var _ fs.ReadDirFile = (*awssmFile)(nil)

func (f *awssmFile) Close() error {
	// no-op - no state is kept
	return nil
}

func (f *awssmFile) Read(p []byte) (int, error) {
	if f.body == nil {
		err := f.request(f.ctx)
		if err != nil {
			return 0, &fs.PathError{Op: "read", Path: f.name, Err: err}
		}
	}

	return f.body.Read(p)
}

func (f *awssmFile) Stat() (fs.FileInfo, error) {
	if f.fi != nil {
		return f.fi, nil
	}

	err := f.request(f.ctx)
	if err == nil {
		return f.fi, nil
	}

	if !errors.Is(err, fs.ErrNotExist) {
		return nil, &fs.PathError{Op: "stat", Path: f.name, Err: err}
	}

	// may be a directory
	dir, err := f.asDir()
	if err != nil {
		return nil, &fs.PathError{Op: "stat", Path: f.name, Err: err}
	}

	return dir.Stat()
}

// convertAWSError converts an AWS error to an error suitable for returning
// from the package. We don't want to leak SDK error types.
func convertAWSError(err error) error {
	// We can't find the resource that you asked for.
	var rnfErr *smtypes.ResourceNotFoundException
	if errors.As(err, &rnfErr) {
		return fmt.Errorf("%w: %s", fs.ErrNotExist, rnfErr.ErrorMessage())
	}

	// Secrets Manager can't decrypt the protected secret text using the provided KMS key.
	var dcErr *smtypes.DecryptionFailure
	if errors.As(err, &dcErr) {
		return fmt.Errorf("%w: %s: %s", fs.ErrPermission, dcErr.ErrorCode(), dcErr.ErrorMessage())
	}

	// An error occurred on the server side.
	var internalErr *smtypes.InternalServiceError
	if errors.As(err, &internalErr) {
		return fmt.Errorf("internal error: %s: %s", internalErr.ErrorCode(), internalErr.ErrorMessage())
	}

	// You provided an invalid value for a parameter.
	var paramErr *smtypes.InvalidParameterException
	if errors.As(err, &paramErr) {
		return fmt.Errorf("%w: %s", fs.ErrInvalid, paramErr.ErrorMessage())
	}

	// You provided a parameter value that is not valid for the current state of the resource.
	var reqErr *smtypes.InvalidRequestException
	if errors.As(err, &reqErr) {
		return fmt.Errorf("%w: %s", fs.ErrInvalid, reqErr.ErrorMessage())
	}

	return err
}

// request the secret from AWS Secrets Manager and populate body and fi.
// SDK errors will not be leaked, instead they will be converted to more
// general errors.
func (f *awssmFile) request(ctx context.Context) error {
	fullPath := path.Join(f.root, f.name)

	secret, err := f.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &fullPath,
	})
	if err != nil {
		return fmt.Errorf("getSecretValue: %w", convertAWSError(err))
	}

	body := secret.SecretBinary

	// May be a string
	if secret.SecretString != nil {
		body = []byte(*secret.SecretString)
	}

	seclen := int64(len(body))
	f.body = bytes.NewReader(body)

	// secret versions are immutable, so the created date for this version
	// is also the last modified date
	modTime := secret.CreatedDate
	if modTime == nil {
		modTime = &time.Time{}
	}

	// populate fi
	f.fi = internal.FileInfo(f.name, seclen, 0o644, *modTime, "")

	return nil
}

func (f *awssmFile) asDir() (*awssmFile, error) {
	// prefix filters must end in /
	prefix := path.Join(f.root, f.name) + "/"

	filters := []smtypes.Filter{{Key: "name", Values: []string{prefix}}}
	// handle opaque scheme (i.e. secret names that start without a /)
	if prefix == "./" {
		filters = nil
	}

	// just list one - if it's found, we have a dir
	secrets, err := f.client.ListSecrets(f.ctx, &secretsmanager.ListSecretsInput{
		MaxResults: 1, Filters: filters,
	})
	if err != nil {
		return nil, convertAWSError(err)
	}

	if len(secrets.SecretList) == 0 {
		return nil, fs.ErrNotExist
	}

	f.fi = internal.DirInfo(f.name, time.Time{})

	return f, nil
}

// list returns a sorted list of the children of this directory
func (f *awssmFile) list() ([]fs.FileInfo, error) {
	// prefix filters must end in /
	prefix := path.Join(f.root, f.name) + "/"
	if prefix == "//" {
		prefix = "/"
	}

	if prefix == "./" {
		prefix = ""
	}

	filters := []smtypes.Filter{{Key: "name", Values: []string{prefix}}}
	// handle opaque scheme (i.e. secret names that start without a /)
	if prefix == "" {
		filters = []smtypes.Filter{{Key: "name", Values: []string{"!/"}}}
	}

	secrets, err := f.client.ListSecrets(f.ctx, &secretsmanager.ListSecretsInput{
		MaxResults: 100, // 100 max results is the AWS limit - remove once pagination is implemented
		Filters:    filters,
	})
	if err != nil {
		return nil, fmt.Errorf("listSecrets: %w", err)
	}

	if secrets.NextToken != nil {
		// TODO: support pagination!
		return nil, fmt.Errorf("listSecrets: more results are available, but pagination is not supported")
	}

	// no such thing as empty directories in SM, they're artificial
	if len(secrets.SecretList) == 0 {
		return nil, fmt.Errorf("%w (or empty): %q", fs.ErrNotExist, prefix)
	}

	children := []fs.FileInfo{}

	seen := map[string]bool{}

	for _, entry := range secrets.SecretList {
		name := strings.TrimPrefix(*entry.Name, prefix)
		if prefix != "/" {
			name = strings.TrimPrefix(name, "/")
		}

		parts := strings.SplitN(name, "/", 2)
		name = parts[0]

		if _, ok := seen[name]; ok {
			continue
		}

		seen[name] = true

		if len(parts) > 1 {
			// given that directories are artificial, they have a zero time
			children = append(children, internal.DirInfo(name, time.Time{}))
		} else {
			child := &awssmFile{
				ctx:    f.ctx,
				root:   path.Join(f.root, f.name),
				name:   name,
				client: f.client,
			}
			fi, err := child.Stat()
			if err != nil {
				return nil, err
			}

			children = append(children, fi)
		}
	}

	sort.Slice(children, func(i, j int) bool {
		return children[i].Name() < children[j].Name()
	})

	return children, nil
}

// If n > 0, ReadDir returns at most n DirEntry structures.
// In this case, if ReadDir returns an empty slice, it will return
// a non-nil error explaining why.
// At the end of a directory, the error is io.EOF.
//
// If n <= 0, ReadDir returns all the DirEntry values from the directory
// in a single slice. In this case, if ReadDir succeeds (reads all the way
// to the end of the directory), it returns the slice and a nil error.
// If it encounters an error before the end of the directory,
// ReadDir returns the DirEntry list read until that point and a non-nil error.
func (f *awssmFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if f.children == nil {
		children, err := f.list()
		if err != nil {
			return nil, fmt.Errorf("list: %w", err)
		}

		f.children = children
	}

	if n > 0 && f.diroff >= len(f.children) {
		return nil, io.EOF
	}

	low := f.diroff
	high := f.diroff + n

	// clamp high at the max, and ensure it's higher than low
	if high >= len(f.children) || high <= low {
		high = len(f.children)
	}

	entries := dirents(f.children[low:high])

	f.diroff = high

	return entries, nil
}

func dirents(children []fs.FileInfo) []fs.DirEntry {
	entries := make([]fs.DirEntry, len(children))

	for i, fi := range children {
		switch de := fi.(type) {
		case fs.DirEntry:
			entries[i] = de
		default:
			entries[i] = &fileinfoDirEntry{fi}
		}
	}

	return entries
}

// a wrapper to make a fs.FileInfo into an fs.DirEntry
type fileinfoDirEntry struct {
	fs.FileInfo
}

var _ fs.DirEntry = (*fileinfoDirEntry)(nil)

func (fi *fileinfoDirEntry) Info() (fs.FileInfo, error) { return fi, nil }
func (fi *fileinfoDirEntry) Type() fs.FileMode          { return fi.Mode().Type() }
