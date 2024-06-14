package fileupload

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type fileuploadFS struct {
	dir string
}

var _ Uploader = (*fileuploadFS)(nil)

func (fs *fileuploadFS) load(ctx context.Context, filename string) (basename string, modTime time.Time, content io.ReadSeekCloser, err error) {
	f, err := os.Open(filepath.Join(fs.dir, filepath.FromSlash(filename)))
	if err != nil {
		return "", time.Time{}, nil, err
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return "", time.Time{}, nil, err
	} else if fi.IsDir() {
		f.Close()
		return "", time.Time{}, nil, fmt.Errorf("file is a directory")
	}

	basename = filepath.Base(filename)
	if i := strings.IndexByte(basename, '-'); i >= 0 {
		basename = basename[i+1:]
	}

	return basename, fi.ModTime(), f, nil
}

func (fs *fileuploadFS) store(ctx context.Context, r io.Reader, username, mimeType, origBasename string) (out string, err error) {
	var suffix string
	if filepath.Ext(origBasename) == "" && mimeType != "" {
		if ext, ok := primaryExts[mimeType]; ok {
			suffix = "." + ext
		} else if exts, _ := mime.ExtensionsByType(mimeType); len(exts) == 1 {
			suffix = exts[0]
		}
	}

	dir := filepath.Join(fs.dir, username)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create user upload directory: %w", err)
	}

	var f *os.File
	for i := 0; i < 100; i++ {
		tokenLen := 8
		if origBasename != "" && i == 0 {
			tokenLen = 4
		}
		prefix, err := generateToken(tokenLen)
		if err != nil {
			return "", fmt.Errorf("failed to generate file base: %w", err)
		}

		basename := prefix
		if origBasename != "" {
			basename += "-" + origBasename
		}
		basename += suffix

		f, err = os.OpenFile(filepath.Join(dir, basename), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			break
		} else if !os.IsExist(err) {
			return "", fmt.Errorf("failed to open file: %w", err)
		}
	}
	if f == nil {
		return "", fmt.Errorf("failed to pick filename")
	}
	defer f.Close()

	if _, err := io.Copy(f, r); err != nil {
		return "", fmt.Errorf("failed to write file: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("failed to close file: %w", err)
	}

	return url.PathEscape(username) + "/" + url.PathEscape(filepath.Base(f.Name())), nil
}
