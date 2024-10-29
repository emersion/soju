package fileupload

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"
)

type fileuploadHTTP struct {
	url string
}

var _ Uploader = (*fileuploadHTTP)(nil)

func (fs *fileuploadHTTP) load(ctx context.Context, filename string) (basename string, modTime time.Time, content io.ReadSeekCloser, err error) {
	// TODO: perhaps proxy requests to the http backend
	return "", time.Time{}, nil, errors.New("fetching files is not supported for the file-upload http backend")
}

func (fs *fileuploadHTTP) store(ctx context.Context, r io.Reader, username, mimeType, origBasename string) (out string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fs.url, r)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "soju")
	if origBasename != "" {
		req.Header.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": origBasename}))
	}
	if mimeType != "" {
		req.Header.Set("Content-Type", mimeType)
	}
	req.Header.Set("Soju-Username", username)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	if res.StatusCode >= 400 && res.StatusCode < 600 {
		return "", &httpError{
			Code:        res.StatusCode,
			ContentType: res.Header.Get("Content-Type"),
			Body:        res.Body,
		}
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("unexpected response code: %v", res.StatusCode)
	}
	out = res.Header.Get("Location")
	if out == "" {
		return "", fmt.Errorf("no location found")
	}
	return out, nil
}
