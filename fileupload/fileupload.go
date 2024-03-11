package fileupload

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"git.sr.ht/~emersion/soju/auth"
	"git.sr.ht/~emersion/soju/database"
)

const maxSize = 50 * 1024 * 1024 // 50 MiB

// inlineMIMETypes contains MIME types which are allowed to be displayed inline
// by the Web browser. This has security implications: we don't want the
// browser to execute any kind of script. For instance, SVG images are
// intentionally omitted.
var inlineMIMETypes = map[string]bool{
	"audio/aac":  true,
	"audio/mp4":  true,
	"audio/mpeg": true,
	"audio/ogg":  true,
	"audio/webm": true,
	"image/apng": true,
	"image/gif":  true,
	"image/jpeg": true,
	"image/png":  true,
	"image/webp": true,
	"text/plain": true,
	"video/mp4":  true,
	"video/ogg":  true,
	"video/webm": true,
}

// Some MIME types have multiple possible extensions, and
// mime.ExtensionsByType returns them out-of-order. We have to hardcode
// a few MIME types to work around this unfortunately (e.g. to not use
// ".jfif" for "image/jpeg").
//
// Note, this is not for registering new MIME types (use mime.AddExtensionType
// for that purpose).
var primaryExts = map[string]string{
	"audio/aac":  "aac",
	"audio/mp4":  "mp4",
	"audio/mpeg": "mp3",
	"audio/ogg":  "oga",
	"image/jpeg": "jpeg",
	"text/plain": "txt",
	"video/mp4":  "mp4",
}

type Uploader interface {
	load(filename string) (basename string, modTime time.Time, content io.ReadSeekCloser, err error)
	store(r io.Reader, username, mimeType, basename string) (outFilename string, err error)
}

func New(driver, source string) (Uploader, error) {
	switch driver {
	case "fs":
		return &fs{source}, nil
	default:
		return nil, fmt.Errorf("unknown file upload driver %q", driver)
	}
}

type Handler struct {
	Uploader    Uploader
	Auth        auth.Authenticator
	DB          database.Database
	HTTPOrigins []string
}

func (h *Handler) checkOrigin(reqOrigin string) bool {
	for _, origin := range h.HTTPOrigins {
		match, err := path.Match(origin, reqOrigin)
		if err != nil {
			panic(err) // patterns are checked at config load time
		} else if match {
			return true
		}
	}
	return false
}

func (h *Handler) setCORS(resp http.ResponseWriter, req *http.Request) error {
	resp.Header().Set("Access-Control-Allow-Credentials", "true")
	resp.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Content-Disposition")
	resp.Header().Set("Access-Control-Expose-Headers", "Location, Content-Disposition")

	reqOrigin := req.Header.Get("Origin")
	if reqOrigin == "" {
		return nil
	}
	u, err := url.Parse(reqOrigin)
	if err != nil {
		return fmt.Errorf("invalid Origin header field: %v", err)
	}

	if !strings.EqualFold(u.Host, req.Host) && !h.checkOrigin(reqOrigin) {
		return fmt.Errorf("unauthorized Origin")
	}

	resp.Header().Set("Access-Control-Allow-Origin", reqOrigin)
	resp.Header().Set("Vary", "Origin")
	return nil
}

func (h *Handler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; script-src 'none';")

	if err := h.setCORS(resp, req); err != nil {
		http.Error(resp, err.Error(), http.StatusForbidden)
		return
	}

	if h.Uploader == nil {
		http.NotFound(resp, req)
		return
	}

	switch req.Method {
	case http.MethodOptions:
		resp.WriteHeader(http.StatusNoContent)
	case http.MethodHead, http.MethodGet:
		h.fetch(resp, req)
	case http.MethodPost:
		h.store(resp, req)
	default:
		http.Error(resp, "only OPTIONS, HEAD, GET and POST are allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) fetch(resp http.ResponseWriter, req *http.Request) {
	prefix := "/uploads/"
	if !strings.HasPrefix(req.URL.Path, prefix) {
		http.Error(resp, "invalid path", http.StatusNotFound)
		return
	}

	filename := strings.TrimPrefix(req.URL.Path, prefix)
	filename = path.Join("/", filename)[1:] // prevent directory traversal
	if filename == "" {
		http.Error(resp, "invalid path", http.StatusNotFound)
		return
	}

	basename, modTime, content, err := h.Uploader.load(filename)
	if err != nil {
		http.Error(resp, "failed to open file", http.StatusNotFound)
		return
	}
	defer content.Close()

	// Guess MIME type from extension, then from content
	contentType := mime.TypeByExtension(path.Ext(basename))
	if contentType == "" {
		var buf [512]byte
		n, _ := io.ReadFull(content, buf[:])
		contentType = http.DetectContentType(buf[:n])
		_, err := content.Seek(0, io.SeekStart) // rewind to output whole file
		if err != nil {
			http.Error(resp, "failed to seek file", http.StatusInternalServerError)
			return
		}
	}

	if contentType != "" {
		resp.Header().Set("Content-Type", contentType)
	}

	contentDispMode := "attachment"
	mimeType, _, _ := mime.ParseMediaType(contentType)
	if inlineMIMETypes[mimeType] {
		contentDispMode = "inline"
	}
	contentDisp := mime.FormatMediaType(contentDispMode, map[string]string{
		"filename": basename,
	})
	resp.Header().Set("Content-Disposition", contentDisp)

	http.ServeContent(resp, req, basename, modTime, content)
}

func (h *Handler) store(resp http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/uploads" {
		http.Error(resp, "invalid path", http.StatusNotFound)
		return
	}

	authz := req.Header.Get("Authorization")
	if authz == "" {
		http.Error(resp, "missing Authorization header", http.StatusUnauthorized)
		return
	}

	var (
		username string
		err      error
	)
	scheme, param, _ := strings.Cut(authz, " ")
	switch strings.ToLower(scheme) {
	case "basic":
		plainAuth, ok := h.Auth.(auth.PlainAuthenticator)
		if !ok {
			http.Error(resp, "Basic scheme in Authorization header not supported", http.StatusBadRequest)
			return
		}
		var password string
		username, password, ok = req.BasicAuth()
		if !ok {
			http.Error(resp, "invalid Authorization header", http.StatusBadRequest)
			return
		}
		err = plainAuth.AuthPlain(req.Context(), h.DB, username, password)
	case "bearer":
		oauthAuth, ok := h.Auth.(auth.OAuthBearerAuthenticator)
		if !ok {
			http.Error(resp, "Bearer scheme in Authorization header not supported", http.StatusBadRequest)
			return
		}
		username, err = oauthAuth.AuthOAuthBearer(req.Context(), h.DB, param)
	default:
		http.Error(resp, "unsupported Authorization header scheme", http.StatusBadRequest)
		return
	}
	if err != nil {
		var msg string
		if authErr, ok := err.(*auth.Error); ok {
			msg = authErr.ExternalMsg
		} else {
			msg = "authentication failed"
		}
		http.Error(resp, msg, http.StatusForbidden)
		return
	}

	var mimeType string
	if contentType := req.Header.Get("Content-Type"); contentType != "" {
		var (
			params map[string]string
			err    error
		)
		mimeType, params, err = mime.ParseMediaType(contentType)
		if err != nil {
			http.Error(resp, "failed to parse Content-Type", http.StatusBadRequest)
			return
		}
		if mimeType == "application/octet-stream" {
			mimeType = ""
		}

		switch strings.ToLower(params["charset"]) {
		case "", "utf-8", "us-ascii":
			// OK
		default:
			http.Error(resp, "unsupported charset", http.StatusUnsupportedMediaType)
			return
		}
	}

	var basename string
	if contentDisp := req.Header.Get("Content-Disposition"); contentDisp != "" {
		_, params, err := mime.ParseMediaType(contentDisp)
		if err != nil {
			http.Error(resp, "failed to parse Content-Disposition", http.StatusBadRequest)
			return
		}
		basename = path.Base(params["filename"])
	}

	r := &limitedReader{r: req.Body, n: maxSize}
	outFilename, err := h.Uploader.store(r, username, mimeType, basename)
	if err != nil {
		http.Error(resp, "failed to write file", http.StatusInternalServerError)
		return
	}

	resp.Header().Set("Location", "/uploads/"+outFilename)
	resp.WriteHeader(http.StatusCreated)
}

type limitedReader struct {
	r io.Reader
	n int64
}

func (lr *limitedReader) Read(p []byte) (n int, err error) {
	if lr.n <= 0 {
		return 0, fmt.Errorf("file too large")
	}
	if int64(len(p)) > lr.n {
		p = p[0:lr.n]
	}
	n, err = lr.r.Read(p)
	lr.n -= int64(n)
	return n, err
}

func generateToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
