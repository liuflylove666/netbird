package downloads

import (
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
)

// EnvClientDownloadsDir is the filesystem directory whose contents are served at /downloads/.
const EnvClientDownloadsDir = "NB_CLIENT_DOWNLOADS_DIR"

// onlyFilesFS hides directory listings (returns 404 for directories).
type onlyFilesFS struct {
	root http.FileSystem
}

func (fs onlyFilesFS) Open(name string) (http.File, error) {
	f, err := fs.root.Open(name)
	if err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if stat.IsDir() {
		_ = f.Close()
		return nil, os.ErrNotExist
	}
	return f, nil
}

// Register mounts GET/HEAD /downloads/ when NB_CLIENT_DOWNLOADS_DIR is set.
func Register(root *mux.Router, corsMiddleware *cors.Cors) {
	dir := strings.TrimSpace(os.Getenv(EnvClientDownloadsDir))
	if dir == "" {
		return
	}

	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		log.Warnf("%s is not a readable directory (%q): %v", EnvClientDownloadsDir, dir, err)
		return
	}

	fs := onlyFilesFS{root: http.Dir(dir)}
	fileServer := http.StripPrefix("/downloads/", http.FileServer(fs))
	// Large installers: allow browser and reverse proxies to cache. Go's FileServer
	// still sends Last-Modified / ETag so clients can revalidate after max-age.
	// Paths stay fixed (e.g. ios/netbird.ipa); bump cache bust by replacing the file
	// or use a CDN query string if you need instant worldwide invalidation.
	handler := cacheableDownloadsHandler(fileServer)
	root.PathPrefix("/downloads/").Handler(corsMiddleware.Handler(handler))
	log.Infof("client downloads static server enabled at /downloads/ from %s", dir)
}

func cacheableDownloadsHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		p := strings.ToLower(r.URL.Path)
		switch {
		case strings.HasSuffix(p, ".ipa"), strings.HasSuffix(p, ".apk"):
			w.Header().Set("Cache-Control", "public, max-age=86400")
		case strings.HasSuffix(p, ".pkg"), strings.HasSuffix(p, ".msi"),
			strings.HasSuffix(p, ".exe"), strings.HasSuffix(p, ".deb"):
			w.Header().Set("Cache-Control", "public, max-age=86400")
		}
		next.ServeHTTP(w, r)
	})
}
