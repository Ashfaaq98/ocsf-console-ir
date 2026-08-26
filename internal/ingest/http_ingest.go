package ingest

import (
	"github.com/Ashfaaq98/ocsf-console-ir/internal/logging"

	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// HTTPIngestOptions controls the HTTP ingestion server behavior.
type HTTPIngestOptions struct {
	// Bind address, e.g. "127.0.0.1:8081"
	Bind string
	// Token for Authorization: Bearer <token> header. Empty disables auth.
	Token string
	// Dir to write accepted payload files into (watched by folder ingestor)
	Dir string
	// RPS is max requests per second (approximate). 0 disables rate limiting.
	RPS int
	// Burst is the token bucket size. If 0 and RPS>0, defaults to RPS.
	Burst int
	// Logger for minimal logs (optional)
	Logger *logging.Logger
	// MaxBodyBytes caps request body size; defaults to 10 MiB.
	MaxBodyBytes int64
}

// HTTPIngestServer provides POST /ingest for JSON/JSONL payloads written atomically to Dir.
type HTTPIngestServer struct {
	srv     *http.Server
	opts    HTTPIngestOptions
	limiter *simpleLimiter
	logger  *logging.Logger
	started int32

	// stop cancels the run started by Start, so a caller can close the
	// listener without owning the context it was handed. The interface offers
	// this as a toggle, and "restart the application" is not a toggle.
	stop func()
	// addr is where it actually bound, which is not always what was asked for:
	// port 0 means "any free port", and a screen reporting ":0" tells nobody
	// where to send anything.
	addr atomic.Value
	// received counts accepted payloads, so a screen can say the listener is
	// doing something rather than merely being up.
	received int64
}

// NewHTTPIngestServer constructs a new HTTP server for ingestion.
func NewHTTPIngestServer(opts HTTPIngestOptions) (*HTTPIngestServer, error) {
	if opts.Bind == "" {
		opts.Bind = "127.0.0.1:8081"
	}
	if opts.Dir == "" {
		opts.Dir = DefaultDir
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 10 * 1024 * 1024 // 10 MiB
	}

	// VULN-9: Require bearer token when binding to non-localhost addresses
	if opts.Token == "" && !isLocalhostBind(opts.Bind) {
		return nil, fmt.Errorf("http ingest: --http-ingest-token is required when binding to non-localhost address %q", opts.Bind)
	}

	var logger *logging.Logger
	if opts.Logger != nil {
		logger = opts.Logger
	} else {
		logger = nil
	}
	if err := os.MkdirAll(opts.Dir, 0700); err != nil {
		return nil, fmt.Errorf("create ingest dir: %w", err)
	}
	var lim *simpleLimiter
	if opts.RPS > 0 {
		if opts.Burst <= 0 {
			opts.Burst = opts.RPS
		}
		lim = newSimpleLimiter(opts.RPS, opts.Burst)
	}
	his := &HTTPIngestServer{
		opts:    opts,
		limiter: lim,
		logger:  logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ingest", his.handleIngest)

	his.srv = &http.Server{
		Addr:         opts.Bind,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return his, nil
}

// Start starts the HTTP server concurrently and attaches to ctx for shutdown.
func (h *HTTPIngestServer) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&h.started, 0, 1) {
		return errors.New("http ingest server already started")
	}
	// Bind early to surface errors synchronously
	ln, err := net.Listen("tcp", h.opts.Bind)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", h.opts.Bind, err)
	}
	h.addr.Store(ln.Addr().String())
	h.logger.Printf("HTTP ingest listening on http://%s, dir=%s rps=%d burst=%d auth=%v",
		h.Address(), h.opts.Dir, h.opts.RPS, h.opts.Burst, h.opts.Token != "")

	go func() {
		if err := h.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			h.logger.Printf("server error: %v", err)
		}
	}()

	runCtx, cancel := context.WithCancel(ctx)
	h.stop = cancel

	go func() {
		<-runCtx.Done()
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelShutdown()
		if err := h.srv.Shutdown(shutdownCtx); err != nil {
			h.logger.Printf("graceful shutdown failed: %v", err)
		}
		if h.limiter != nil {
			h.limiter.Close()
		}
		atomic.StoreInt32(&h.started, 0)
	}()
	return nil
}

// Stop closes the listener. Safe to call when it is not running.
//
// A payload part-way through being written is finished first: the handler
// renames a complete temporary file into place, so a shutdown either leaves a
// whole file for the watcher or none at all.
func (h *HTTPIngestServer) Stop() {
	if h.stop != nil {
		h.stop()
	}
}

// Listening reports whether the server is accepting requests.
func (h *HTTPIngestServer) Listening() bool { return atomic.LoadInt32(&h.started) == 1 }

// Address is where it listens: the address it bound to once it is running, and
// the one it was asked for before that.
func (h *HTTPIngestServer) Address() string {
	if a, ok := h.addr.Load().(string); ok && a != "" {
		return a
	}
	return h.opts.Bind
}

// HasToken reports whether a bearer token is required.
//
// Worth surfacing rather than inferring: without one, anything that can reach
// the address can write into the analyst's case data.
func (h *HTTPIngestServer) HasToken() bool { return strings.TrimSpace(h.opts.Token) != "" }

// Received is how many payloads have been accepted since the process started.
func (h *HTTPIngestServer) Received() int { return int(atomic.LoadInt64(&h.received)) }

// handleIngest accepts POST /ingest with JSON or JSONL
func (h *HTTPIngestServer) handleIngest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// A loopback bind is not an authentication boundary. Without a token,
	// anything running on this machine can post — including any web page the
	// analyst opens, since a string body makes the request CORS-simple and no
	// preflight is sent. Requiring the browser's own Origin and Host to name
	// this listener rejects cross-site posts and DNS-rebound origins alike.
	// A token makes this unnecessary: the Authorization header forces a
	// preflight no cross-site page can pass.
	if h.opts.Token == "" && !h.originAllowed(r) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	// Basic bearer auth
	if h.opts.Token != "" {
		auth := r.Header.Get("Authorization")
		provided := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		// VULN-3: Use constant-time comparison to prevent timing attacks
		if !strings.HasPrefix(auth, "Bearer ") || subtle.ConstantTimeCompare([]byte(provided), []byte(h.opts.Token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="console-ir"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	// Rate limit
	if h.limiter != nil {
		// short wait using request context
		if err := h.limiter.Wait(r.Context()); err != nil {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
	}
	// Cap body size
	r.Body = http.MaxBytesReader(w, r.Body, h.opts.MaxBodyBytes)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	// Detect format
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	format := ""
	if strings.Contains(ct, "ndjson") || strings.Contains(ct, "jsonl") {
		format = "jsonl"
	} else if strings.Contains(ct, "application/json") || strings.Contains(ct, "json") {
		format = "json"
	} else {
		// Heuristic
		trim := bytes.TrimSpace(body)
		if len(trim) > 0 && (trim[0] == '{' || trim[0] == '[') {
			format = "json"
		} else if bytes.Contains(body, []byte("\n")) {
			format = "jsonl"
		} else {
			// default to json, will validate soon
			format = "json"
		}
	}
	// Validate
	switch format {
	case "jsonl":
		if err := validateJSONL(body); err != nil {
			http.Error(w, "invalid JSONL: "+err.Error(), http.StatusBadRequest)
			return
		}
	case "json":
		if err := validateJSON(body); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "unsupported format", http.StatusBadRequest)
		return
	}
	// Write atomically
	ack := uuid.New().String()
	ts := time.Now().UTC().Format("20060102T150405Z")
	ext := ".json"
	if format == "jsonl" {
		ext = ".jsonl"
	}
	finalName := fmt.Sprintf("%s-%s%s", ts, ack, ext)
	finalPath := filepath.Join(h.opts.Dir, finalName)
	tmpFile, err := os.CreateTemp(h.opts.Dir, finalName+".tmp-*")
	if err != nil {
		http.Error(w, "failed to create temp file", http.StatusInternalServerError)
		return
	}
	tmpPath := tmpFile.Name()
	// write
	if _, err := tmpFile.Write(body); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		http.Error(w, "failed to write file", http.StatusInternalServerError)
		return
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		http.Error(w, "failed to sync file", http.StatusInternalServerError)
		return
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		http.Error(w, "failed to close file", http.StatusInternalServerError)
		return
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		os.Remove(tmpPath)
		http.Error(w, "failed to commit file", http.StatusInternalServerError)
		return
	}
	// Respond
	atomic.AddInt64(&h.received, 1)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"ack":"%s"}`, ack)))
	// Log request
	h.logger.Printf("accepted ack=%s bytes=%d ct=%q path=%s remote=%s dur=%s",
		ack, len(body), ct, finalName, remoteIP(r.RemoteAddr), time.Since(start).String())
}

func validateJSON(body []byte) error {
	if !json.Valid(body) {
		return errors.New("not valid json")
	}
	// ensure starts with { or [
	trim := bytes.TrimSpace(body)
	if len(trim) == 0 {
		return errors.New("empty")
	}
	if trim[0] != '{' && trim[0] != '[' {
		return errors.New("expected object or array")
	}
	// Deliberately no json.Unmarshal here. json.Valid above already proved the
	// body well-formed, so decoding it into an interface{} adds no validation —
	// but it does materialise the whole body as a live object tree, which for a
	// wide, shallow body costs roughly twenty times its size in heap that the
	// collector cannot reclaim while the decode is running. With the default
	// burst of 20 those decodes stack, and a few megabytes of request can turn
	// into gigabytes of live heap. The parser reads the file again anyway.
	return nil
}

func validateJSONL(body []byte) error {
	// iterate lines
	scanner := bufio.NewScanner(bytes.NewReader(body))
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)
	lineNum := 0
	nonEmpty := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		nonEmpty++
		if !json.Valid([]byte(line)) {
			return fmt.Errorf("line %d invalid json", lineNum)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if nonEmpty == 0 {
		return errors.New("no non-empty lines")
	}
	return nil
}

// simpleLimiter is a minimal token bucket limiter
type simpleLimiter struct {
	tokens chan struct{}
	stop   chan struct{}
}

func newSimpleLimiter(rps, burst int) *simpleLimiter {
	if rps <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = rps
	}
	l := &simpleLimiter{
		tokens: make(chan struct{}, burst),
		stop:   make(chan struct{}),
	}
	// initially fill bucket
	for i := 0; i < burst; i++ {
		l.tokens <- struct{}{}
	}
	// refill goroutine
	go func() {
		// ticker rate: 1 token every 1/rps second
		interval := time.Second / time.Duration(rps)
		if interval <= 0 {
			interval = time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				select {
				case l.tokens <- struct{}{}:
				default:
					// bucket full
				}
			case <-l.stop:
				return
			}
		}
	}()
	return l
}

func (l *simpleLimiter) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.stop:
		return errors.New("limiter stopped")
	case <-l.tokens:
		return nil
	}
}

func (l *simpleLimiter) Close() {
	if l == nil {
		return
	}
	close(l.stop)
}

// remoteIP extracts ip from host:port
func remoteIP(addr string) string {
	if i := strings.LastIndex(addr, ":"); i != -1 {
		return addr[:i]
	}
	return addr
}

// originAllowed reports whether a request may post while no token is set.
//
// Browsers attach Origin to every cross-origin POST and to same-origin POSTs
// alike, so requiring it to name this listener blocks a page on any other site
// from writing into the analyst's cases. A DNS-rebound page carries its own
// public name in Origin and Host, so it is refused on both. A sandboxed or
// file:// document sends "null", which matches nothing.
//
// Non-browser senders — a forwarder, curl, the tool's own tests — send no
// Origin at all and are unaffected. Their Host still has to name the listener,
// which is what it naturally is when they post to the address they were given.
func (h *HTTPIngestServer) originAllowed(r *http.Request) bool {
	_, port, err := net.SplitHostPort(h.Address())
	if err != nil {
		return false
	}
	allowed := map[string]bool{
		net.JoinHostPort("127.0.0.1", port): true,
		net.JoinHostPort("localhost", port): true,
		net.JoinHostPort("::1", port):       true,
	}
	if o := strings.TrimSpace(r.Header.Get("Origin")); o != "" {
		u, err := url.Parse(o)
		if err != nil || !allowed[u.Host] {
			return false
		}
	}
	// HTTP/1.0 senders may omit Host entirely; they cannot be a browser.
	return r.Host == "" || allowed[r.Host]
}

// isLocalhostBind reports whether the bind address reaches only this machine.
//
// A host-less bind is deliberately not loopback. net.Listen("tcp", ":8081")
// listens on every unicast and anycast address of the host, exactly as
// "0.0.0.0:8081" does — it is the shorter spelling of the same thing, not a
// safer one. Treating it as loopback let the token requirement be skipped for
// the most idiomatic way to write a wildcard bind, so the analyst who typed
// the short form got an unauthenticated receiver on every interface while the
// documentation and the settings screen both promised a token was required.
//
// An empty string cannot reach here: the constructor rewrites an empty Bind to
// the loopback default before the guard runs.
func isLocalhostBind(bind string) bool {
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		host = bind
	}
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}
