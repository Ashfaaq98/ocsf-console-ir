package ingest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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
	Logger *log.Logger
	// MaxBodyBytes caps request body size; defaults to 10 MiB.
	MaxBodyBytes int64
}

// HTTPIngestServer provides POST /ingest for JSON/JSONL payloads written atomically to Dir.
type HTTPIngestServer struct {
	srv     *http.Server
	opts    HTTPIngestOptions
	limiter *simpleLimiter
	logger  *log.Logger
	started int32
}

// NewHTTPIngestServer constructs a new HTTP server for ingestion.
func NewHTTPIngestServer(opts HTTPIngestOptions) (*HTTPIngestServer, error) {
	if opts.Bind == "" {
		opts.Bind = "127.0.0.1:8081"
	}
	if opts.Dir == "" {
		opts.Dir = "data/incoming"
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 10 * 1024 * 1024 // 10 MiB
	}
	var logger *log.Logger
	if opts.Logger != nil {
		logger = opts.Logger
	} else {
		logger = log.New(os.Stderr, "[http-ingest] ", log.LstdFlags)
	}
	if err := os.MkdirAll(opts.Dir, 0755); err != nil {
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
	h.logger.Printf("HTTP ingest listening on http://%s, dir=%s rps=%d burst=%d auth=%v",
		h.opts.Bind, h.opts.Dir, h.opts.RPS, h.opts.Burst, h.opts.Token != "")

	go func() {
		if err := h.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			h.logger.Printf("server error: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.srv.Shutdown(shutdownCtx); err != nil {
			h.logger.Printf("graceful shutdown failed: %v", err)
		}
		if h.limiter != nil {
			h.limiter.Close()
		}
	}()
	return nil
}

// handleIngest accepts POST /ingest with JSON or JSONL
func (h *HTTPIngestServer) handleIngest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Basic bearer auth
	if h.opts.Token != "" {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) != h.opts.Token {
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
	// Try unmarshal as interface to fully validate
	var v interface{}
	if err := json.Unmarshal(trim, &v); err != nil {
		return err
	}
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