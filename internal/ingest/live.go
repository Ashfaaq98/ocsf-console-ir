package ingest

import (
	"context"
	"errors"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// LiveOptions configures the live event ingestor.
type LiveOptions struct {
	// URL is the OCSF sample/simulator endpoint that returns a JSON event per GET.
	URL string

	// Interval is the target interval between successful ingests.
	// Defaults to 2s. Minimum enforced at 100ms.
	Interval time.Duration

	// Jitter applies a +/- percentage to Interval. Clamp: [0.0, 1.0].
	// 0.1 means +/-10% of Interval.
	Jitter float64

	// CaseTitle, when set, assigns each ingested event to this case
	// (created if missing). When empty, events are not assigned to any case.
	CaseTitle string

	// Count limits number of events to ingest. 0 means run until ctx is cancelled.
	Count int

	// Logger for operational logs. If nil, a default logger is used.
	Logger *log.Logger

	// HTTPClient for fetching events. If nil, a default client is used.
	HTTPClient *http.Client
}

// LiveIngestor fetches OCSF sample events on an interval and ingests them.
type LiveIngestor struct {
	parser *Parser
	store  *store.Store
	bus    bus.Bus

	opts   LiveOptions
	client *http.Client
	logger *log.Logger

	caseID string
	rng    *rand.Rand
}

// NewLiveIngestor constructs a LiveIngestor with sane defaults and clamps.
func NewLiveIngestor(parser *Parser, st *store.Store, b bus.Bus, opts LiveOptions) *LiveIngestor {
	logger := opts.Logger
	if logger == nil {
		logger = log.New(log.Writer(), "[live-ingest] ", log.LstdFlags)
	}

	// Defaults and clamps
	if opts.URL == "" {
		opts.URL = "https://schema.ocsf.io/sample/1.6.0/classes/account_change?profiles=cloud"
	}
	if opts.Interval <= 0 {
		opts.Interval = 2 * time.Second
	}
	if opts.Interval < 100*time.Millisecond {
		opts.Interval = 100 * time.Millisecond
	}
	if opts.Jitter < 0 {
		opts.Jitter = 0
	}
	if opts.Jitter > 1 {
		opts.Jitter = 1
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	return &LiveIngestor{
		parser: parser,
		store:  st,
		bus:    b,
		opts:   opts,
		client: client,
		logger: logger,
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Run starts the fetch-parse-ingest loop until Count is reached (if >0) or ctx is cancelled.
// When CaseTitle is set, it ensures the case exists and periodically syncs event_count.
func (li *LiveIngestor) Run(ctx context.Context) error {
	// Optional case management
	if strings.TrimSpace(li.opts.CaseTitle) != "" {
		if err := li.ensureCase(ctx); err != nil {
			return err
		}
	}

	// Periodic case event_count sync (mirrors folder watch behavior cadence)
	var caseTicker *time.Ticker
	if li.caseID != "" {
		caseTicker = time.NewTicker(3 * time.Second)
		defer caseTicker.Stop()
	}

	var (
		ingested   int
		failStreak int
	)

	for {
		// Respect Count limit if provided
		if li.opts.Count > 0 && ingested >= li.opts.Count {
			// Final best-effort case sync
			if li.caseID != "" {
				_ = li.store.UpdateCaseEventCount(context.Background(), li.caseID)
			}
			return nil
		}

		// Check for cancellation
		select {
		case <-ctx.Done():
			// Final best-effort case sync
			if li.caseID != "" {
				_ = li.store.UpdateCaseEventCount(context.Background(), li.caseID)
			}
			return ctx.Err()
		default:
		}

		// Fetch a raw OCSF JSON event
		raw, fetchErr := li.fetchOnce(ctx)
		if fetchErr != nil {
			// Suppress noisy logs when shutdown was requested
			if errors.Is(fetchErr, context.Canceled) || ctx.Err() != nil {
				// Propagate cancellation without logging a fetch error
				return ctx.Err()
			}
			failStreak++
			li.logger.Printf("fetch error (streak=%d): %v", failStreak, fetchErr)
			li.sleepWithBackoff(ctx, failStreak)
			continue
		}
		// Reset backoff after any successful fetch
		failStreak = 0

		// Ingest it (parse, save, assign, publish)
		if _, err := li.ingestRaw(ctx, raw); err != nil {
			li.logger.Printf("ingest error: %v", err)
			// No special backoff for parse/store/bus errors; continue loop
		} else {
			ingested++
		}

		// Periodic case event_count sync
		if caseTicker != nil {
			select {
			case <-caseTicker.C:
				_ = li.store.UpdateCaseEventCount(context.Background(), li.caseID)
			default:
			}
		}

		// Wait for next tick with jitter
		if err := li.sleepInterval(ctx); err != nil {
			// Interrupted by context
			if li.caseID != "" {
				_ = li.store.UpdateCaseEventCount(context.Background(), li.caseID)
			}
			return err
		}
	}
}

// fetchOnce performs a single HTTP GET to the configured URL and returns the body bytes.
func (li *LiveIngestor) fetchOnce(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, li.opts.URL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := li.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Treat non-2xx as error
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, resp.Body)
		return nil, errors.New(resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	trim := strings.TrimSpace(string(data))
	if trim == "" {
		return nil, errors.New("empty response body")
	}
	return []byte(trim), nil
}

// ingestRaw parses the raw JSON, saves the event, optionally assigns to case, and publishes to the bus.
func (li *LiveIngestor) ingestRaw(ctx context.Context, raw []byte) (string, error) {
	ocsfEvent, err := li.parser.ParseEvent(raw)
	if err != nil {
		return "", err
	}

	eventID, err := li.store.SaveEvent(ctx, ocsfEvent)
	if err != nil {
		return "", err
	}

	// Optional case assignment
	if li.caseID != "" {
		if err := li.store.AssignEventToCase(ctx, eventID, li.caseID); err != nil {
			// Not fatal to the whole loop; log and continue
			li.logger.Printf("assign to case error: %v", err)
		}
	}

	// Best-effort publish to bus (no-op on NullBus)
	_ = li.bus.PublishEvent(ctx, bus.EventMessage{
		EventID:   eventID,
		EventType: string(ocsfEvent.GetEventType()),
		RawJSON:   string(raw),
		Timestamp: ocsfEvent.Time.Unix(),
	})

	return eventID, nil
}

// ensureCase finds or creates the case with the configured CaseTitle.
// Mirrors logic pattern from the folder ingestor.
func (li *LiveIngestor) ensureCase(ctx context.Context) error {
	title := strings.TrimSpace(li.opts.CaseTitle)
	if title == "" {
		return nil
	}

	cases, err := li.store.ListCases(ctx)
	if err != nil {
		return err
	}
	for _, c := range cases {
		if c.Title == title {
			li.caseID = c.ID
			return nil
		}
	}

	newCase := store.Case{
		Title:       title,
		Description: "Live ingested events",
		Severity:    "medium",
		Status:      "open",
	}
	id, err := li.store.CreateOrUpdateCase(ctx, newCase)
	if err != nil {
		return err
	}
	li.caseID = id
	return nil
}

// sleepInterval sleeps for the configured interval with optional jitter, unless ctx is cancelled.
func (li *LiveIngestor) sleepInterval(ctx context.Context) error {
	d := li.intervalWithJitter()
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// sleepWithBackoff sleeps using exponential backoff based on consecutive failure streak.
// Base backoff is 1s, capped at 30s. Jitter is applied if configured.
func (li *LiveIngestor) sleepWithBackoff(ctx context.Context, failStreak int) {
	base := time.Second
	// backoff = base * 2^(failStreak-1), capped
	exp := math.Pow(2, float64(failStreak-1))
	backoff := time.Duration(float64(base) * exp)
	if backoff > 30*time.Second {
		backoff = 30 * time.Second
	}

	// Apply jitter proportionally to backoff (reuse li.Jitter semantics)
	j := li.applyJitterDuration(backoff)
	timer := time.NewTimer(j)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-timer.C:
		return
	}
}

// intervalWithJitter computes Interval with +/- jitter.
func (li *LiveIngestor) intervalWithJitter() time.Duration {
	return li.applyJitterDuration(li.opts.Interval)
}

func (li *LiveIngestor) applyJitterDuration(d time.Duration) time.Duration {
	if li.opts.Jitter <= 0 {
		return d
	}
	// random in [-j, +j]
	frac := (li.rng.Float64()*2 - 1) * li.opts.Jitter
	adjust := 1 + frac
	if adjust < 0.1 {
		adjust = 0.1 // never less than 10% of base
	}
	return time.Duration(float64(d) * adjust)
}