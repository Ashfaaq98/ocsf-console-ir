package cmd

import (
	"context"
	"log"
	"sync"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/enrich/geoip"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/enrich/whois"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/plugins"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// coreEnrichers returns the embedded, in-process enrichments.
//
// Single source of truth: both the long-running pipeline (which registers these
// with the plugin manager's queue) and one-shot ingest (which calls them
// directly) build their set from here, so the two can never drift apart.
func coreEnrichers(logger *log.Logger) []plugins.CorePlugin {
	return []plugins.CorePlugin{
		whois.New(logger),
		geoip.New(logger),
	}
}

// registerCoreEnrichers wires the embedded enrichments into a plugin manager for
// the long-running, queue-driven path used by the TUI and watch mode.
func registerCoreEnrichers(pm plugins.PluginManager, logger *log.Logger) {
	for _, p := range coreEnrichers(logger) {
		if err := pm.GetRegistry().RegisterCorePlugin(p); err != nil {
			logger.Printf("Failed to register %s enrichment: %v", p.Name(), err)
		}
	}
}

// enrichSyncConcurrency bounds the in-flight enrichment work for one-shot
// ingestion. WHOIS and GeoIP are network calls, so some parallelism matters, but
// an unbounded fan-out would hammer the upstream services.
const enrichSyncConcurrency = 8

// syncEnricher applies embedded enrichments to events as they are ingested,
// synchronously.
//
// The long-running path is deliberately asynchronous — enqueue, worker, bus,
// processor — so ingestion is never stalled by a slow lookup. That design has no
// notion of "finished", which a one-shot command needs before it can exit. Since
// plugins.CorePlugin already exposes a plain Process call, batch ingestion skips
// the queue entirely and waits for its own work instead.
type syncEnricher struct {
	store     *store.Store
	enrichers []plugins.CorePlugin
	logger    *log.Logger

	sem chan struct{}
	wg  sync.WaitGroup

	mu      sync.Mutex
	applied int
	failed  int
}

func newSyncEnricher(st *store.Store, logger *log.Logger) *syncEnricher {
	return &syncEnricher{
		store:     st,
		enrichers: coreEnrichers(logger),
		logger:    logger,
		sem:       make(chan struct{}, enrichSyncConcurrency),
	}
}

// Start initializes the underlying enrichments.
func (s *syncEnricher) Start(ctx context.Context) error {
	for _, p := range s.enrichers {
		if err := p.Start(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Stop shuts the enrichments down. Call Wait first.
func (s *syncEnricher) Stop() {
	for _, p := range s.enrichers {
		_ = p.Stop()
	}
}

// Enqueue schedules enrichment for one ingested record. It satisfies
// ingest.Enricher so the folder ingestor can drive it unchanged.
func (s *syncEnricher) EnqueueEvent(msg bus.EventMessage) {
	if msg.EventID == "" {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.sem <- struct{}{}
		defer func() { <-s.sem }()
		s.process(context.Background(), msg)
	}()
}

func (s *syncEnricher) process(ctx context.Context, msg bus.EventMessage) {
	for _, p := range s.enrichers {
		results, err := p.Process(ctx, msg)
		if err != nil {
			s.mu.Lock()
			s.failed++
			s.mu.Unlock()
			s.logger.Printf("enrichment %s failed for %s: %v", p.Name(), msg.EventID, err)
			continue
		}
		for _, e := range results {
			if err := s.store.ApplyEnrichment(ctx, msg.EventID, e); err != nil {
				s.mu.Lock()
				s.failed++
				s.mu.Unlock()
				s.logger.Printf("failed to store %s enrichment for %s: %v", p.Name(), msg.EventID, err)
				continue
			}
			s.mu.Lock()
			s.applied++
			s.mu.Unlock()
		}
	}
}

// Wait blocks until every scheduled enrichment has completed, and reports how
// many were applied and how many failed. This is what makes a one-shot ingest
// able to finish rather than exiting with lookups still in flight.
func (s *syncEnricher) Wait() (applied, failed int) {
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applied, s.failed
}
