package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/ocsf"
	"github.com/stretchr/testify/require"
)

func newEnrichedTestEvent(t *testing.T, s *Store, ctx context.Context) string {
	t.Helper()
	id, err := s.SaveEvent(ctx, &ocsf.Event{
		Time:        time.Now(),
		ClassUID:    4001,
		CategoryUID: 4,
		ActivityID:  1,
		TypeUID:     400101,
		SeverityID:  2,
		Message:     "event awaiting enrichment",
	})
	require.NoError(t, err)
	return id
}

// The detail pane redraws off this signal, so it must fire with the right event
// ID — without it, enrichment lands and the pane keeps showing stale data.
func TestOnEnrichmentNotifiesSubscribers(t *testing.T) {
	st, err := NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	eventID := newEnrichedTestEvent(t, st, ctx)

	var mu sync.Mutex
	var got []string
	st.OnEnrichment(func(id string) {
		mu.Lock()
		got = append(got, id)
		mu.Unlock()
	})

	require.NoError(t, st.ApplyEnrichment(ctx, eventID, Enrichment{
		Source: "geoip",
		Type:   "geoip",
		Data:   map[string]string{"geoip_8_8_8_8_country": "United States"},
	}))

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{eventID}, got)
}

// The subscriber must not be told about an enrichment it cannot read back.
func TestOnEnrichmentFiresOnlyAfterTheRowIsReadable(t *testing.T) {
	st, err := NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	eventID := newEnrichedTestEvent(t, st, ctx)

	var seen int
	st.OnEnrichment(func(id string) {
		enrichments, err := st.GetEnrichmentsByEvent(ctx, id)
		require.NoError(t, err)
		require.NotEmpty(t, enrichments, "notified before the enrichment was queryable")
		seen = len(enrichments)
	})

	require.NoError(t, st.ApplyEnrichment(ctx, eventID, Enrichment{
		Source: "whois",
		Type:   "whois",
		Data:   map[string]string{"whois_example_com_registrar": "MarkMonitor Inc."},
	}))
	require.Equal(t, 1, seen)
}

func TestOnEnrichmentSupportsMultipleSubscribers(t *testing.T) {
	st, err := NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	eventID := newEnrichedTestEvent(t, st, ctx)

	var mu sync.Mutex
	calls := 0
	for i := 0; i < 3; i++ {
		st.OnEnrichment(func(string) {
			mu.Lock()
			calls++
			mu.Unlock()
		})
	}
	// A nil callback must not panic the enrichment worker.
	st.OnEnrichment(nil)

	require.NoError(t, st.ApplyEnrichment(ctx, eventID, Enrichment{
		Source: "geoip",
		Data:   map[string]string{"geoip_1_1_1_1_city": "Sydney"},
	}))

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 3, calls)
}

// A failed write must not claim an enrichment arrived.
func TestOnEnrichmentSilentOnFailedWrite(t *testing.T) {
	st, err := NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()

	notified := false
	st.OnEnrichment(func(string) { notified = true })

	// Foreign keys are enforced, so an enrichment for an event that does not
	// exist is rejected.
	err = st.ApplyEnrichment(ctx, "evt_does_not_exist", Enrichment{
		Source: "geoip",
		Data:   map[string]string{"geoip_8_8_8_8_city": "Mountain View"},
	})
	require.Error(t, err)
	require.False(t, notified, "notified subscribers about an enrichment that was never stored")
}

// Registration races with enrichment workers in a real run.
func TestOnEnrichmentIsRaceSafe(t *testing.T) {
	st, err := NewStore(":memory:")
	require.NoError(t, err)
	defer st.Close()

	ctx := context.Background()
	eventID := newEnrichedTestEvent(t, st, ctx)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st.OnEnrichment(func(string) {})
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = st.ApplyEnrichment(ctx, eventID, Enrichment{
				Source: "geoip",
				Data:   map[string]string{"geoip_8_8_8_8_city": "Mountain View"},
			})
		}(i)
	}
	wg.Wait()
}
