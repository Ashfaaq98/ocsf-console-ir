package ingest

import "github.com/Ashfaaq98/ocsf-console-ir/internal/bus"

// Enricher receives ingested events for optional in-process enrichment by
// embedded core plugins. It is deliberately decoupled from the plugins package
// so ingestors depend only on this small interface.
//
// A nil Enricher disables in-process enrichment; the event bus path (Redis, if
// configured) is unaffected. Implementations must be non-blocking so ingestion
// is never stalled by slow enrichment.
type Enricher interface {
	EnqueueEvent(event bus.EventMessage)
}
