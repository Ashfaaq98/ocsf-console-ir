package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// A case briefing is stored as structured notes rather than new tables.
//
// The precedent is already here: the generated case summary is a note with
// LinkedType "summary", filtered out of the notes list. This extends the same
// mechanism to the statement, the hypotheses and the next actions.
//
// Tables come later, if querying or ordering these proves cumbersome. A
// migration for something only the briefing reads, in the order it was written,
// would be a migration for visual polish.

// Briefing note types. These occupy Note.LinkedType, alongside the existing
// "summary" and the "event"/"ioc" links a note can carry.
const (
	NoteTypeStatement  = "statement"
	NoteTypeHypothesis = "hypothesis"
	NoteTypeNextAction = "next_action"
	NoteTypeSummary    = "summary"
)

// IsBriefingNote reports whether a note holds briefing content rather than
// analyst prose. The notes tab must exclude these, or the decision log fills
// with fragments of the briefing.
func IsBriefingNote(n Note) bool {
	switch strings.ToLower(n.LinkedType) {
	case NoteTypeStatement, NoteTypeHypothesis, NoteTypeNextAction, NoteTypeSummary:
		return true
	}
	return false
}

// Confidence levels a hypothesis can carry.
const (
	ConfidenceConfirmed = "confirmed"
	ConfidenceLikely    = "likely"
	ConfidenceOpen      = "open"
)

// Hypothesis is a belief about the incident and how sure the analyst is.
type Hypothesis struct {
	Text       string `json:"text"`
	Confidence string `json:"confidence"`
}

// NextAction is one item on the case's checklist.
type NextAction struct {
	Text string `json:"text"`
	Done bool   `json:"done"`
}

// Briefing is a case's narrative content.
type Briefing struct {
	Statement   string
	Hypotheses  []Hypothesis
	NextActions []NextAction
	// Summary is generated text. It is kept apart from the rest so nothing can
	// mistake it for something an analyst wrote.
	Summary    string
	SummaryAt  time.Time
	HasSummary bool
}

// GetBriefing assembles a case's briefing from its notes.
//
// Malformed entries are skipped rather than failing the whole briefing: one bad
// row written by an older build must not blank the screen.
func (s *Store) GetBriefing(ctx context.Context, caseID string) (Briefing, error) {
	// Oldest first: a checklist and a set of hypotheses read in the order the
	// analyst wrote them, not reversed.
	notes, err := s.notesInOrder(ctx, caseID, true)
	if err != nil {
		return Briefing{}, fmt.Errorf("failed to read briefing notes: %w", err)
	}

	var b Briefing
	for _, n := range notes {
		switch strings.ToLower(n.LinkedType) {
		case NoteTypeStatement:
			b.Statement = n.Content
		case NoteTypeHypothesis:
			var h Hypothesis
			if json.Unmarshal([]byte(n.Content), &h) == nil && h.Text != "" {
				b.Hypotheses = append(b.Hypotheses, h)
			}
		case NoteTypeNextAction:
			var a NextAction
			if json.Unmarshal([]byte(n.Content), &a) == nil && a.Text != "" {
				b.NextActions = append(b.NextActions, a)
			}
		case NoteTypeSummary:
			b.Summary, b.SummaryAt, b.HasSummary = n.Content, n.CreatedAt, true
		}
	}
	return b, nil
}

// SetStatement records the incident statement, replacing any previous one.
func (s *Store) SetStatement(ctx context.Context, caseID, author, text string) error {
	if err := s.deleteBriefingNotes(ctx, caseID, NoteTypeStatement); err != nil {
		return err
	}
	if strings.TrimSpace(text) == "" {
		return nil
	}
	_, err := s.AddNote(ctx, Note{
		CaseID: caseID, Author: author, Content: text, LinkedType: NoteTypeStatement,
	})
	return err
}

// AddHypothesis records a belief and its confidence.
func (s *Store) AddHypothesis(ctx context.Context, caseID, author string, h Hypothesis) error {
	return s.addJSONNote(ctx, caseID, author, NoteTypeHypothesis, h)
}

// AddNextAction records a checklist item.
func (s *Store) AddNextAction(ctx context.Context, caseID, author string, a NextAction) error {
	return s.addJSONNote(ctx, caseID, author, NoteTypeNextAction, a)
}

// SetNextActions replaces the whole checklist, which is what ticking an item
// amounts to when the items have no ids of their own.
func (s *Store) SetNextActions(ctx context.Context, caseID, author string, actions []NextAction) error {
	if err := s.deleteBriefingNotes(ctx, caseID, NoteTypeNextAction); err != nil {
		return err
	}
	for _, a := range actions {
		if err := s.addJSONNote(ctx, caseID, author, NoteTypeNextAction, a); err != nil {
			return err
		}
	}
	return nil
}

// SetHypotheses replaces the whole set, for the same reason as SetNextActions.
func (s *Store) SetHypotheses(ctx context.Context, caseID, author string, hs []Hypothesis) error {
	if err := s.deleteBriefingNotes(ctx, caseID, NoteTypeHypothesis); err != nil {
		return err
	}
	for _, h := range hs {
		if err := s.addJSONNote(ctx, caseID, author, NoteTypeHypothesis, h); err != nil {
			return err
		}
	}
	return nil
}

// addJSONNote stores a value as a note of the given type.
func (s *Store) addJSONNote(ctx context.Context, caseID, author, noteType string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to encode %s: %w", noteType, err)
	}
	_, err = s.AddNote(ctx, Note{
		CaseID: caseID, Author: author, Content: string(data), LinkedType: noteType,
	})
	return err
}

// deleteBriefingNotes removes every note of one briefing type for a case.
func (s *Store) deleteBriefingNotes(ctx context.Context, caseID, noteType string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM notes WHERE case_id = ? AND linked_type = ?`, caseID, noteType)
	if err != nil {
		return fmt.Errorf("failed to clear %s notes: %w", noteType, err)
	}
	return nil
}

// AcceptSummary promotes a generated summary into an ordinary authored note.
//
// This is the only route from generated text into the case record, and it takes
// a deliberate action. The summary itself stays where it was: accepting it is
// the analyst saying "this is now my words", not a move.
func (s *Store) AcceptSummary(ctx context.Context, caseID, author, summary string) error {
	if strings.TrimSpace(summary) == "" {
		return fmt.Errorf("there is no summary to accept")
	}
	_, err := s.AddNote(ctx, Note{
		CaseID:  caseID,
		Author:  author,
		Content: summary,
		// No LinkedType: it is now an ordinary note, indistinguishable in the
		// log from one that was typed, because the analyst has adopted it.
	})
	return err
}
