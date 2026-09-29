package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/policyz"
)

const authorizationFileName = "authorization.json"

// maxAuditEvents bounds the append-only audit trail so a long-running process
// cannot grow the snapshot without limit. Events are dropped oldest-first, but
// a revocation always persists both its role removal and its audit fact; the
// bound is large enough that recent security history survives normal use.
const maxAuditEvents = 10000

// AuthzStore persists role assignments and the audit trail independently of
// business state. Keeping authorization.json separate from state.json means
// configuration changes never collide with business revisions and a restart
// restores both role configuration and revocation facts verbatim.
type AuthzStore struct {
	mu   sync.RWMutex
	path string
	now  func() time.Time

	State policyz.State
}

// OpenAuthorization loads the durable authorization state from dataDir. When
// no file exists yet, an empty, un-bootstrapped state is returned and the
// caller is expected to bootstrap the initial administrator.
func OpenAuthorization(dataDir string) (*AuthzStore, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	store := &AuthzStore{
		path: filepath.Join(dataDir, authorizationFileName),
		now:  func() time.Time { return time.Now().UTC() },
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *AuthzStore) load() error {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.State = policyz.EmptyState()
		return nil
	}
	if err != nil {
		return fmt.Errorf("read authorization state: %w", err)
	}
	var loaded policyz.State
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return fmt.Errorf("decode authorization state: %w", err)
	}
	normalized, err := normalizeAuthzState(loaded)
	if err != nil {
		return err
	}
	s.State = normalized
	return nil
}

// normalizeAuthzState validates persisted authorization data. Unknown roles in
// an assignment and malformed audit entries stop startup instead of being
// silently dropped, because an unrecognized role could silently expand or
// shrink an operator's access.
func normalizeAuthzState(value policyz.State) (policyz.State, error) {
	if value.Revision < 0 {
		return policyz.State{}, fmt.Errorf("authorization revision cannot be negative")
	}
	if value.Assignments == nil {
		value.Assignments = map[string][]policyz.Role{}
	}
	if value.Audit == nil {
		value.Audit = []policyz.AuditEvent{}
	}
	for operatorID, roles := range value.Assignments {
		if operatorID == "" {
			return policyz.State{}, fmt.Errorf("authorization state contains an empty operator id")
		}
		if len(roles) == 0 {
			return policyz.State{}, fmt.Errorf("operator %s has an empty role assignment", operatorID)
		}
		seen := map[policyz.Role]struct{}{}
		for _, role := range roles {
			if !policyz.IsKnownRole(role) {
				return policyz.State{}, fmt.Errorf(
					"operator %s has unknown role %q", operatorID, role)
			}
			if _, duplicate := seen[role]; duplicate {
				return policyz.State{}, fmt.Errorf(
					"operator %s has a duplicated role %q", operatorID, role)
			}
			seen[role] = struct{}{}
		}
	}
	for _, event := range value.Audit {
		if event.ID == "" || event.OccurredAt.IsZero() {
			return policyz.State{}, fmt.Errorf("authorization audit contains an incomplete event")
		}
	}
	return value, nil
}

// Revision returns the current authorization revision.
func (s *AuthzStore) Revision() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.State.Revision
}

// View hands a deep copy of the current state to visitor. Every call reads the
// freshly committed state, so a permission change is visible on the next
// request without any identity or permission cache.
func (s *AuthzStore) View(visitor func(policyz.State) error) error {
	s.mu.RLock()
	copied := s.State.Clone()
	s.mu.RUnlock()
	return visitor(copied)
}

// Update serializes an authorization change, validates it against a clone, and
// commits it durably before replacing the in-memory state. A mutator error
// leaves both files and memory untouched.
func (s *AuthzStore) Update(mutate func(*policyz.State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	candidate := s.State.Clone()
	if err := mutate(&candidate); err != nil {
		return err
	}
	candidate.Revision = s.State.Revision + 1
	candidate.UpdatedAt = s.now()
	if err := writeSnapshot(s.path, candidate); err != nil {
		return fmt.Errorf("persist authorization state: %w", err)
	}
	s.State = candidate
	return nil
}

// AppendAuthzAudit records an audit fact inside an in-progress mutation. It
// preserves chronological order and enforces the retention bound.
func AppendAuthzAudit(state *policyz.State, event policyz.AuditEvent) {
	state.Audit = append(state.Audit, event)
	if overflow := len(state.Audit) - maxAuditEvents; overflow > 0 {
		state.Audit = append([]policyz.AuditEvent(nil), state.Audit[overflow:]...)
	}
}

// SortedOperatorIDs returns assignment keys in stable order for diagnostics.
func SortedOperatorIDs(state policyz.State) []string {
	ids := make([]string, 0, len(state.Assignments))
	for id := range state.Assignments {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
