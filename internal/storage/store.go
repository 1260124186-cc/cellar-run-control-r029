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

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/authz"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
)

const stateFileName = "state.json"

type Store struct {
	mu       sync.RWMutex
	path     string
	snapshot domain.Snapshot
	now      func() time.Time
}

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	store := &Store{
		path:     filepath.Join(dataDir, stateFileName),
		snapshot: domain.EmptySnapshot(),
		now:      func() time.Time { return time.Now().UTC() },
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read state: %w", err)
	}
	var loaded domain.Snapshot
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return fmt.Errorf("decode state: %w", err)
	}
	normalized, err := normalizeSnapshot(loaded)
	if err != nil {
		return err
	}
	s.snapshot = normalized
	return nil
}

func normalizeSnapshot(value domain.Snapshot) (domain.Snapshot, error) {
	if value.Revision < 0 {
		return domain.Snapshot{}, fmt.Errorf("state revision cannot be negative")
	}
	if value.Formulas == nil {
		value.Formulas = map[string]domain.Formula{}
	}
	if value.Vessels == nil {
		value.Vessels = map[string]domain.Vessel{}
	}
	if value.Runs == nil {
		value.Runs = map[string]domain.FermentationRun{}
	}
	if value.NameIndex == nil {
		value.NameIndex = map[string]string{}
	}
	if value.VesselIndex == nil {
		value.VesselIndex = map[string]string{}
	}
	if value.RunIndex == nil {
		value.RunIndex = map[string]string{}
	}
	if value.Authorization.Operators == nil {
		value.Authorization.Operators = map[string]domain.OperatorRecord{}
	}
	if value.Authorization.Audit == nil {
		value.Authorization.Audit = []domain.AuditEvent{}
	}
	if value.Authorization.NextAuditSeq < 1 {
		return domain.Snapshot{}, fmt.Errorf("authorization audit sequence cannot be below one")
	}
	if err := validateIndexes(value); err != nil {
		return domain.Snapshot{}, err
	}
	if err := validateAuthorization(value.Authorization); err != nil {
		return domain.Snapshot{}, err
	}
	return value, nil
}

// validateAuthorization guarantees a restarted process never serves with an
// unreadable role assignment: unknown roles, conflicting operational roles, or
// a mismatched audit sequence stop startup instead of being silently repaired.
func validateAuthorization(state domain.AuthorizationState) error {
	ids := make([]string, 0, len(state.Operators))
	for id := range state.Operators {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		operator := state.Operators[id]
		if operator.ID != id {
			return fmt.Errorf("operator %s index does not match its record", id)
		}
		if err := domain.ValidateOperatorID(id, "operator id"); err != nil {
			return fmt.Errorf("operator record has an invalid identity: %w", err)
		}
		if operator.Version < 1 {
			return fmt.Errorf("operator %s has an invalid version", id)
		}
		roles, err := authz.NormalizeRoles(operator.Roles)
		if err != nil {
			return fmt.Errorf("operator %s has an invalid role set: %w", id, err)
		}
		if a, b, conflict := authz.Conflict(roles); conflict {
			return fmt.Errorf("operator %s holds conflicting roles %s and %s", id, a, b)
		}
	}
	expectedSeq := int64(0)
	for index, event := range state.Audit {
		if index == 0 {
			expectedSeq = event.Sequence
		} else if event.Sequence != expectedSeq {
			return fmt.Errorf("audit history has a non-contiguous sequence")
		}
		expectedSeq = event.Sequence + 1
	}
	if len(state.Audit) > 0 && state.NextAuditSeq != expectedSeq {
		return fmt.Errorf("audit sequence does not match its history")
	}
	return nil
}

func validateIndexes(value domain.Snapshot) error {
	expectedNames := make(map[string]string, len(value.Formulas))
	for id, formula := range value.Formulas {
		key := domain.NameKey(formula.Name)
		if key == "" {
			return fmt.Errorf("formula %s has an empty normalized name", id)
		}
		if existing, found := expectedNames[key]; found && existing != id {
			return fmt.Errorf("formula name index contains a duplicate key")
		}
		expectedNames[key] = id
	}
	if err := compareIndexes("formula name", value.NameIndex, expectedNames); err != nil {
		return err
	}

	expectedVessels := make(map[string]string, len(value.Vessels))
	for id, vessel := range value.Vessels {
		if existing, found := expectedVessels[vessel.Code]; found && existing != id {
			return fmt.Errorf("vessel index contains a duplicate code")
		}
		expectedVessels[vessel.Code] = id
	}
	if err := compareIndexes("vessel code", value.VesselIndex, expectedVessels); err != nil {
		return err
	}

	expectedRuns := make(map[string]string, len(value.Runs))
	for id, run := range value.Runs {
		if existing, found := expectedRuns[run.Code]; found && existing != id {
			return fmt.Errorf("run index contains a duplicate code")
		}
		expectedRuns[run.Code] = id
	}
	return compareIndexes("run code", value.RunIndex, expectedRuns)
}

func compareIndexes(label string, actual, expected map[string]string) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("%s index does not match its collection", label)
	}
	for key, expectedID := range expected {
		actualID, found := actual[key]
		if !found || actualID != expectedID {
			return fmt.Errorf("%s index does not match its collection", label)
		}
	}
	return nil
}

func (s *Store) Revision() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshot.Revision
}

func (s *Store) View(visitor func(domain.Snapshot) error) error {
	s.mu.RLock()
	copied := s.snapshot.Clone()
	s.mu.RUnlock()
	return visitor(copied)
}

func (s *Store) Update(expected *int64, mutate func(*domain.Snapshot) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if expected != nil && *expected != s.snapshot.Revision {
		return domain.NewError(domain.CodeRevisionConflict,
			"the supplied revision does not match the current snapshot")
	}
	candidate := s.snapshot.Clone()
	if err := mutate(&candidate); err != nil {
		return err
	}
	candidate.Revision = s.snapshot.Revision + 1
	candidate.UpdatedAt = s.now()
	if err := writeSnapshot(s.path, candidate); err != nil {
		return domain.NewError(domain.CodeStorage, err.Error())
	}
	s.snapshot = candidate
	return nil
}

func (s *Store) Execute(mutator func(*domain.Snapshot) error) error {
	return s.Update(nil, mutator)
}
