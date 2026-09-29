package service

import (
	"strings"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/clock"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/policyz"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/storage"
)

type Service struct {
	store *storage.Store
	authz *storage.AuthzStore
	clock clock.Clock
}

// New builds the application service backed by a business snapshot store and
// an authorization store. The initial administrator is seeded once and
// restored from disk on subsequent starts.
func New(store *storage.Store, authz *storage.AuthzStore, timeSource clock.Clock) (*Service, error) {
	if timeSource == nil {
		timeSource = clock.System{}
	}
	service := &Service{store: store, authz: authz, clock: timeSource}
	if err := service.ensureBootstrap(timeSource.Now()); err != nil {
		return nil, err
	}
	return service, nil
}

// PolicyPermissions exposes the static permission set of a role for
// diagnostics and API responses.
func PolicyPermissions(role policyz.Role) ([]policyz.Permission, bool) {
	return policyz.RolePermissions(role)
}

func (s *Service) Revision() int64 {
	return s.store.Revision()
}

func (s *Service) checkExpected(current int64, expected *int64) error {
	if expected != nil && current != *expected {
		return domain.NewError(domain.CodeRevisionConflict,
			"the aggregate version does not match X-Expected-Version")
	}
	return nil
}

func generateEntityID(prefix string) (string, error) {
	return domain.NewID(prefix)
}

func generatedRunCode() (string, error) {
	value, err := domain.NewID("run")
	if err != nil {
		return "", err
	}
	suffix := strings.ToUpper(strings.TrimPrefix(value, "run_"))
	return "RUN-" + suffix, nil
}
