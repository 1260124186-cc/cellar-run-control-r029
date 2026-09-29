package service

import (
	"errors"
	"sort"
	"strings"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/authz"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
)

// Actor is the authenticated operator identity attached to a request. The
// identity is supplied over the trusted local API; roles are always resolved
// from the durable snapshot, never from the request.
type Actor struct {
	ID string
}

type AssignRolesInput struct {
	ExpectedVersion *int64
	Roles           []string
}

type RevokeRolesInput struct {
	ExpectedVersion *int64
	// Roles lists the roles to remove. A nil or empty list removes every role.
	Roles []string
}

// authorizationFailure carries both the domain error returned to the caller
// and the pure decision that produced it, so the denial can be audited.
type authorizationFailure struct {
	decision authz.Decision
	err      *domain.Error
}

func decisionError(decision authz.Decision) *domain.Error {
	switch decision.Reason {
	case authz.ReasonIdentityRequired:
		return domain.NewError(domain.CodeIdentityRequired,
			"X-Operator-ID is required for this operation")
	case authz.ReasonUnknownOperator:
		return domain.NewError(domain.CodeUnknownOperator,
			"the operator identity is not registered")
	case authz.ReasonUnknownRole:
		return domain.NewError(domain.CodeUnknownRole,
			"the operator holds a role that is not defined")
	case authz.ReasonRoleConflict:
		return domain.NewError(domain.CodeRoleConflict,
			"the operator holds mutually exclusive roles")
	default:
		return domain.NewError(domain.CodePermissionDenied,
			"the operator lacks the required permission")
	}
}

// authorizedUpdate enforces perm inside the same transaction that runs mutate.
// A denial returns before mutate is invoked, so no business write can occur;
// the denial is then persisted to the audit log by a separate audit-only
// transaction. Because the role set is read from the current snapshot on each
// call, a grant or revocation takes effect on the next request.
func (s *Service) authorizedUpdate(
	actor Actor,
	perm authz.Permission,
	mutate func(*domain.Snapshot) error,
) error {
	var failure *authorizationFailure
	err := s.store.Execute(func(snapshot *domain.Snapshot) error {
		record, registered := snapshot.Authorization.Operators[actor.ID]
		decision := authz.Decide(actor.ID, registered, record.Roles, perm)
		if !decision.Allowed {
			failure = &authorizationFailure{decision: decision, err: decisionError(decision)}
			return failure.err
		}
		return mutate(snapshot)
	})
	if failure != nil {
		if auditErr := s.recordDenial(actor, failure.decision); auditErr != nil {
			return auditErr
		}
		return failure.err
	}
	return err
}

// authorizedView guards administrative reads. A denial is audited exactly as
// for a write but no business data is returned.
func (s *Service) authorizedView(
	actor Actor,
	perm authz.Permission,
	visitor func(domain.Snapshot) error,
) error {
	var failure *authorizationFailure
	viewErr := s.store.View(func(snapshot domain.Snapshot) error {
		record, registered := snapshot.Authorization.Operators[actor.ID]
		decision := authz.Decide(actor.ID, registered, record.Roles, perm)
		if !decision.Allowed {
			failure = &authorizationFailure{decision: decision, err: decisionError(decision)}
			return failure.err
		}
		return visitor(snapshot)
	})
	if failure != nil {
		if auditErr := s.recordDenial(actor, failure.decision); auditErr != nil {
			return auditErr
		}
		return failure.err
	}
	return viewErr
}

// recordDenial appends an audit entry in its own transaction, independent of
// the rejected business transaction, so a denial never rides along with a
// business write and still survives restarts.
func (s *Service) recordDenial(actor Actor, decision authz.Decision) error {
	return s.recordDeny(actor.ID, "", string(decision.Permission), decision.Reason)
}

// RecordIdentityDenial audits a request that presented no operator identity.
// It is invoked from the HTTP boundary before any business code can run, so an
// unauthenticated attempt is denied and recorded without a business write, just
// like a denial decided inside a transaction.
func (s *Service) RecordIdentityDenial(required authz.Permission) error {
	return s.recordDeny("", "", string(required), authz.ReasonIdentityRequired)
}

// recordAdministrationDenial audits an authorized admin's rejected role
// assignment (unknown role or role conflict) in its own transaction. The
// rejected assignment itself never reaches storage.
func (s *Service) recordAdministrationDenial(actor Actor, target string, reason domain.Code) error {
	return s.recordDeny(actor.ID, target, string(authz.PermAdmin), authz.Reason(reason))
}

func (s *Service) recordDeny(actor, target, permission string, reason authz.Reason) error {
	return s.store.Execute(func(snapshot *domain.Snapshot) error {
		snapshot.Authorization.AppendAudit(domain.AuditEvent{
			OccurredAt: s.clock.Now(),
			Actor:      actor,
			Target:     target,
			Action:     domain.AuditActionDeny,
			Permission: permission,
			Reason:     string(reason),
		})
		return nil
	})
}

// SeedBootstrapAdmin provisions the initial administrator once, when no
// operator records exist. It never revives an administrator that was later
// removed, so a revocation survives restart.
func (s *Service) SeedBootstrapAdmin(bootstrapID string) error {
	bootstrapID = strings.ToLower(strings.TrimSpace(bootstrapID))
	if err := domain.ValidateOperatorID(bootstrapID, "bootstrap admin"); err != nil {
		return err
	}
	return s.store.Execute(func(snapshot *domain.Snapshot) error {
		if len(snapshot.Authorization.Operators) > 0 {
			return nil
		}
		now := s.clock.Now()
		snapshot.Authorization.Operators[bootstrapID] = domain.OperatorRecord{
			ID:        bootstrapID,
			Roles:     []string{string(authz.RoleAdmin)},
			Version:   1,
			CreatedAt: now,
			UpdatedAt: now,
		}
		snapshot.Authorization.AppendAudit(domain.AuditEvent{
			OccurredAt: now,
			Actor:      bootstrapID,
			Action:     domain.AuditActionBootstrapAdmin,
			Target:     bootstrapID,
			Roles:      []string{string(authz.RoleAdmin)},
		})
		return nil
	})
}

func (s *Service) ListOperators(actor Actor) ([]domain.OperatorRecord, error) {
	var records []domain.OperatorRecord
	err := s.authorizedView(actor, authz.PermAdmin, func(snapshot domain.Snapshot) error {
		records = make([]domain.OperatorRecord, 0, len(snapshot.Authorization.Operators))
		for _, record := range snapshot.Authorization.Operators {
			records = append(records, cloneOperator(record))
		}
		sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
		return nil
	})
	if err != nil {
		return nil, err
	}
	return records, nil
}

func (s *Service) AssignRoles(
	actor Actor,
	target string,
	input AssignRolesInput,
) (domain.OperatorRecord, error) {
	target = strings.ToLower(strings.TrimSpace(target))
	var updated domain.OperatorRecord
	var rejected domain.Code
	err := s.authorizedUpdate(actor, authz.PermAdmin, func(snapshot *domain.Snapshot) error {
		if err := domain.ValidateOperatorID(target, "operator_id"); err != nil {
			return err
		}
		roles, err := authz.NormalizeRoles(input.Roles)
		if err != nil {
			if authz.IsUnknownRole(err) {
				rejected = domain.CodeUnknownRole
			}
			return roleListError(err)
		}
		if a, b, conflict := authz.Conflict(roles); conflict {
			rejected = domain.CodeRoleConflict
			return domain.NewError(domain.CodeRoleConflict,
				"roles "+string(a)+" and "+string(b)+" are mutually exclusive")
		}
		now := s.clock.Now()
		record, exists := snapshot.Authorization.Operators[target]
		if !exists {
			if input.ExpectedVersion != nil {
				return domain.NewError(domain.CodeOperatorNotFound, "operator was not found")
			}
			record = domain.OperatorRecord{ID: target, Version: 1, CreatedAt: now}
		} else if err := s.checkExpected(record.Version, input.ExpectedVersion); err != nil {
			return err
		}
		record.Roles = roleStrings(roles)
		record.Version++
		record.UpdatedAt = now
		snapshot.Authorization.Operators[target] = record
		snapshot.Authorization.AppendAudit(domain.AuditEvent{
			OccurredAt: now,
			Actor:      actor.ID,
			Action:     domain.AuditActionGrant,
			Target:     target,
			Roles:      append([]string(nil), record.Roles...),
		})
		updated = cloneOperator(record)
		return nil
	})
	if err != nil {
		// An authorized admin attempted to assign an unknown or conflicting
		// role. The assignment is rejected without a business write; record the
		// attempt in its own transaction so the stable result stays auditable.
		if rejected == domain.CodeUnknownRole || rejected == domain.CodeRoleConflict {
			if auditErr := s.recordAdministrationDenial(actor, target, rejected); auditErr != nil {
				return domain.OperatorRecord{}, auditErr
			}
		}
		return domain.OperatorRecord{}, err
	}
	return updated, nil
}

func (s *Service) RevokeRoles(
	actor Actor,
	target string,
	input RevokeRolesInput,
) (domain.OperatorRecord, error) {
	target = strings.ToLower(strings.TrimSpace(target))
	var updated domain.OperatorRecord
	err := s.authorizedUpdate(actor, authz.PermAdmin, func(snapshot *domain.Snapshot) error {
		if err := domain.ValidateOperatorID(target, "operator_id"); err != nil {
			return err
		}
		record, exists := snapshot.Authorization.Operators[target]
		if !exists {
			return domain.NewError(domain.CodeOperatorNotFound, "operator was not found")
		}
		if err := s.checkExpected(record.Version, input.ExpectedVersion); err != nil {
			return err
		}
		held := make(map[string]bool, len(record.Roles))
		for _, role := range record.Roles {
			held[role] = true
		}
		removeAll := len(input.Roles) == 0
		var requested []authz.Role
		if !removeAll {
			roles, err := authz.NormalizeRoles(input.Roles)
			if err != nil {
				return roleListError(err)
			}
			requested = roles
		}
		removed := make([]string, 0, len(record.Roles))
		remaining := make([]string, 0, len(record.Roles))
		for _, role := range record.Roles {
			shouldRemove := removeAll
			if !removeAll {
				for _, wanted := range requested {
					if string(wanted) == role {
						shouldRemove = true
						break
					}
				}
			}
			if shouldRemove {
				removed = append(removed, role)
			} else {
				remaining = append(remaining, role)
			}
		}
		// A subset revocation that removes nothing is idempotent and does not
		// manufacture a revision or a fake revocation fact.
		if len(removed) == 0 {
			updated = cloneOperator(record)
			return nil
		}
		now := s.clock.Now()
		record.Roles = remaining
		record.Version++
		record.UpdatedAt = now
		snapshot.Authorization.Operators[target] = record
		snapshot.Authorization.AppendAudit(domain.AuditEvent{
			OccurredAt: now,
			Actor:      actor.ID,
			Action:     domain.AuditActionRevoke,
			Target:     target,
			Roles:      removed,
		})
		updated = cloneOperator(record)
		return nil
	})
	if err != nil {
		return domain.OperatorRecord{}, err
	}
	return updated, nil
}

// ListAudit returns audit events in sequence order, newest first when
// descending, limited to at most limit entries.
func (s *Service) ListAudit(actor Actor, limit int) ([]domain.AuditEvent, error) {
	if limit <= 0 || limit > domain.MaxAuditEntries {
		limit = domain.MaxAuditEntries
	}
	var events []domain.AuditEvent
	err := s.authorizedView(actor, authz.PermAdmin, func(snapshot domain.Snapshot) error {
		total := len(snapshot.Authorization.Audit)
		start := total - limit
		if start < 0 {
			start = 0
		}
		events = append([]domain.AuditEvent(nil), snapshot.Authorization.Audit[start:]...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}

func roleListError(err error) error {
	var listErr *authz.RoleListError
	if !errors.As(err, &listErr) {
		return err
	}
	if listErr.Kind == "unknown" {
		return domain.NewError(domain.CodeUnknownRole, "role is not defined: "+listErr.Value)
	}
	if listErr.Kind == "too_many" {
		return domain.FieldError(domain.CodeInvalidInput, "roles",
			"an operator can hold at most eight roles")
	}
	return domain.FieldError(domain.CodeInvalidInput, "roles", "role names must not be empty")
}

func roleStrings(roles []authz.Role) []string {
	values := make([]string, 0, len(roles))
	for _, role := range roles {
		values = append(values, string(role))
	}
	return values
}

func cloneOperator(record domain.OperatorRecord) domain.OperatorRecord {
	record.Roles = cloneRoleStrings(record.Roles)
	return record
}

// cloneRoleStrings preserves a non-nil empty slice so responses render an
// operator without roles as "roles": [] instead of null.
func cloneRoleStrings(roles []string) []string {
	cloned := make([]string, len(roles))
	copy(cloned, roles)
	return cloned
}
