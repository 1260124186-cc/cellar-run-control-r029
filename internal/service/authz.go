package service

import (
	"errors"
	"strings"
	"time"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/policyz"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/storage"
)

// BootstrapAdminID is the identity seeded with the admin role on a fresh data
// directory. It lets the first administrator assign roles; every later change
// goes through the authenticated admin API.
const BootstrapAdminID = "cellar-admin"

// RoleView is the stable JSON representation of an operator's roles.
type RoleView struct {
	OperatorID string         `json:"operator_id"`
	Roles      []policyz.Role `json:"roles"`
}

// AuditEventView is the stable JSON representation of an audit fact.
type AuditEventView struct {
	ID         string                 `json:"id"`
	OccurredAt time.Time              `json:"occurred_at"`
	Type       policyz.EventType      `json:"type"`
	ActorID    string                 `json:"actor_id"`
	TargetID   string                 `json:"target_id,omitempty"`
	Role       policyz.Role           `json:"role,omitempty"`
	Permission policyz.Permission     `json:"permission,omitempty"`
	Reason     policyz.DecisionReason `json:"reason,omitempty"`
	Detail     string                 `json:"detail,omitempty"`
	Resource   string                 `json:"resource,omitempty"`
}

// ensureBootstrap seeds the initial administrator exactly once. The seed and
// its audit fact are committed atomically, so a crash after seeding cannot
// leave an assignment without its audit record.
func (s *Service) ensureBootstrap(now time.Time) error {
	alreadyBootstrapped := false
	if err := s.authz.View(func(state policyz.State) error {
		alreadyBootstrapped = state.BootstrappedAt != (time.Time{})
		return nil
	}); err != nil {
		return err
	}
	if alreadyBootstrapped {
		return nil
	}
	return s.authz.Update(func(state *policyz.State) error {
		if state.BootstrappedAt != (time.Time{}) {
			return nil
		}
		if _, exists := state.Assignments[BootstrapAdminID]; !exists {
			state.Assignments[BootstrapAdminID] = []policyz.Role{policyz.RoleAdmin}
		}
		state.BootstrapAdmin = BootstrapAdminID
		state.BootstrappedAt = now.UTC()
		eventID, err := generateEntityID("audit")
		if err != nil {
			return err
		}
		appendAudit(state, policyz.AuditEvent{
			ID:         eventID,
			OccurredAt: now.UTC(),
			Type:       policyz.EventBootstrap,
			ActorID:    BootstrapAdminID,
			TargetID:   BootstrapAdminID,
			Role:       policyz.RoleAdmin,
			Detail:     "initial administrator role seeded",
		})
		return nil
	})
}

// Authorize derives the caller's permissions for permission and either allows
// the caller to proceed or returns a stable domain error. Every denial is
// persisted as an audit fact before the error is returned, so unknown roles,
// conflicts, and over-privileged attempts remain auditable. A denial performs
// no business mutation: callers invoke this before any business write.
func (s *Service) Authorize(
	operatorID string,
	permission policyz.Permission,
	resource string,
) error {
	var decision policyz.Decision
	if err := s.authz.View(func(state policyz.State) error {
		decision = state.Resolve(operatorID, permission)
		return nil
	}); err != nil {
		return err
	}
	if decision.Allowed() {
		return nil
	}
	return s.recordDenial(decision, permission, resource)
}

func (s *Service) recordDenial(
	decision policyz.Decision,
	permission policyz.Permission,
	resource string,
) error {
	denied := s.denialError(decision, permission)
	eventType := policyz.EventAccessDenied
	switch {
	case strings.HasPrefix(resource, "DELETE "):
		eventType = policyz.EventRoleRevocationDenied
	case permission == policyz.PermRoleAssign:
		eventType = policyz.EventRoleGrantRejected
	}
	now := s.clock.Now()
	if auditErr := s.authz.Update(func(state *policyz.State) error {
		eventID, idErr := generateEntityID("audit")
		if idErr != nil {
			return idErr
		}
		appendAudit(state, policyz.AuditEvent{
			ID:         eventID,
			OccurredAt: now.UTC(),
			Type:       eventType,
			ActorID:    decision.OperatorID,
			Permission: permission,
			Reason:     decision.Reason,
			Role:       decision.Role,
			Detail:     denied.Error(),
			Resource:   resource,
		})
		return nil
	}); auditErr != nil {
		// Persisting the audit fact is part of the stable denial contract; if
		// it fails, fail closed with a storage error rather than allowing an
		// unaudited request to reach the business layer.
		return domain.NewError(domain.CodeStorage, auditErr.Error())
	}
	return denied
}

func (s *Service) denialError(
	decision policyz.Decision,
	permission policyz.Permission,
) error {
	switch decision.Reason {
	case policyz.ReasonNoIdentity:
		return domain.NewError(domain.CodeUnauthenticated,
			"request is missing an operator identity")
	case policyz.ReasonUnknownOperator:
		return domain.NewError(domain.CodeForbidden,
			"operator has no assigned roles")
	case policyz.ReasonUnknownRole:
		return domain.NewError(domain.CodeUnknownRole,
			"operator carries an unknown role: "+string(decision.Role))
	case policyz.ReasonConflictingRoles:
		return domain.NewError(domain.CodeRoleConflict,
			"operator holds conflicting roles: "+
				string(decision.Role)+" and "+string(decision.OtherRole))
	case policyz.ReasonPermissionDenied:
		return domain.NewError(domain.CodeForbidden,
			"operator lacks permission "+string(permission))
	default:
		return domain.NewError(domain.CodeForbidden,
			"authorization failed for permission "+string(permission))
	}
}

// GrantRole assigns role to targetID. The caller needs role.assign. Unknown
// roles and separation-of-duties conflicts are rejected with stable codes and
// audit facts; the assignment is only committed when fully valid.
func (s *Service) GrantRole(
	operatorID string,
	targetID string,
	role policyz.Role,
) (RoleView, error) {
	target := normalizeOperatorID(targetID)
	if target == "" {
		return RoleView{}, domain.FieldError(domain.CodeInvalidInput,
			"operator_id", "must identify an operator")
	}
	if err := s.Authorize(operatorID, policyz.PermRoleAssign, "POST /v1/operators/{id}/roles"); err != nil {
		return RoleView{}, err
	}
	role = policyz.NormalizeRole(string(role))
	if !policyz.IsKnownRole(role) {
		if err := s.recordAdministrativeDenial(operatorID, target, role,
			policyz.EventRoleGrantRejected, policyz.ReasonUnknownRole,
			"grant of unknown role "+string(role)); err != nil {
			return RoleView{}, err
		}
		return RoleView{}, domain.NewError(domain.CodeUnknownRole,
			"role is not defined in the policy table")
	}

	var resulting []policyz.Role
	var rejected error
	err := s.authz.Update(func(state *policyz.State) error {
		assigned := state.Assignments[target]
		for _, existing := range assigned {
			if existing == role {
				rejected = domain.NewError(domain.CodeRoleAlreadyAssigned,
					"operator already holds role "+string(role))
				break
			}
		}
		if rejected == nil {
			if conflicting := state.ConflictWithExisting(target, role); conflicting != "" {
				rejected = domain.NewError(domain.CodeRoleConflict,
					"role "+string(role)+" conflicts with existing role "+string(conflicting))
			}
		}
		eventID, err := generateEntityID("audit")
		if err != nil {
			return err
		}
		event := policyz.AuditEvent{
			ID:         eventID,
			OccurredAt: s.clock.Now().UTC(),
			ActorID:    normalizeOperatorID(operatorID),
			TargetID:   target,
			Role:       role,
		}
		if rejected != nil {
			// Commit the rejection audit without touching the assignment.
			event.Type = policyz.EventRoleGrantRejected
			event.Reason = policyz.DecisionReason(conflictReason(rejected))
			event.Detail = rejected.Error()
			appendAudit(state, event)
			resulting = append([]policyz.Role(nil), assigned...)
			return nil
		}
		state.Assignments[target] = append(assigned, role)
		event.Type = policyz.EventRoleGranted
		event.Reason = policyz.ReasonAllowed
		appendAudit(state, event)
		resulting = append([]policyz.Role(nil), state.Assignments[target]...)
		return nil
	})
	if err != nil {
		return RoleView{}, err
	}
	if rejected != nil {
		return RoleView{}, rejected
	}
	return RoleView{OperatorID: target, Roles: sortRoles(resulting)}, nil
}

// conflictReason maps an administrative rejection to the stable reason stored
// on its audit event.
func conflictReason(err error) string {
	var domainErr *domain.Error
	if errors.As(err, &domainErr) {
		switch domainErr.Code {
		case domain.CodeRoleConflict:
			return string(policyz.ReasonConflictingRoles)
		case domain.CodeUnknownRole:
			return string(policyz.ReasonUnknownRole)
		}
	}
	return string(policyz.ReasonPermissionDenied)
}

// RevokeRole removes role from targetID and records the revocation durably. The
// caller needs role.assign. The removal and the revocation fact commit in one
// atomic update, so a restart can neither restore the role nor lose the fact
// that it was revoked.
func (s *Service) RevokeRole(
	operatorID string,
	targetID string,
	role policyz.Role,
) (RoleView, error) {
	target := normalizeOperatorID(targetID)
	if target == "" {
		return RoleView{}, domain.FieldError(domain.CodeInvalidInput,
			"operator_id", "must identify an operator")
	}
	if err := s.Authorize(operatorID, policyz.PermRoleAssign, "DELETE /v1/operators/{id}/roles/{role}"); err != nil {
		return RoleView{}, err
	}
	role = policyz.NormalizeRole(string(role))
	if !policyz.IsKnownRole(role) {
		if err := s.recordAdministrativeDenial(operatorID, target, role,
			policyz.EventRoleRevocationDenied, policyz.ReasonUnknownRole,
			"revoke of unknown role "+string(role)); err != nil {
			return RoleView{}, err
		}
		return RoleView{}, domain.NewError(domain.CodeUnknownRole,
			"role is not defined in the policy table")
	}

	var resulting []policyz.Role
	var rejected error
	err := s.authz.Update(func(state *policyz.State) error {
		assigned := state.Assignments[target]
		kept := make([]policyz.Role, 0, len(assigned))
		hadRole := false
		for _, existing := range assigned {
			if existing == role {
				hadRole = true
				continue
			}
			kept = append(kept, existing)
		}
		eventID, err := generateEntityID("audit")
		if err != nil {
			return err
		}
		event := policyz.AuditEvent{
			ID:         eventID,
			OccurredAt: s.clock.Now().UTC(),
			ActorID:    normalizeOperatorID(operatorID),
			TargetID:   target,
			Role:       role,
		}
		if !hadRole {
			rejected = domain.NewError(domain.CodeRoleNotAssigned,
				"operator does not hold role "+string(role))
			event.Type = policyz.EventRoleRevocationDenied
			event.Reason = policyz.ReasonPermissionDenied
			event.Detail = rejected.Error()
			appendAudit(state, event)
			resulting = append([]policyz.Role(nil), assigned...)
			return nil
		}
		if len(kept) == 0 {
			delete(state.Assignments, target)
		} else {
			state.Assignments[target] = kept
		}
		event.Type = policyz.EventRoleRevoked
		event.Reason = policyz.ReasonAllowed
		event.Detail = "role revoked; effective on the next request"
		appendAudit(state, event)
		resulting = append([]policyz.Role(nil), state.Assignments[target]...)
		return nil
	})
	if err != nil {
		return RoleView{}, err
	}
	if rejected != nil {
		return RoleView{}, rejected
	}
	return RoleView{OperatorID: target, Roles: sortRoles(resulting)}, nil
}

// ListOperators returns all current role assignments in stable order. Requires
// role.read.
func (s *Service) ListOperators(operatorID string) ([]RoleView, error) {
	if err := s.Authorize(operatorID, policyz.PermRoleRead, "GET /v1/operators"); err != nil {
		return nil, err
	}
	var views []RoleView
	err := s.authz.View(func(state policyz.State) error {
		views = make([]RoleView, 0, len(state.Assignments))
		for _, id := range storage.SortedOperatorIDs(state) {
			views = append(views, RoleView{
				OperatorID: id,
				Roles:      sortRoles(append([]policyz.Role(nil), state.Assignments[id]...)),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return views, nil
}

// GetOperator returns one operator's roles. Requires role.read.
func (s *Service) GetOperator(operatorID, targetID string) (RoleView, error) {
	if err := s.Authorize(operatorID, policyz.PermRoleRead, "GET /v1/operators/{id}"); err != nil {
		return RoleView{}, err
	}
	target := normalizeOperatorID(targetID)
	var view RoleView
	err := s.authz.View(func(state policyz.State) error {
		roles, found := state.Assignments[target]
		if !found {
			return domain.NewError(domain.CodeOperatorNotFound, "operator was not found")
		}
		view = RoleView{OperatorID: target, Roles: sortRoles(append([]policyz.Role(nil), roles...))}
		return nil
	})
	if err != nil {
		return RoleView{}, err
	}
	return view, nil
}

// ListAuditEvents returns the most recent audit facts, newest first, bounded by
// limit. Requires role.read.
func (s *Service) ListAuditEvents(operatorID string, limit int) ([]AuditEventView, error) {
	if err := s.Authorize(operatorID, policyz.PermRoleRead, "GET /v1/authorization/audit"); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var views []AuditEventView
	err := s.authz.View(func(state policyz.State) error {
		total := len(state.Audit)
		start := total - limit
		if start < 0 {
			start = 0
		}
		views = make([]AuditEventView, 0, total-start)
		for i := total - 1; i >= start; i-- {
			event := state.Audit[i]
			views = append(views, AuditEventView{
				ID:         event.ID,
				OccurredAt: event.OccurredAt,
				Type:       event.Type,
				ActorID:    event.ActorID,
				TargetID:   event.TargetID,
				Role:       event.Role,
				Permission: event.Permission,
				Reason:     event.Reason,
				Detail:     event.Detail,
				Resource:   event.Resource,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return views, nil
}

// recordAdministrativeDenial appends an audit fact for an administrative
// request that was structurally invalid (unknown role), so these attempts stay
// auditable even though they never mutate assignments.
func (s *Service) recordAdministrativeDenial(
	operatorID, targetID string,
	role policyz.Role,
	eventType policyz.EventType,
	reason policyz.DecisionReason,
	detail string,
) error {
	now := s.clock.Now()
	if err := s.authz.Update(func(state *policyz.State) error {
		eventID, err := generateEntityID("audit")
		if err != nil {
			return err
		}
		appendAudit(state, policyz.AuditEvent{
			ID:         eventID,
			OccurredAt: now.UTC(),
			Type:       eventType,
			ActorID:    normalizeOperatorID(operatorID),
			TargetID:   targetID,
			Role:       role,
			Reason:     reason,
			Detail:     detail,
		})
		return nil
	}); err != nil {
		return domain.NewError(domain.CodeStorage, err.Error())
	}
	return nil
}

func normalizeOperatorID(value string) string {
	return strings.TrimSpace(value)
}

func sortRoles(roles []policyz.Role) []policyz.Role {
	result := append([]policyz.Role(nil), roles...)
	for i := 1; i < len(result); i++ {
		for j := i; j > 0 && result[j-1] > result[j]; j-- {
			result[j-1], result[j] = result[j], result[j-1]
		}
	}
	return result
}

// appendAudit is a service-level wrapper kept thin so callers do not depend on
// storage internals.
func appendAudit(state *policyz.State, event policyz.AuditEvent) {
	storage.AppendAuthzAudit(state, event)
}
