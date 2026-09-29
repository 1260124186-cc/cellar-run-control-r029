package policyz

import (
	"sort"
	"strings"
	"time"
)

// DecisionReason is the stable, machine-readable outcome of an authorization
// decision. It is recorded on audit events so denial causes remain auditable.
type DecisionReason string

const (
	ReasonAllowed          DecisionReason = "allowed"
	ReasonNoIdentity       DecisionReason = "no_identity"
	ReasonUnknownOperator  DecisionReason = "unknown_operator"
	ReasonUnknownRole      DecisionReason = "unknown_role"
	ReasonConflictingRoles DecisionReason = "conflicting_roles"
	ReasonPermissionDenied DecisionReason = "permission_denied"
)

// Decision captures the result of deriving permissions from an operator's
// identity and current role assignments.
type Decision struct {
	Reason      DecisionReason
	OperatorID  string
	Roles       []Role
	Permissions []Permission
	// Role reports an unknown role when Reason is ReasonUnknownRole, or the
	// first role of a conflicting pair when Reason is ReasonConflictingRoles.
	Role Role
	// OtherRole is the second role of a conflicting pair, if any.
	OtherRole Role
}

// Allowed reports whether the requested permission was granted.
func (d Decision) Allowed() bool {
	return d.Reason == ReasonAllowed
}

// EventType classifies persisted audit events.
type EventType string

const (
	EventBootstrap            EventType = "bootstrap"
	EventRoleGranted          EventType = "role_granted"
	EventRoleRevoked          EventType = "role_revoked"
	EventRoleGrantRejected    EventType = "role_grant_rejected"
	EventRoleRevocationDenied EventType = "role_revocation_denied"
	EventAccessDenied         EventType = "access_denied"
	EventAccessAllowed        EventType = "access_allowed"
)

// AuditEvent is one immutable, append-only authorization fact. Denied
// attempts, conflicts, unknown roles, grants, and revocations are all recorded
// so the security posture is auditable after restart.
type AuditEvent struct {
	ID         string         `json:"id"`
	OccurredAt time.Time      `json:"occurred_at"`
	Type       EventType      `json:"type"`
	ActorID    string         `json:"actor_id"`
	TargetID   string         `json:"target_id,omitempty"`
	Role       Role           `json:"role,omitempty"`
	Permission Permission     `json:"permission,omitempty"`
	Reason     DecisionReason `json:"reason,omitempty"`
	Detail     string         `json:"detail,omitempty"`
	Resource   string         `json:"resource,omitempty"`
}

// State is the persisted authorization configuration. It holds operator role
// assignments and the append-only audit trail. Revocation is represented by
// removing the role from the assignment and by a durable role_revoked event,
// so a restart can neither restore a revoked role nor erase the fact that it
// was revoked.
type State struct {
	Revision       int64             `json:"revision"`
	UpdatedAt      time.Time         `json:"updated_at"`
	BootstrappedAt time.Time         `json:"bootstrapped_at,omitempty"`
	BootstrapAdmin string            `json:"bootstrap_admin,omitempty"`
	Assignments    map[string][]Role `json:"assignments"`
	Audit          []AuditEvent      `json:"audit"`
}

// EmptyState returns an initialized, never-bootstrapped authorization state.
func EmptyState() State {
	return State{
		Assignments: map[string][]Role{},
		Audit:       []AuditEvent{},
	}
}

// Clone returns a deep copy so callers can mutate it without sharing storage.
func (s State) Clone() State {
	cloned := s
	cloned.Assignments = make(map[string][]Role, len(s.Assignments))
	for operatorID, roles := range s.Assignments {
		copiedRoles := append([]Role(nil), roles...)
		cloned.Assignments[operatorID] = copiedRoles
	}
	if s.Audit != nil {
		cloned.Audit = append([]AuditEvent(nil), s.Audit...)
	}
	return cloned
}

// RolesFor returns the sorted, de-duplicated roles currently assigned to
// operatorID. A missing or empty assignment yields nil.
func (s State) RolesFor(operatorID string) []Role {
	roles := append([]Role(nil), s.Assignments[operatorID]...)
	roles = uniqueSortedRoles(roles)
	return roles
}

// HasRole reports whether operatorID currently holds role.
func (s State) HasRole(operatorID string, role Role) bool {
	for _, assigned := range s.Assignments[operatorID] {
		if assigned == role {
			return true
		}
	}
	return false
}

// Resolve derives an authorization decision for operatorID requesting
// permission. It is a pure function over State, so its outcome is stable and
// independent of call order. Fail-closed ordering is:
//
//  1. missing/blank identity,
//  2. operator with no assignment,
//  3. assignment containing an unknown role,
//  4. assignment containing conflicting roles,
//  5. missing permission.
func (s State) Resolve(operatorID string, permission Permission) Decision {
	trimmed := strings.TrimSpace(operatorID)
	decision := Decision{OperatorID: trimmed}
	if trimmed == "" {
		decision.Reason = ReasonNoIdentity
		return decision
	}
	roles, found := s.Assignments[trimmed]
	if !found || len(roles) == 0 {
		decision.Reason = ReasonUnknownOperator
		return decision
	}
	decision.Roles = uniqueSortedRoles(roles)

	granted := map[Permission]struct{}{}
	for _, role := range decision.Roles {
		permissions, known := RolePermissions(role)
		if !known {
			decision.Reason = ReasonUnknownRole
			decision.Role = role
			return decision
		}
		for _, permission := range permissions {
			granted[permission] = struct{}{}
		}
	}
	if conflict, other, ok := roleConflict(decision.Roles); ok {
		decision.Reason = ReasonConflictingRoles
		decision.Role = conflict
		decision.OtherRole = other
		return decision
	}
	decision.Permissions = make([]Permission, 0, len(granted))
	for permission := range granted {
		decision.Permissions = append(decision.Permissions, permission)
	}
	sort.Slice(decision.Permissions, func(i, j int) bool {
		return decision.Permissions[i] < decision.Permissions[j]
	})
	if _, ok := granted[permission]; !ok {
		decision.Reason = ReasonPermissionDenied
		return decision
	}
	decision.Reason = ReasonAllowed
	return decision
}

func uniqueSortedRoles(roles []Role) []Role {
	seen := map[Role]struct{}{}
	result := make([]Role, 0, len(roles))
	for _, role := range roles {
		if _, ok := seen[role]; ok {
			continue
		}
		seen[role] = struct{}{}
		result = append(result, role)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
