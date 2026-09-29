// Package authz defines the role-based permission catalog and the pure
// authorization decision used by the cellar service.
//
// Permissions are derived from an operator identity: the service maps an
// operator identifier to the roles held below, and roles grant permissions.
// The four operational permission classes are:
//
//   - formula:plan      - planning operations (create, configure, approve and
//     retire formulas);
//   - vessel:operate    - container operations (register vessels and drive run
//     reservation, start, abort and cleaning);
//   - observation:write - append gravity observations;
//   - run:complete      - move a run through conditioning and completion.
//
// A separate admin permission guards role assignment. This package holds no
// state and performs no I/O so that every decision is deterministic and can be
// re-evaluated from the durable snapshot on each request.
package authz

import (
	"errors"
	"sort"
	"strings"
)

// Role identifies a named set of permissions.
type Role string

const (
	RoleAdmin    Role = "admin"
	RolePlanner  Role = "planner"
	RoleOperator Role = "operator"
	RoleObserver Role = "observer"
)

// Permission names an operation class that a business entry point requires.
type Permission string

const (
	// PermAdmin covers role grants, revocations and audit review.
	PermAdmin Permission = "admin:manage"
	// PermFormulaPlan covers formula planning and approval operations.
	PermFormulaPlan Permission = "formula:plan"
	// PermVesselOperate covers container registration and run lifecycle
	// operations that reserve or move a vessel.
	PermVesselOperate Permission = "vessel:operate"
	// PermObserve covers appending gravity observations.
	PermObserve Permission = "observation:write"
	// PermComplete covers conditioning and run completion.
	PermComplete Permission = "run:complete"
)

// Reason explains a denial with a stable, audit-ready identifier.
type Reason string

const (
	ReasonIdentityRequired Reason = "identity_required"
	ReasonUnknownOperator  Reason = "unknown_operator"
	ReasonUnknownRole      Reason = "unknown_role"
	ReasonRoleConflict     Reason = "role_conflict"
	ReasonPermissionDenied Reason = "permission_denied"
)

const maxRolesPerOperator = 8

var roleCatalog = map[Role]struct {
	permissions []Permission
	operational bool
}{
	RoleAdmin:    {[]Permission{PermAdmin}, false},
	RolePlanner:  {[]Permission{PermFormulaPlan}, true},
	RoleOperator: {[]Permission{PermVesselOperate}, true},
	RoleObserver: {[]Permission{PermObserve, PermComplete}, true},
}

// conflictPairs enforces segregation of duties between operational roles: a
// single operator may not plan, operate vessels, and observe/completion the
// same production stream. Admin carries no operational permissions and is not
// part of the matrix.
var conflictPairs = map[[2]Role]bool{
	{RolePlanner, RoleOperator}:  true,
	{RolePlanner, RoleObserver}:  true,
	{RoleOperator, RoleObserver}: true,
}

// Roles returns the known role identifiers in sorted order.
func Roles() []Role {
	roles := make([]Role, 0, len(roleCatalog))
	for role := range roleCatalog {
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	return roles
}

// KnownRole reports whether role names a catalogued role.
func KnownRole(role string) bool {
	_, ok := roleCatalog[Role(role)]
	return ok
}

// RoleListError rejects a role assignment payload before it is persisted.
type RoleListError struct {
	// Kind is "empty", "too_many" or "unknown".
	Kind  string
	Value string
}

func (e *RoleListError) Error() string {
	switch e.Kind {
	case "empty":
		return "role list contains an empty role"
	case "too_many":
		return "role list exceeds the maximum number of roles per operator"
	default:
		return "role is not defined: " + e.Value
	}
}

// NormalizeRoles trims, lower-cases, de-duplicates and sorts role tokens.
// Empty tokens and oversized lists are malformed input; a non-empty token that
// is not a catalogued role is an unknown role.
func NormalizeRoles(tokens []string) ([]Role, error) {
	if len(tokens) > maxRolesPerOperator {
		return nil, &RoleListError{Kind: "too_many"}
	}
	seen := make(map[Role]bool, len(tokens))
	roles := make([]Role, 0, len(tokens))
	for _, token := range tokens {
		name := strings.ToLower(strings.TrimSpace(token))
		if name == "" {
			return nil, &RoleListError{Kind: "empty"}
		}
		role := Role(name)
		if !KnownRole(name) {
			return nil, &RoleListError{Kind: "unknown", Value: name}
		}
		if !seen[role] {
			seen[role] = true
			roles = append(roles, role)
		}
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	return roles, nil
}

// Conflict returns the first mutually-exclusive role pair in deterministic
// order. It returns ok=false when the role set is consistent. The conflict
// table keys are order-independent: the catalog is enumerated in sorted order
// and both pair orientations are matched so the table may list roles in any
// order.
func Conflict(roles []Role) (a, b Role, ok bool) {
	held := make(map[Role]bool, len(roles))
	for _, role := range roles {
		held[role] = true
	}
	catalog := Roles()
	for i, left := range catalog {
		for _, right := range catalog[i+1:] {
			conflicting := conflictPairs[[2]Role{left, right}] ||
				conflictPairs[[2]Role{right, left}]
			if conflicting && held[left] && held[right] {
				return left, right, true
			}
		}
	}
	return "", "", false
}

// EffectivePermissions returns the permission set granted by the given roles.
func EffectivePermissions(roles []Role) map[Permission]bool {
	permissions := make(map[Permission]bool)
	for _, role := range roles {
		for _, permission := range roleCatalog[role].permissions {
			permissions[permission] = true
		}
	}
	return permissions
}

// Decision is the deterministic result of evaluating one operation.
type Decision struct {
	Allowed    bool
	Reason     Reason
	Permission Permission
	Role       Role
	ConflictA  Role
	ConflictB  Role
}

// Decide derives an authorization decision from an operator identity and the
// roles recorded for that operator. registered=false means the identity does
// not map to any operator record. The check is pure: callers supply the
// persisted role list freshly read for each request.
func Decide(operatorID string, registered bool, roles []string, want Permission) Decision {
	decision := Decision{Permission: want}
	if strings.TrimSpace(operatorID) == "" {
		decision.Reason = ReasonIdentityRequired
		return decision
	}
	if !registered {
		decision.Reason = ReasonUnknownOperator
		return decision
	}
	held := make([]Role, 0, len(roles))
	for _, value := range roles {
		role := Role(value)
		if !KnownRole(value) {
			decision.Reason = ReasonUnknownRole
			decision.Role = role
			return decision
		}
		held = append(held, role)
	}
	if a, b, conflict := Conflict(held); conflict {
		decision.Reason = ReasonRoleConflict
		decision.ConflictA, decision.ConflictB = a, b
		return decision
	}
	if EffectivePermissions(held)[want] {
		decision.Allowed = true
		return decision
	}
	decision.Reason = ReasonPermissionDenied
	return decision
}

// AsError adapts malformed role-list errors for callers that only need the
// stable kind marker.
func IsUnknownRole(err error) bool {
	var listErr *RoleListError
	return errors.As(err, &listErr) && listErr.Kind == "unknown"
}
