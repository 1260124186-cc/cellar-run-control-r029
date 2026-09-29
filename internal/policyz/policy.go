// Package policyz defines the role-based authorization layer used to derive
// permissions from the operator identity presented on each request.
//
// The package is deliberately free of HTTP and storage dependencies: it models
// actors, roles, permissions, the role policy table, and authorization
// decisions. Persistence lives in internal/storage and request binding in
// internal/httpapi so the dependency direction stays
// cmd -> httpapi -> service/policyz -> domain.
package policyz

import (
	"sort"
	"strings"
)

// Permission identifies a single authorized business capability. Permissions
// are grouped around the four operational surfaces of the cellar: planning
// formulas, managing vessels and runs, recording observations, and finishing
// work. Read access is granted alongside the matching write surface so that an
// operator who performs work can also inspect it.
type Permission string

const (
	// Formula planning surface.
	PermFormulaPlan   Permission = "formula.plan"
	PermFormulaManage Permission = "formula.manage"
	PermFormulaRead   Permission = "formula.read"

	// Vessel and run container surface.
	PermVesselManage Permission = "vessel.manage"
	PermVesselRead   Permission = "vessel.read"
	PermRunPlan      Permission = "run.plan"
	PermRunControl   Permission = "run.control"
	PermRunRead      Permission = "run.read"

	// Observation surface.
	PermObservationWrite Permission = "observation.write"

	// Completion and lifecycle surface.
	PermRunComplete Permission = "run.complete"
	PermRunAbort    Permission = "run.abort"

	// Authorization administration surface.
	PermRoleAssign Permission = "role.assign"
	PermRoleRead   Permission = "role.read"
)

// Role is a stable role identifier assigned to an operator.
type Role string

const (
	// RolePlanner is the production planner: owns formula lifecycle.
	RolePlanner Role = "planner"
	// RoleOperator is the cellar operator: owns vessels and active runs.
	RoleOperator Role = "operator"
	// RoleObserver is the fermentation observer: records observations and
	// moves runs through conditioning and completion.
	RoleObserver Role = "observer"
	// RoleAdmin manages role assignments and may read the audit trail.
	RoleAdmin Role = "admin"
)

// KnownRoles lists every role understood by the policy table. The order is
// fixed and used to keep serialized output stable.
func KnownRoles() []Role {
	return []Role{RolePlanner, RoleOperator, RoleObserver, RoleAdmin}
}

// IsKnownRole reports whether value names a role in the policy table.
func IsKnownRole(value Role) bool {
	for _, role := range KnownRoles() {
		if role == value {
			return true
		}
	}
	return false
}

// NormalizeRole trims and lower-cases a role token so configuration input and
// request headers cannot smuggle duplicate role spellings.
func NormalizeRole(value string) Role {
	return Role(strings.ToLower(strings.TrimSpace(value)))
}

// rolePermissions is the immutable role -> permission policy table. A role not
// present here grants nothing.
var rolePermissions = map[Role]map[Permission]struct{}{
	RolePlanner: permissionSet(
		PermFormulaPlan, PermFormulaManage, PermFormulaRead,
		PermRunRead,
	),
	RoleOperator: permissionSet(
		PermVesselManage, PermVesselRead, PermRunPlan, PermRunControl, PermRunRead,
		PermRunAbort,
		PermFormulaRead,
	),
	RoleObserver: permissionSet(
		PermObservationWrite, PermRunComplete, PermRunRead,
		PermVesselRead,
		PermFormulaRead,
	),
	RoleAdmin: permissionSet(
		PermFormulaPlan, PermFormulaManage, PermFormulaRead,
		PermVesselManage, PermVesselRead,
		PermRunPlan, PermRunControl, PermRunRead, PermRunAbort,
		PermObservationWrite, PermRunComplete,
		PermRoleAssign, PermRoleRead,
	),
}

// RolePermissions returns a sorted copy of the permissions granted directly by
// role. An unknown role yields an empty slice and false.
func RolePermissions(role Role) ([]Permission, bool) {
	set, ok := rolePermissions[role]
	if !ok {
		return nil, false
	}
	result := make([]Permission, 0, len(set))
	for permission := range set {
		result = append(result, permission)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, true
}

func permissionSet(permissions ...Permission) map[Permission]struct{} {
	set := make(map[Permission]struct{}, len(permissions))
	for _, permission := range permissions {
		set[permission] = struct{}{}
	}
	return set
}
