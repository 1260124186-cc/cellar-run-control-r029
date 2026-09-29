package policyz

// conflicts encodes separation-of-duties rules. A single operator must not
// simultaneously hold roles that let both sides of an independent control be
// performed by the same person. The matrix is symmetric: a grant that would
// create any pair listed here is rejected, and an existing conflicting
// assignment fails closed on every subsequent decision.
//
// Operational split in the cellar:
//   - planner designs and approves formulas;
//   - operator registers vessels and drives runs;
//   - observer independently records measurements and completes work;
//   - admin governs assignments and must not also hold an operational role.
var conflicts = map[Role]map[Role]struct{}{
	RolePlanner: {
		RoleOperator: {},
		RoleObserver: {},
		RoleAdmin:    {},
	},
	RoleOperator: {
		RolePlanner:  {},
		RoleObserver: {},
		RoleAdmin:    {},
	},
	RoleObserver: {
		RolePlanner:  {},
		RoleOperator: {},
		RoleAdmin:    {},
	},
	RoleAdmin: {
		RolePlanner:  {},
		RoleOperator: {},
		RoleObserver: {},
	},
}

// RolesConflict reports whether the two roles cannot be held together. The
// check is symmetric.
func RolesConflict(a, b Role) bool {
	if a == b {
		return false
	}
	set, ok := conflicts[a]
	if !ok {
		return false
	}
	_, ok = set[b]
	return ok
}

// roleConflict scans sorted roles for the first conflicting pair and returns
// both roles. The deterministic order keeps the decision and audit result
// stable regardless of map iteration.
func roleConflict(sortedRoles []Role) (Role, Role, bool) {
	for i := 0; i < len(sortedRoles); i++ {
		for j := i + 1; j < len(sortedRoles); j++ {
			if RolesConflict(sortedRoles[i], sortedRoles[j]) {
				return sortedRoles[i], sortedRoles[j], true
			}
		}
	}
	return "", "", false
}

// ConflictWithExisting returns the existing role that conflicts with candidate
// for operatorID, or "" when no conflict exists.
func (s State) ConflictWithExisting(operatorID string, candidate Role) Role {
	for _, assigned := range s.Assignments[operatorID] {
		if RolesConflict(assigned, candidate) {
			return assigned
		}
	}
	return ""
}
