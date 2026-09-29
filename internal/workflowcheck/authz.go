package workflowcheck

import (
	"fmt"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
)

// roleAccessControl exercises the authorization layer end to end: role
// derivation, stable results for missing/unknown/conflicting roles, denial
// without a business write, next-request effect of grants and revocations, and
// the durable audit trail of denials and permission changes.
func roleAccessControl(api *client) error {
	admin := api.as(BootstrapAdmin)
	planner := api.as("planner")
	operator := api.as("operator")
	observer := api.as("observer")
	anonymous := api.as("")
	stranger := api.as("ghost-user")

	// A request without identity is rejected before any write with 401.
	missing, err := anonymous.call("POST", "/v1/formulas",
		createFormulaPayload("No Identity"), nil)
	if err != nil {
		return err
	}
	if err := requireCode(missing, 401, string(domain.CodeIdentityRequired),
		"reject anonymous write"); err != nil {
		return err
	}

	// An unregistered identity is a stable 403 unknown_operator.
	unregistered, err := stranger.call("POST", "/v1/formulas",
		createFormulaPayload("Unknown Operator"), nil)
	if err != nil {
		return err
	}
	if err := requireCode(unregistered, 403, string(domain.CodeUnknownOperator),
		"reject unregistered operator"); err != nil {
		return err
	}

	// A planner may plan but not operate a vessel. Permission boundaries hold
	// even though the identities are registered.
	created, err := planner.call("POST", "/v1/formulas",
		createFormulaPayload("Access Formula"), nil)
	if err != nil {
		return err
	}
	if err := requireStatus(created, 201, "planner creates formula"); err != nil {
		return err
	}

	crossRole, err := planner.call("POST", "/v1/vessels",
		map[string]any{"code": "VSL-909", "capacity_liters": 500.0}, nil)
	if err != nil {
		return err
	}
	if err := requireCode(crossRole, 403, string(domain.CodePermissionDenied),
		"planner cannot register a vessel"); err != nil {
		return err
	}

	// The rejected vessel request must not have left any business state.
	deniedVessel, err := operator.call("POST", "/v1/vessels",
		map[string]any{"code": "VSL-909", "capacity_liters": 500.0}, nil)
	if err != nil {
		return err
	}
	if err := requireStatus(deniedVessel, 201,
		"denied planner write left no vessel"); err != nil {
		return err
	}

	// An unknown role in an assignment is a stable 403 unknown_role and is not
	// persisted.
	unknownGrant, err := admin.call("PUT", "/v1/operators/bad-role/roles",
		map[string]any{"roles": []string{"brewmaster"}}, nil)
	if err != nil {
		return err
	}
	if err := requireCode(unknownGrant, 403, string(domain.CodeUnknownRole),
		"reject grant of unknown role"); err != nil {
		return err
	}

	// Mutually exclusive operational roles are rejected with role_conflict.
	conflicting, err := admin.call("PUT", "/v1/operators/conflicted/roles",
		map[string]any{"roles": []string{"planner", "operator"}}, nil)
	if err != nil {
		return err
	}
	if err := requireCode(conflicting, 403, string(domain.CodeRoleConflict),
		"reject conflicting roles"); err != nil {
		return err
	}

	// A newly granted operator takes effect on the next request.
	fresh := api.as("fresh-user")
	beforeGrant, err := fresh.call("GET", "/v1/operators", nil, nil)
	if err != nil {
		return err
	}
	if err := requireCode(beforeGrant, 403, string(domain.CodeUnknownOperator),
		"fresh operator blocked before grant"); err != nil {
		return err
	}
	grant, err := admin.call("PUT", "/v1/operators/fresh-user/roles",
		map[string]any{"roles": []string{"observer"}}, nil)
	if err != nil {
		return err
	}
	if err := requireStatus(grant, 200, "grant observer role"); err != nil {
		return err
	}

	// observer can observe/complete but cannot plan.
	planDenied, err := fresh.call("POST", "/v1/formulas",
		createFormulaPayload("Fresh Observer"), nil)
	if err != nil {
		return err
	}
	if err := requireCode(planDenied, 403, string(domain.CodePermissionDenied),
		"fresh observer cannot plan"); err != nil {
		return err
	}

	// A revocation takes effect on the next request and leaves an audit fact.
	revoke, err := admin.call("POST", "/v1/operators/fresh-user/revoke", nil, nil)
	if err != nil {
		return err
	}
	if err := requireStatus(revoke, 200, "revoke fresh operator roles"); err != nil {
		return err
	}
	afterRevoke, err := fresh.call("GET", "/v1/operators", nil, nil)
	if err != nil {
		return err
	}
	if err := requireCode(afterRevoke, 403, string(domain.CodePermissionDenied),
		"revoked operator blocked on next request"); err != nil {
		return err
	}

	// An operator cannot administer roles; the attempt is itself audited.
	nonAdminGrant, err := operator.call("PUT", "/v1/operators/intruder/roles",
		map[string]any{"roles": []string{"admin"}}, nil)
	if err != nil {
		return err
	}
	if err := requireCode(nonAdminGrant, 403, string(domain.CodePermissionDenied),
		"operator cannot grant admin"); err != nil {
		return err
	}
	auditResponse, err := admin.call("GET", "/v1/audit", nil, nil)
	if err != nil {
		return err
	}
	if err := requireStatus(auditResponse, 200, "admin reads audit log"); err != nil {
		return err
	}
	body := string(auditResponse.body)
	for _, want := range []string{
		domain.AuditActionDeny,
		string(domain.CodePermissionDenied),
		string(domain.CodeIdentityRequired),
		string(domain.CodeUnknownOperator),
		domain.AuditActionGrant,
		domain.AuditActionRevoke,
		domain.AuditActionBootstrapAdmin,
	} {
		if !containsString(body, want) {
			return fmt.Errorf("audit log missing stable record %q", want)
		}
	}

	// Non-admins cannot read the audit log.
	auditDenied, err := observer.call("GET", "/v1/audit", nil, nil)
	if err != nil {
		return err
	}
	if err := requireCode(auditDenied, 403, string(domain.CodePermissionDenied),
		"observer cannot read audit log"); err != nil {
		return err
	}

	// Reads of business data remain available to the integration client without
	// a role; authorization governs writes and management routes.
	readFormulas, err := anonymous.call("GET", "/v1/formulas", nil, nil)
	if err != nil {
		return err
	}
	if err := requireStatus(readFormulas, 200, "anonymous business read allowed"); err != nil {
		return err
	}
	return nil
}

func containsString(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
