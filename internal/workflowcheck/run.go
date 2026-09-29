package workflowcheck

import (
	"fmt"
	"net/http/httptest"
	"os"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/clock"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/httpapi"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/policyz"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/service"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/storage"
)

// Operator identities used by the production checks. The seeded administrator
// grants each one a single role before the workflow runs, so every business
// call is authorized through the same role-to-permission path as production.
const (
	checkAdminID    = service.BootstrapAdminID
	checkPlannerID  = "check-planner"
	checkOperatorID = "check-operator"
	checkObserverID = "check-observer"
)

type actors struct {
	admin    *client
	planner  *client
	operator *client
	observer *client
}

func Run(name string) error {
	dataDir, err := os.MkdirTemp("", "cellar-run-check-*")
	if err != nil {
		return fmt.Errorf("create check directory: %w", err)
	}
	defer os.RemoveAll(dataDir)

	store, err := storage.Open(dataDir)
	if err != nil {
		return err
	}
	authz, err := storage.OpenAuthorization(dataDir)
	if err != nil {
		return err
	}
	app, err := service.New(store, authz, clock.System{})
	if err != nil {
		return err
	}
	server := httptest.NewServer(httpapi.NewHandler(app))
	defer server.Close()

	base := newClient(server.URL)
	team := actors{
		admin:    base.as(checkAdminID),
		planner:  base.as(checkPlannerID),
		operator: base.as(checkOperatorID),
		observer: base.as(checkObserverID),
	}
	if err := provisionCheckRoles(team); err != nil {
		return err
	}

	switch name {
	case "formula-approval":
		if err := formulaApproval(team); err != nil {
			return err
		}
	case "vessel-run-lifecycle":
		if err := vesselRunLifecycle(team); err != nil {
			return err
		}
	case "observations-completion":
		if err := observationsCompletion(team); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown workflow check %q", name)
	}
	fmt.Printf("workflow check passed: %s\n", name)
	return nil
}

// provisionCheckRoles assigns one operational role to each check identity and
// verifies that an unauthorized attempt is rejected before any business data
// exists. This exercises grant, conflict, and denial behavior on every check.
func provisionCheckRoles(team actors) error {
	grants := []struct {
		target string
		role   policyz.Role
	}{
		{checkPlannerID, policyz.RolePlanner},
		{checkOperatorID, policyz.RoleOperator},
		{checkObserverID, policyz.RoleObserver},
	}
	for _, grant := range grants {
		response, err := team.admin.call("PUT",
			"/v1/operators/"+grant.target+"/roles/"+string(grant.role), nil, nil)
		if err != nil {
			return err
		}
		if err := requireStatus(response, 200, "grant role "+string(grant.role)); err != nil {
			return err
		}
	}

	// A non-administrator cannot manage roles.
	denied, err := team.planner.call("PUT",
		"/v1/operators/"+checkPlannerID+"/roles/"+string(policyz.RoleAdmin), nil, nil)
	if err != nil {
		return err
	}
	if err := requireCode(denied, 403, "forbidden", "planner grants role"); err != nil {
		return err
	}

	// An unauthenticated business request is rejected without any write.
	anonymous := team.admin.as("")
	rejected, err := anonymous.call("POST", "/v1/formulas", nil, nil)
	if err != nil {
		return err
	}
	if err := requireCode(rejected, 401, "unauthenticated", "anonymous formula create"); err != nil {
		return err
	}
	return nil
}
