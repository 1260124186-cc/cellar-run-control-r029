package workflowcheck

import (
	"fmt"
	"net/http/httptest"
	"os"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/clock"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/httpapi"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/service"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/storage"
)

// BootstrapAdmin is the initial administrator identity used by checks.
const BootstrapAdmin = "cellar-admin"

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
	app := service.New(store, clock.System{})
	if err := app.SeedBootstrapAdmin(BootstrapAdmin); err != nil {
		return err
	}
	server := httptest.NewServer(httpapi.NewHandler(app))
	defer server.Close()
	api := newClient(server.URL)
	if err := seedOperators(api); err != nil {
		return err
	}

	switch name {
	case "formula-approval":
		if err := formulaApproval(api); err != nil {
			return err
		}
	case "vessel-run-lifecycle":
		if err := vesselRunLifecycle(api); err != nil {
			return err
		}
	case "observations-completion":
		if err := observationsCompletion(api); err != nil {
			return err
		}
	case "role-access-control":
		if err := roleAccessControl(api); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown workflow check %q", name)
	}
	fmt.Printf("workflow check passed: %s\n", name)
	return nil
}

func seedOperators(api *client) error {
	admin := api.as(BootstrapAdmin)
	identities := map[string][]string{
		"planner":  {"planner"},
		"operator": {"operator"},
		"observer": {"observer"},
	}
	for id, roles := range identities {
		response, err := admin.call("PUT", "/v1/operators/"+id+"/roles",
			map[string]any{"roles": roles}, nil)
		if err != nil {
			return err
		}
		if err := requireStatus(response, 200, "grant "+id+" roles"); err != nil {
			return err
		}
	}
	return nil
}
