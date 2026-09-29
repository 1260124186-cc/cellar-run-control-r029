package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/clock"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/httpapi"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/policyz"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/service"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/storage"
)

var serverURL string
var dataDir string

type hc struct {
	operator string
}

func (c hc) do(method, path string, body any) (int, map[string]any) {
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, serverURL+path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.operator != "" {
		req.Header.Set("X-Operator-ID", c.operator)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var decoded map[string]any
	_ = json.Unmarshal(raw, &decoded)
	return resp.StatusCode, decoded
}

func code(body map[string]any) string {
	if e, ok := body["error"].(map[string]any); ok {
		if s, ok := e["code"].(string); ok {
			return s
		}
	}
	return ""
}

func must(cond bool, msg string) {
	if !cond {
		panic("FAILED: " + msg)
	}
}

func startServer() func() {
	store, err := storage.Open(dataDir)
	if err != nil {
		panic(err)
	}
	authz, err := storage.OpenAuthorization(dataDir)
	if err != nil {
		panic(err)
	}
	app, err := service.New(store, authz, clock.System{})
	if err != nil {
		panic(err)
	}
	server := httptest.NewServer(httpapi.NewHandler(app))
	serverURL = server.URL
	return server.Close
}

func approvedFormula(operator, name string) string {
	status, body := hc{operator}.do("POST", "/v1/formulas", map[string]any{
		"name": name, "style": "s", "target_original_gravity": 1.052,
		"target_final_gravity": 1.012, "max_fermentation_temp_c": 22.0,
		"minimum_days": 7, "maximum_days": 21,
	})
	must(status == 201, fmt.Sprintf("create formula status %d body %v", status, body))
	id := body["id"].(string)
	status, body = hc{operator}.do("PUT", "/v1/formulas/"+id+"/steps", map[string]any{
		"steps": []map[string]any{
			{"sequence": 1, "label": "a", "temperature_c": 66.0, "hold_minutes": 60},
		},
	})
	must(status == 200, fmt.Sprintf("steps status %d", status))
	status, body = hc{operator}.do("POST", "/v1/formulas/"+id+"/approve", nil)
	must(status == 200, fmt.Sprintf("approve status %d", status))
	return id
}

func main() {
	var err error
	dataDir, err = os.MkdirTemp("", "cellar-verify-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dataDir)

	admin := hc{"cellar-admin"}

	// --- Start #1 ---
	stop := startServer()

	// 1. Unauthenticated and unknown operator fail closed.
	status, body := hc{""}.do("POST", "/v1/formulas", map[string]any{"x": 1})
	must(status == 401 && code(body) == string(domain.CodeUnauthenticated), "anon -> 401")
	status, body = hc{"ghost"}.do("GET", "/v1/formulas", nil)
	must(status == 403 && code(body) == string(domain.CodeForbidden), "ghost -> 403")

	// 2. Grant planner; next request is authorized.
	status, body = admin.do("PUT", "/v1/operators/p1/roles/planner", nil)
	must(status == 200, fmt.Sprintf("grant planner %d %v", status, body))
	f1 := approvedFormula("p1", "Verify Ale")
	must(f1 != "", "planner works after grant (next request)")

	// 3. Over-privileged attempt: observer cannot plan; nothing is written.
	status, _ = admin.do("PUT", "/v1/operators/o1/roles/observer", nil)
	must(status == 200, "grant observer")
	status, body = hc{"o1"}.do("POST", "/v1/formulas", map[string]any{
		"name": "Observers Should Not Plan", "style": "s", "target_original_gravity": 1.052,
		"target_final_gravity": 1.012, "max_fermentation_temp_c": 22.0,
		"minimum_days": 7, "maximum_days": 21,
	})
	must(status == 403 && code(body) == string(domain.CodeForbidden), "observer plan -> 403")
	status, body = hc{"p1"}.do("GET", "/v1/formulas", nil)
	list := body["formulas"].([]any)
	must(len(list) == 1, "denied formula create left no write")

	// 4. Role conflict grant is rejected stably.
	status, body = admin.do("PUT", "/v1/operators/p1/roles/operator", nil)
	must(status == 403 && code(body) == string(domain.CodeRoleConflict),
		"conflicting grant -> role_conflict")
	status, body = admin.do("GET", "/v1/operators/p1", nil)
	roles := body["roles"].([]any)
	must(len(roles) == 1 && roles[0] == "planner", "conflict left assignment intact")

	// 5. Unknown role grant is rejected stably.
	status, body = admin.do("PUT", "/v1/operators/p1/roles/wizard", nil)
	must(status == 403 && code(body) == string(domain.CodeUnknownRole), "unknown role -> unknown_role")

	// 6. Revoke; next request loses access immediately.
	status, _ = admin.do("DELETE", "/v1/operators/p1/roles/planner", nil)
	must(status == 200, "revoke planner")
	status, body = hc{"p1"}.do("GET", "/v1/formulas", nil)
	must(status == 403 && code(body) == string(domain.CodeForbidden), "revoke effective next request")
	status, body = admin.do("GET", "/v1/operators/p1", nil)
	must(status == 404, "fully revoked operator disappears")

	// 7. Audit trail records denials, grants, revocations.
	status, body = admin.do("GET", "/v1/authorization/audit?limit=200", nil)
	must(status == 200, "audit readable")
	events := body["events"].([]any)
	var sawDenied, sawRevoked, sawConflict, sawUnknown bool
	for _, e := range events {
		ev := e.(map[string]any)
		t := ev["type"].(string)
		switch t {
		case "access_denied":
			sawDenied = true
		case "role_revoked":
			sawRevoked = true
		}
		if ev["reason"] == "conflicting_roles" {
			sawConflict = true
		}
		if ev["reason"] == "unknown_role" {
			sawUnknown = true
		}
	}
	must(sawDenied && sawRevoked, "audit has denial and revocation facts")
	must(sawConflict && sawUnknown, "audit records conflict and unknown role")

	// 8. Conflicting assignment in durable state fails closed on resolve.
	// Grant operator fresh, then hand-edit authorization.json to add a
	// conflicting planner role (simulating tampering/legacy state).
	status, _ = admin.do("PUT", "/v1/operators/v1/roles/operator", nil)
	must(status == 200, "grant operator for conflict-on-load")
	stop()

	authzPath := dataDir + "/authorization.json"
	raw, err := os.ReadFile(authzPath)
	if err != nil {
		panic(err)
	}
	var persisted map[string]any
	must(json.Unmarshal(raw, &persisted) == nil, "decode authz file")
	assignments := persisted["assignments"].(map[string]any)
	v1roles := assignments["v1"].([]any)
	assignments["v1"] = append(v1roles, "planner")
	raw2, _ := json.Marshal(persisted)
	must(os.WriteFile(authzPath, raw2, 0o644) == nil, "rewrite authz with conflict")

	// --- Start #2 (restart) ---
	stop = startServer()

	// 9. Revocation survived restart (p1 still forbidden).
	status, body = hc{"p1"}.do("GET", "/v1/formulas", nil)
	must(status == 403, "revocation survived restart")

	// 10. Config survived restart (o1 still observer, read works).
	status, _ = hc{"o1"}.do("GET", "/v1/formulas", nil)
	must(status == 200, "observer config survived restart")

	// 11. Conflicting roles resolve to stable role_conflict.
	status, body = hc{"v1"}.do("GET", "/v1/vessels", nil)
	must(status == 403 && code(body) == string(domain.CodeRoleConflict),
		"conflicting roles fail closed after restart")
	status, body = admin.do("GET", "/v1/authorization/audit?limit=1", nil)
	must(status == 200, "audit survived restart")

	// 12. Vessel/run lifecycle authorization and denied write integrity.
	status, _ = admin.do("PUT", "/v1/operators/op/roles/operator", nil)
	must(status == 200, "grant op operator")
	status, body = hc{"op"}.do("POST", "/v1/vessels", map[string]any{
		"code": "VSL-900", "capacity_liters": 200,
	})
	must(status == 201, "operator creates vessel")
	vesselID := body["id"].(string)

	// Recreate an approved formula via a new planner because p1 was revoked.
	status, _ = admin.do("PUT", "/v1/operators/p2/roles/planner", nil)
	must(status == 200, "grant p2")
	fid := approvedFormula("p2", "Restart Formula")
	status, body = hc{"op"}.do("POST", "/v1/runs", map[string]any{
		"code": "RUN-VERIFY", "formula_id": fid, "planned_volume_liters": 100,
	})
	must(status == 201, "operator plans run")
	runID := body["id"].(string)
	status, _ = hc{"op"}.do("POST", "/v1/runs/"+runID+"/reserve",
		map[string]any{"vessel_id": vesselID})
	must(status == 200, "operator reserves")
	status, _ = hc{"op"}.do("POST", "/v1/runs/"+runID+"/start", nil)
	must(status == 200, "operator starts")

	// Observer cannot abort (operator-only); run stays fermenting.
	status, body = hc{"o1"}.do("POST", "/v1/runs/"+runID+"/abort", nil)
	must(status == 403 && code(body) == string(domain.CodeForbidden), "observer abort denied")
	status, body = hc{"op"}.do("GET", "/v1/runs/"+runID, nil)
	must(body["state"] == "fermenting", "denied abort left run fermenting")

	// Policy table is inspectable.
	status, body = hc{""}.do("GET", "/v1/policy/roles", nil)
	must(status == 200, "policy table public")
	_ = policyz.RoleAdmin
	_ = domain.RunPlanned
	stop()
	fmt.Println("VERIFY: all authorization properties passed")
}
