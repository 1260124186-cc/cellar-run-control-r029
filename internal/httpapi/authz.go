package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/authz"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/service"
)

const operatorHeader = "X-Operator-ID"

// requireActor resolves the operator identity for a request. Every business
// write and every management route requires it; the response is a stable 401
// when the header is absent. A missing identity is itself an authorization
// attempt, so the denial is persisted to the audit log before the 401 is
// returned, exactly like a denial decided inside the service. A malformed
// identity spelling is bad input and is rejected with 400. Roles are never
// trusted from the request and are resolved by the service from the durable
// snapshot.
func requireActor(
	response http.ResponseWriter,
	request *http.Request,
	app *service.Service,
	required authz.Permission,
) (service.Actor, bool) {
	value := strings.ToLower(strings.TrimSpace(request.Header.Get(operatorHeader)))
	if value == "" {
		if err := app.RecordIdentityDenial(required); err != nil {
			writeDomainError(response, err)
			return service.Actor{}, false
		}
		writeDomainError(response, domain.NewError(domain.CodeIdentityRequired,
			operatorHeader+" header is required"))
		return service.Actor{}, false
	}
	if err := domain.ValidateOperatorID(value, operatorHeader); err != nil {
		writeDomainError(response, err)
		return service.Actor{}, false
	}
	return service.Actor{ID: value}, true
}

type assignRolesRequest struct {
	Roles []string `json:"roles"`
}

type revokeRolesRequest struct {
	Roles []string `json:"roles,omitempty"`
}

func registerOperatorRoutes(mux *http.ServeMux, app *service.Service) {
	mux.HandleFunc("GET /v1/operators", func(response http.ResponseWriter, request *http.Request) {
		actor, ok := requireActor(response, request, app, authz.PermAdmin)
		if !ok {
			return
		}
		operators, err := app.ListOperators(actor)
		if err != nil {
			writeDomainError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"operators": operators})
	})

	mux.HandleFunc("PUT /v1/operators/{id}/roles", func(response http.ResponseWriter, request *http.Request) {
		actor, ok := requireActor(response, request, app, authz.PermAdmin)
		if !ok {
			return
		}
		body, err := decodeJSON[assignRolesRequest](response, request)
		if !handleDecode(response, err) {
			return
		}
		expected, err := expectedVersion(request)
		if !handleDecode(response, err) {
			return
		}
		operator, err := app.AssignRoles(actor, request.PathValue("id"),
			service.AssignRolesInput{ExpectedVersion: expected, Roles: body.Roles})
		if err != nil {
			writeDomainError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, operator)
	})

	mux.HandleFunc("POST /v1/operators/{id}/revoke", func(response http.ResponseWriter, request *http.Request) {
		actor, ok := requireActor(response, request, app, authz.PermAdmin)
		if !ok {
			return
		}
		body, present, err := decodeOptionalJSON[revokeRolesRequest](response, request)
		if !handleDecode(response, err) {
			return
		}
		expected, err := expectedVersion(request)
		if !handleDecode(response, err) {
			return
		}
		var roles []string
		if present {
			roles = body.Roles
		}
		operator, err := app.RevokeRoles(actor, request.PathValue("id"),
			service.RevokeRolesInput{ExpectedVersion: expected, Roles: roles})
		if err != nil {
			writeDomainError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, operator)
	})

	mux.HandleFunc("GET /v1/audit", func(response http.ResponseWriter, request *http.Request) {
		actor, ok := requireActor(response, request, app, authz.PermAdmin)
		if !ok {
			return
		}
		events, err := app.ListAudit(actor, domain.MaxAuditEntries)
		if err != nil {
			writeDomainError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"audit": events})
	})
}

// decodeOptionalJSON decodes a JSON body that is allowed to be absent. present
// is false when the request carried no bytes.
func decodeOptionalJSON[T any](response http.ResponseWriter, request *http.Request) (T, bool, error) {
	var value T
	limited := http.MaxBytesReader(response, request.Body, maxRequestBody)
	buffered, err := io.ReadAll(limited)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return value, false, domain.NewError(domain.CodeInvalidInput, "request body exceeds 1 MiB")
		}
		return value, false, domain.FieldError(domain.CodeInvalidInput, "body", "could not be read")
	}
	if len(strings.TrimSpace(string(buffered))) == 0 {
		return value, false, nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(buffered)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, false, domain.FieldError(domain.CodeInvalidInput, "body",
			"must be valid JSON with known fields")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return value, false, domain.NewError(domain.CodeInvalidInput,
				"request body must contain one JSON object")
		}
		return value, false, domain.FieldError(domain.CodeInvalidInput, "body",
			"must be valid JSON with known fields")
	}
	return value, true, nil
}
