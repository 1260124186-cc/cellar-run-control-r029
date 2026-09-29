package httpapi

import (
	"net/http"
	"strconv"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/policyz"
	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/service"
)

type grantRoleRequest struct {
	Role string `json:"role"`
}

func registerAuthorizationRoutes(mux *http.ServeMux, app *service.Service) {
	mux.HandleFunc("GET /v1/policy/roles", func(response http.ResponseWriter, _ *http.Request) {
		roles := policyz.KnownRoles()
		type roleDescription struct {
			Role        policyz.Role         `json:"role"`
			Permissions []policyz.Permission `json:"permissions"`
		}
		descriptions := make([]roleDescription, 0, len(roles))
		for _, role := range roles {
			permissions, _ := policyz.RolePermissions(role)
			descriptions = append(descriptions, roleDescription{
				Role:        role,
				Permissions: permissions,
			})
		}
		writeJSON(response, http.StatusOK, map[string]any{"roles": descriptions})
	})

	mux.HandleFunc("GET /v1/operators", func(response http.ResponseWriter, request *http.Request) {
		operators, err := app.ListOperators(operatorFromRequest(request))
		if err != nil {
			writeDomainError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"operators": operators})
	})

	mux.HandleFunc("GET /v1/operators/{id}", func(response http.ResponseWriter, request *http.Request) {
		operator, err := app.GetOperator(operatorFromRequest(request), request.PathValue("id"))
		if err != nil {
			writeDomainError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, operator)
	})

	mux.HandleFunc("PUT /v1/operators/{id}/roles/{role}", func(response http.ResponseWriter, request *http.Request) {
		operatorID, ok := requireOperator(response, request)
		if !ok {
			return
		}
		view, err := app.GrantRole(operatorID,
			request.PathValue("id"), policyz.Role(request.PathValue("role")))
		if err != nil {
			writeDomainError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, view)
	})

	mux.HandleFunc("POST /v1/operators/{id}/roles", func(response http.ResponseWriter, request *http.Request) {
		operatorID, ok := requireOperator(response, request)
		if !ok {
			return
		}
		body, err := decodeJSON[grantRoleRequest](response, request)
		if !handleDecode(response, err) {
			return
		}
		view, err := app.GrantRole(operatorID,
			request.PathValue("id"), policyz.Role(body.Role))
		if err != nil {
			writeDomainError(response, err)
			return
		}
		writeJSON(response, http.StatusCreated, view)
	})

	mux.HandleFunc("DELETE /v1/operators/{id}/roles/{role}", func(response http.ResponseWriter, request *http.Request) {
		operatorID, ok := requireOperator(response, request)
		if !ok {
			return
		}
		view, err := app.RevokeRole(operatorID,
			request.PathValue("id"), policyz.Role(request.PathValue("role")))
		if err != nil {
			writeDomainError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, view)
	})

	mux.HandleFunc("GET /v1/authorization/audit", func(response http.ResponseWriter, request *http.Request) {
		limit := 0
		if raw := request.URL.Query().Get("limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil {
				writeDomainError(response, domainFieldLimitError())
				return
			}
			limit = parsed
		}
		events, err := app.ListAuditEvents(operatorFromRequest(request), limit)
		if err != nil {
			writeDomainError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"events": events})
	})
}

func domainFieldLimitError() error {
	return domain.FieldError(domain.CodeInvalidInput, "limit",
		"must be a positive integer")
}
