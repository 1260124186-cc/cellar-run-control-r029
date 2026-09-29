package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/1260124186-cc/solo-0016-cellar-run-control/internal/domain"
)

const (
	maxRequestBody   = 1 << 20
	operatorIDHeader = "X-Operator-ID"
)

type errorBody struct {
	Code   domain.Code `json:"code"`
	Detail string      `json:"detail"`
	Field  string      `json:"field,omitempty"`
}

type errorResponse struct {
	Error errorBody `json:"error"`
}

func decodeJSON[T any](response http.ResponseWriter, request *http.Request) (T, error) {
	var value T
	if request.Body == nil {
		return value, domain.NewError(domain.CodeInvalidInput, "request body is required")
	}
	body := http.MaxBytesReader(response, request.Body, maxRequestBody)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, decodeError(err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return value, domain.NewError(domain.CodeInvalidInput,
				"request body must contain one JSON object")
		}
		return value, decodeError(err)
	}
	return value, nil
}

func decodeError(err error) error {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		return domain.NewError(domain.CodeInvalidInput, "request body exceeds 1 MiB")
	}
	return domain.FieldError(domain.CodeInvalidInput, "body",
		"must be valid JSON with known fields")
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeDomainError(response http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	body := errorBody{
		Code:   domain.CodeStorage,
		Detail: "internal service failure",
	}
	var domainErr *domain.Error
	if errors.As(err, &domainErr) {
		body.Code = domainErr.Code
		body.Detail = domainErr.Message
		body.Field = domainErr.Field
		status = statusForCode(domainErr.Code)
	}
	writeJSON(response, status, errorResponse{Error: body})
}

func statusForCode(code domain.Code) int {
	switch code {
	case domain.CodeInvalidInput:
		return http.StatusBadRequest
	case domain.CodeFormulaNotFound, domain.CodeVesselNotFound, domain.CodeRunNotFound,
		domain.CodeOperatorNotFound:
		return http.StatusNotFound
	case domain.CodeFormulaNameConflict, domain.CodeFormulaState,
		domain.CodeFormulaInUse, domain.CodeVesselConflict,
		domain.CodeVesselUnavailable, domain.CodeVesselState,
		domain.CodeRunConflict, domain.CodeRunState,
		domain.CodeObservationConflict,
		domain.CodeRoleAlreadyAssigned, domain.CodeRoleNotAssigned:
		return http.StatusConflict
	case domain.CodeRevisionConflict:
		return http.StatusPreconditionFailed
	case domain.CodeUnauthenticated:
		return http.StatusUnauthorized
	case domain.CodeForbidden, domain.CodeUnknownRole, domain.CodeRoleConflict:
		return http.StatusForbidden
	case domain.CodeStorage:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

func expectedVersion(request *http.Request) (*int64, error) {
	value := request.Header.Get("X-Expected-Version")
	if value == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 1 {
		return nil, domain.FieldError(domain.CodeInvalidInput,
			"X-Expected-Version", "must be a positive integer")
	}
	return &parsed, nil
}

// operatorFromRequest extracts the caller identity from X-Operator-ID. The
// service resolves roles from this identity; a missing or blank header yields
// an empty string and the service fails closed with unauthenticated.
func operatorFromRequest(request *http.Request) string {
	return strings.TrimSpace(request.Header.Get(operatorIDHeader))
}

// requireOperator is the HTTP entry guard for business writes. It rejects a
// missing or blank X-Operator-ID before the request body is decoded or any
// service method runs, so an unauthenticated request can never reach a
// business write. It returns false after writing the response.
func requireOperator(response http.ResponseWriter, request *http.Request) (string, bool) {
	operatorID := operatorFromRequest(request)
	if operatorID == "" {
		writeDomainError(response, domain.NewError(domain.CodeUnauthenticated,
			"request is missing an operator identity"))
		return "", false
	}
	return operatorID, true
}

func handleDecode(response http.ResponseWriter, err error) bool {
	if err == nil {
		return true
	}
	writeDomainError(response, err)
	return false
}
