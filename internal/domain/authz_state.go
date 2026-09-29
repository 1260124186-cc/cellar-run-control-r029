package domain

import (
	"regexp"
	"time"
)

// AuthorizationState is the durable, restorable part of the authorization
// layer. Operator records map an identity to roles; audit entries record
// permission changes and denials. Revocation is never represented by deleting
// an operator, so the fact of a revocation survives in the roles and audit
// history.
type AuthorizationState struct {
	Operators    map[string]OperatorRecord `json:"operators"`
	Audit        []AuditEvent              `json:"audit"`
	NextAuditSeq int64                     `json:"next_audit_seq"`
}

// OperatorRecord holds one identity and the roles currently assigned to it.
type OperatorRecord struct {
	ID        string    `json:"id"`
	Roles     []string  `json:"roles"`
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuditEvent is one append-only authorization fact.
type AuditEvent struct {
	Sequence   int64     `json:"sequence"`
	OccurredAt time.Time `json:"occurred_at"`
	// Actor is the identity performing the action. It is empty when a request
	// presented no identity.
	Actor string `json:"actor,omitempty"`
	// Action is one of "deny", "grant", "revoke", or "bootstrap_admin".
	Action string `json:"action"`
	// Target is the operator whose roles changed for grant/revoke actions.
	Target string `json:"target,omitempty"`
	// Permission is the permission required by a denied business request.
	Permission string `json:"permission,omitempty"`
	// Reason is the stable denial reason code.
	Reason string `json:"reason,omitempty"`
	// Roles is the resulting (grant) or removed (revoke) role set.
	Roles []string `json:"roles,omitempty"`
}

const (
	AuditActionDeny           = "deny"
	AuditActionGrant          = "grant"
	AuditActionRevoke         = "revoke"
	AuditActionBootstrapAdmin = "bootstrap_admin"
)

const MaxAuditEntries = 1000

var operatorIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)

// ValidateOperatorID enforces a stable identity spelling so audit records and
// role mappings cannot be confused by whitespace or casing.
func ValidateOperatorID(value, field string) error {
	if !operatorIDPattern.MatchString(value) {
		return FieldError(CodeInvalidInput, field,
			"must contain 2 to 64 lowercase letters, digits, dots, underscores, or hyphens")
	}
	return nil
}

func EmptyAuthorizationState() AuthorizationState {
	return AuthorizationState{
		Operators:    map[string]OperatorRecord{},
		Audit:        []AuditEvent{},
		NextAuditSeq: 1,
	}
}

func (a AuthorizationState) clone() AuthorizationState {
	cloned := AuthorizationState{
		Operators:    make(map[string]OperatorRecord, len(a.Operators)),
		Audit:        make([]AuditEvent, len(a.Audit)),
		NextAuditSeq: a.NextAuditSeq,
	}
	for id, operator := range a.Operators {
		operator.Roles = cloneStrings(operator.Roles)
		cloned.Operators[id] = operator
	}
	copy(cloned.Audit, a.Audit)
	for index := range cloned.Audit {
		cloned.Audit[index].Roles = cloneStrings(cloned.Audit[index].Roles)
	}
	return cloned
}

// cloneStrings copies a string slice while preserving a non-nil empty slice, so
// a role set that is empty (all roles revoked) serializes as [] rather than
// null across snapshot clones and restarts.
func cloneStrings(values []string) []string {
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

// AppendAudit assigns the next sequence, appends the event, and bounds the
// history by dropping the oldest entries while retaining the newest facts.
func (a *AuthorizationState) AppendAudit(event AuditEvent) AuditEvent {
	if a.NextAuditSeq <= 0 {
		a.NextAuditSeq = 1
	}
	event.Sequence = a.NextAuditSeq
	a.NextAuditSeq++
	a.Audit = append(a.Audit, event)
	if overflow := len(a.Audit) - MaxAuditEntries; overflow > 0 {
		a.Audit = append([]AuditEvent(nil), a.Audit[overflow:]...)
	}
	return event
}
