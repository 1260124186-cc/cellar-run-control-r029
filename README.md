# Cellar Run Control

Cellar Run Control is a local Go HTTP service for coordinating a small
production cellar. It keeps formula approval, vessel availability, active
fermentation runs, gravity observations, conditioning, completion metrics, and
vessel cleaning in one deterministic process.

This repository is a healthy initialization baseline. It has no intentional
defects and no automated test suite. Tests are intentionally deferred to a
later engineering task; the production workflow checks in this repository
remain available for immediate build and behavior verification.

## Requirements

- Go 1.23 or later
- A writable local data directory
- No database, network service, or third-party module

## Build And Run

Build every package:

```bash
go build ./...
```

Start the service:

```bash
go run ./cmd/fermentctl serve
```

The default address is `127.0.0.1:8088`. The default snapshot directory is
`./data`.

Environment variables:

- `CELLAR_CONTROL_ADDR`: HTTP listen address.
- `CELLAR_CONTROL_DATA_DIR`: directory containing `state.json` and
  `authorization.json`.

Example:

```bash
CELLAR_CONTROL_ADDR=127.0.0.1:9099 \
CELLAR_CONTROL_DATA_DIR=/tmp/cellar-control \
go run ./cmd/fermentctl serve
```

## Directory Structure

```text
cmd/fermentctl                 service and workflow-check executable
internal/clock                 time boundary
internal/config                environment configuration
internal/domain                entities, validation, transitions, metrics
internal/httpapi               HTTP routes, JSON decoding, errors
internal/policyz               roles, permissions, conflict rules, decisions
internal/service               use-case orchestration
internal/storage               revisioned snapshot persistence
internal/workflowcheck         real HTTP production checks
```

## Public API

Health:

- `GET /healthz`

Formula workflow:

- `POST /v1/formulas`
- `GET /v1/formulas`
- `GET /v1/formulas/{id}`
- `PUT /v1/formulas/{id}/steps`
- `POST /v1/formulas/{id}/approve`
- `POST /v1/formulas/{id}/retire`

Vessel workflow:

- `POST /v1/vessels`
- `GET /v1/vessels`
- `GET /v1/vessels/{id}`
- `POST /v1/vessels/{id}/finish-cleaning`
- `POST /v1/vessels/{id}/retire`

Run workflow:

- `POST /v1/runs`
- `GET /v1/runs`
- `GET /v1/runs/{id}`
- `POST /v1/runs/{id}/reserve`
- `POST /v1/runs/{id}/start`
- `POST /v1/runs/{id}/observations`
- `POST /v1/runs/{id}/conditioning`
- `POST /v1/runs/{id}/complete`
- `POST /v1/runs/{id}/abort`

Writes accept an optional `X-Expected-Version` header. Errors use a stable
shape:

```json
{
  "error": {
    "code": "revision_conflict",
    "detail": "the aggregate version does not match X-Expected-Version",
    "field": ""
  }
}
```

## Role-Based Authorization

Every business request identifies its operator with the `X-Operator-ID`
header. The service derives the caller's permissions from the roles assigned
to that identity. A missing or blank identity fails closed with
`unauthenticated`; an operator without an assignment, with an unknown role, or
with conflicting roles fails closed with `forbidden`, `unknown_role`, or
`role_conflict` respectively. Authorization runs before any business
validation or write, so a rejected request never changes business state.

Roles and the operational surfaces they unlock:

- `planner` — planning: create formulas, set steps, approve and retire them.
- `operator` — containers: register vessels, plan runs, reserve, start, and
  abort them.
- `observer` — observations and completion: append gravity observations and
  move runs through conditioning and completion.
- `admin` — all operational surfaces plus role administration.

Operational roles are mutually exclusive: a grant that would create a
separation-of-duties conflict is rejected stably and leaves the existing
assignment intact. If a conflicting assignment is ever present in durable
state, every later decision for that operator fails closed.

Role assignments and the append-only audit trail are stored in
`authorization.json`, independent of business state. A grant or revocation is
durable before the next request is served and survives restart; the revocation
fact itself is also retained in the audit trail. Role changes have no cache,
so they take effect on the next request.

A fresh data directory seeds the bootstrap administrator `cellar-admin`.
Administration and policy endpoints:

- `GET /v1/policy/roles` — the role-to-permission table (no identity needed).
- `GET /v1/operators` — current assignments (requires `role.read`).
- `GET /v1/operators/{id}` — one operator's roles.
- `PUT /v1/operators/{id}/roles/{role}` — grant a role (requires
  `role.assign`).
- `POST /v1/operators/{id}/roles` — grant a role from a JSON body
  (`{"role": "observer"}`).
- `DELETE /v1/operators/{id}/roles/{role}` — revoke a role.
- `GET /v1/authorization/audit?limit=N` — most recent audit facts, newest
  first (requires `role.read`).

Authorization error codes: `unauthenticated` (401), `forbidden`,
`unknown_role`, `role_conflict` (403), `role_already_assigned`,
`role_not_assigned` (409), and `operator_not_found` (404).

## Workflow Checks

Run each production workflow check separately:

```bash
go run ./cmd/fermentctl check formula-approval
go run ./cmd/fermentctl check vessel-run-lifecycle
go run ./cmd/fermentctl check observations-completion
```

Each check creates a temporary snapshot directory, starts the real HTTP
handler on a loopback listener, issues JSON requests, verifies success and
failure behavior, and removes its temporary data.

## Persistence And Recovery

The service stores a complete revisioned snapshot at
`<data-directory>/state.json`. A write creates a temporary file in the same
directory, commits the encoded bytes durably, closes the handle, and renames
the result over the previous snapshot. The in-memory snapshot is replaced only
after that operation succeeds.

Role assignments and the authorization audit trail are stored independently at
`<data-directory>/authorization.json` using the same atomic commit, so
configuration and revocation facts cannot be lost by a crash or restart.

On startup, an existing snapshot is decoded and normalized. Unknown or
conflicting map indexes are not silently invented; invalid JSON or a negative
revision stops the process before HTTP serving begins.

## Repair-Ready Boundaries

The baseline intentionally keeps several independent behavior surfaces visible
for later engineering evaluation:

- formula name normalization and duplicate detection;
- target gravity and process-step range validation;
- aggregate version conflict checks;
- atomic vessel reservation and release;
- run state transition guards;
- observation sequence and time ordering;
- gravity movement and range checks;
- metric calculation and rounding;
- durable snapshot replacement and startup normalization.

These are production mechanisms, not injected defects. A later task can add
automated tests or request a focused repair without changing the public API.

## Test Boundary

This stage does not create unit tests, integration tests, test fixtures, or an
E2E suite. The later test task owns systematic coverage of validation limits,
state transitions, concurrency, persistence failures, and numeric edge cases.

## Scope

The service does not control physical equipment, authenticate remote users,
send notifications, expose a browser interface, or replicate data across
processes. It is intended for a trusted local network or an internal adapter.
