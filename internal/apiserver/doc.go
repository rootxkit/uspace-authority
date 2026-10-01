// Package apiserver is the one implementation of the strict server
// interface generated from api/openapi.yaml (api/gen). The generated
// interface spans every operation of the contract, while each listener
// serves only some of them (health on the admin port, /v1 on the public
// one), so Server is composed of one handler per API group and each
// listener mounts the subset it serves with Mount. A work package that
// adds a group adds its handler interface here.
//
// It also holds the role check placeholder of WP-1: every /v1
// operation names its console roles (x-roles in the contract, Roles
// here) and RequireRole refuses a request whose identity lacks them.
// Until WP-2 (internal/authz) replaces the IdentifyFunc there is no
// session, so the production identity function refuses every request
// with 401 unauthenticated; tests pass their own.
package apiserver
