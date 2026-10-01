// Package apiserver is the one implementation of the strict server
// interface generated from api/openapi.yaml (api/gen). The generated
// interface spans every operation of the contract, while each listener
// serves only some of them (health on the admin port, /v1 on the public
// one), so Server is composed of one handler per API group and each
// listener mounts the subset it serves with Mount. A work package that
// adds a group adds its handler interface here.
//
// It also holds the access rules of every operation (Authorize, WP-2):
// public operations (`security: []`), operations open to any console
// session (`x-session: any`), role operations (x-roles in the contract,
// Roles here, with the console realm unless an operation names
// another) and scope operations for machine tokens. The IdentifyFunc
// that resolves a request's identity is internal/authz's Authenticator
// in production; tests pass their own.
package apiserver
