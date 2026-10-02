package tokens

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// JWKSCacheControl is the Cache-Control of the JWKS and the metadata.
const JWKSCacheControl = "public, max-age=300"

// Handler serves the token service (apiserver.TokenHandler and
// apiserver.OAuthAdminHandler).
type Handler struct {
	Service  *Service
	Registry *Registry
	Manager  *KeyManager
	Now      func() time.Time
}

var (
	_ apiserver.TokenHandler      = Handler{}
	_ apiserver.OAuthAdminHandler = Handler{}
)

func (h Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// RequestToken runs the client credentials grant.
func (h Handler) RequestToken(ctx context.Context, req gen.RequestTokenRequestObject) (gen.RequestTokenResponseObject, error) {
	tr := TokenRequest{RemoteIP: apiserver.RequestInfoFrom(ctx).RemoteIP}
	if b := req.Body; b != nil {
		tr.GrantType = b.GrantType
		tr.ClientID = deref(b.ClientId)
		tr.ClientSecret, tr.HasSecret = deref(b.ClientSecret), b.ClientSecret != nil
		tr.ClientAssertionType = deref(b.ClientAssertionType)
		tr.ClientAssertion = deref(b.ClientAssertion)
		tr.Scope = deref(b.Scope)
		tr.Audience, tr.HasAudience = deref(b.Audience), b.Audience != nil
		if b.Resource != nil {
			tr.Resources = *b.Resource
		}
	}
	resp, oerr := h.Service.Token(ctx, tr)
	if oerr != nil {
		return oauthResponse(oerr), nil
	}
	noStore, noCache := "no-store", "no-cache"
	return gen.RequestToken200JSONResponse{
		Body:    gen.TokenResponse{AccessToken: resp.AccessToken, TokenType: gen.TokenResponseTokenTypeBearer, ExpiresIn: resp.ExpiresIn, Scope: resp.Scope},
		Headers: gen.RequestToken200ResponseHeaders{CacheControl: &noStore, Pragma: &noCache},
	}, nil
}

// OAuthProblem renders e as the contract's OAuthProblem.
func OAuthProblem(e *OAuthError) gen.OAuthProblem {
	p := httpx.NewProblem(e.Status, e.Code, "", e.Description)
	instance := "/oauth/token"
	desc := e.Description
	return gen.OAuthProblem{
		Type: p.Type, Title: p.Title, Status: p.Status, Detail: &desc, Instance: &instance,
		Errors: []gen.FieldProblem{}, Error: gen.OAuthProblemError(e.Code), ErrorDescription: &desc,
	}
}

func oauthResponse(e *OAuthError) gen.RequestTokenResponseObject {
	body := OAuthProblem(e)
	switch e.Status {
	case http.StatusBadRequest:
		return gen.RequestToken400ApplicationProblemPlusJSONResponse{OAuthErrorApplicationProblemPlusJSONResponse: gen.OAuthErrorApplicationProblemPlusJSONResponse(body)}
	case http.StatusUnauthorized:
		return gen.RequestToken401ApplicationProblemPlusJSONResponse(body)
	case http.StatusTooManyRequests:
		secs := max(1, int(math.Ceil(e.RetryAfter.Seconds())))
		return gen.RequestToken429ApplicationProblemPlusJSONResponse{Body: body, Headers: gen.RequestToken429ResponseHeaders{RetryAfter: &secs}}
	default:
		p := httpx.NewProblem(e.Status, e.Code, "", e.Description)
		return gen.RequestTokendefaultApplicationProblemPlusJSONResponse{StatusCode: e.Status, Body: gen.Problem{
			Type: p.Type, Title: p.Title, Status: p.Status, Detail: &e.Description, Errors: []gen.FieldProblem{},
		}}
	}
}

// FormGuard refuses, before the grant runs, what RFC 6749 forbids of a
// token request: parameters in the query string (credentials would be
// logged with the URL, §2.3.1), a body that is not
// application/x-www-form-urlencoded, and a parameter sent twice (§3.2;
// resource may repeat, RFC 8707, and is judged by the grant). Each
// refusal is a token_refused event like any other.
func (h Handler) FormGuard() apiserver.Middleware {
	return func(f gen.StrictHandlerFunc, operationID string) gen.StrictHandlerFunc {
		if operationID != "RequestToken" {
			return f
		}
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
			var oerr *OAuthError
			mt, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
			switch {
			case r.URL.RawQuery != "":
				oerr = refuse(http.StatusBadRequest, ErrInvalidRequest, "parameters_in_query", "send the parameters in the request body, never in the URL")
			case !strings.EqualFold(strings.TrimSpace(mt), "application/x-www-form-urlencoded"):
				oerr = refuse(http.StatusBadRequest, ErrInvalidRequest, "content_type_wrong", "the body must be application/x-www-form-urlencoded")
			default:
				for name, vals := range r.PostForm {
					if len(vals) > 1 && name != "resource" {
						oerr = refuse(http.StatusBadRequest, ErrInvalidRequest, "parameter_repeated", "a parameter appears more than once: "+quote(name))
						break
					}
				}
			}
			if oerr == nil {
				return f(ctx, w, r, request)
			}
			tr := TokenRequest{ClientID: r.PostForm.Get("client_id"), Scope: r.PostForm.Get("scope"),
				Audience: r.PostForm.Get("audience"), RemoteIP: apiserver.RequestInfoFrom(ctx).RemoteIP}
			h.Service.recordRefusal(ctx, tr, "", oerr)
			return oauthResponse(oerr), nil
		}
	}
}

// GetJWKS serves the JWKS.
func (h Handler) GetJWKS(context.Context, gen.GetJWKSRequestObject) (gen.GetJWKSResponseObject, error) {
	set, err := h.Service.Keys.JWKS(h.now())
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(set)
	if err != nil {
		return nil, err
	}
	var body gen.JWKS
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	if body.Keys == nil {
		body.Keys = []map[string]any{}
	}
	cc := JWKSCacheControl
	return gen.GetJWKS200JSONResponse{Body: body, Headers: gen.GetJWKS200ResponseHeaders{CacheControl: &cc}}, nil
}

// Metadata is the issuer metadata document.
func Metadata(issuer string) gen.IssuerMetadata {
	return gen.IssuerMetadata{
		Issuer:                            issuer,
		JwksUri:                           issuer + "/.well-known/jwks.json",
		TokenEndpoint:                     issuer + "/oauth/token",
		GrantTypesSupported:               []string{GrantClientCredentials},
		TokenEndpointAuthMethodsSupported: []string{MethodSecretPost, MethodPrivateKeyJWT},
		TokenEndpointAuthSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported: IssuedHere(),
	}
}

// GetIssuerMetadata serves /.well-known/openid-configuration.
func (h Handler) GetIssuerMetadata(context.Context, gen.GetIssuerMetadataRequestObject) (gen.GetIssuerMetadataResponseObject, error) {
	cc := JWKSCacheControl
	return gen.GetIssuerMetadata200JSONResponse{Body: Metadata(h.Service.Keys.Issuer()), Headers: gen.GetIssuerMetadata200ResponseHeaders{CacheControl: &cc}}, nil
}

// ListOAuthClients lists the registry.
func (h Handler) ListOAuthClients(ctx context.Context, _ gen.ListOAuthClientsRequestObject) (gen.ListOAuthClientsResponseObject, error) {
	cs, err := h.Registry.List(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.ListOAuthClients200JSONResponse{Clients: make([]gen.OAuthClient, 0, len(cs))}
	for i := range cs {
		c, err := clientToAPI(&cs[i])
		if err != nil {
			return nil, err
		}
		out.Clients = append(out.Clients, c)
	}
	return out, nil
}

// CreateOAuthClient registers a client.
func (h Handler) CreateOAuthClient(ctx context.Context, req gen.CreateOAuthClientRequestObject) (gen.CreateOAuthClientResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "", &core.FieldError{Field: "body", Reason: "required"})
	}
	b := req.Body
	in := ClientInput{ID: b.ClientId, Scopes: b.Scopes, AuthMethod: string(b.AuthMethod),
		MTLSSubject: deref(b.MtlsSubject), CertificateID: deref(b.CertificateId), Note: deref(b.Note)}
	if b.Audiences != nil {
		in.Audiences = *b.Audiences
	}
	if b.Jwks != nil {
		raw, err := json.Marshal(b.Jwks)
		if err != nil {
			return nil, err
		}
		in.JWKS = raw
	}
	c, secret, err := h.Registry.Create(ctx, in, actor)
	if err != nil {
		return nil, err
	}
	api, err := clientToAPI(&c)
	if err != nil {
		return nil, err
	}
	out := gen.CreateOAuthClient201JSONResponse{Client: api}
	if secret != "" {
		out.ClientSecret = &secret
	}
	return out, nil
}

// GetOAuthClient reads one client.
func (h Handler) GetOAuthClient(ctx context.Context, req gen.GetOAuthClientRequestObject) (gen.GetOAuthClientResponseObject, error) {
	c, err := h.Registry.Get(ctx, req.ClientId)
	if err != nil {
		return nil, err
	}
	api, err := clientToAPI(&c)
	if err != nil {
		return nil, err
	}
	return gen.GetOAuthClient200JSONResponse(api), nil
}

// UpdateOAuthClient changes a client.
func (h Handler) UpdateOAuthClient(ctx context.Context, req gen.UpdateOAuthClientRequestObject) (gen.UpdateOAuthClientResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "", &core.FieldError{Field: "body", Reason: "required"})
	}
	p := ClientPatch{Scopes: req.Body.Scopes, Audiences: req.Body.Audiences, Note: req.Body.Note}
	if req.Body.Status != nil {
		st := string(*req.Body.Status)
		p.Status = &st
	}
	c, err := h.Registry.Update(ctx, req.ClientId, p, actor)
	if err != nil {
		return nil, err
	}
	api, err := clientToAPI(&c)
	if err != nil {
		return nil, err
	}
	return gen.UpdateOAuthClient200JSONResponse(api), nil
}

// ListSigningKeys lists signing_keys with each key's state.
func (h Handler) ListSigningKeys(ctx context.Context, _ gen.ListSigningKeysRequestObject) (gen.ListSigningKeysResponseObject, error) {
	rows, err := h.Manager.Store.SigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.ListSigningKeys200JSONResponse{Keys: make([]gen.SigningKey, 0, len(rows))}
	for i := range rows {
		out.Keys = append(out.Keys, h.keyToAPI(&rows[i]))
	}
	return out, nil
}

func (h Handler) keyToAPI(r *KeyRow) gen.SigningKey {
	return gen.SigningKey{
		Kid: r.KID, Purpose: gen.SigningKeyPurpose(r.Purpose), State: gen.SigningKeyState(r.State(h.now(), h.Manager.Keys.Grace())),
		RegisteredAt: r.RegisteredAt.UTC(), ActiveFrom: utc(r.ActiveFrom), RetiredAt: utc(r.RetiredAt), RequestedAt: utc(r.RequestedAt),
		RequestedBy: optional(r.RequestedBy), CompromisedAt: utc(r.CompromisedAt), CompromisedBy: optional(r.CompromisedBy),
		CompromiseReason: optional(r.CompromiseReason),
	}
}

// CompromiseSigningKey drops a key now.
func (h Handler) CompromiseSigningKey(ctx context.Context, req gen.CompromiseSigningKeyRequestObject) (gen.CompromiseSigningKeyResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "", &core.FieldError{Field: "body", Reason: "required"})
	}
	row, err := h.Manager.Compromise(ctx, req.Kid, req.Body.Reason, actor)
	if err != nil {
		return nil, err
	}
	return gen.CompromiseSigningKey200JSONResponse(h.keyToAPI(&row)), nil
}

// RotateSigningKey runs one half of the two-person rotation, or the
// whole rotation without it.
func (h Handler) RotateSigningKey(ctx context.Context, _ gen.RotateSigningKeyRequestObject) (gen.RotateSigningKeyResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	rot, err := h.Manager.Rotate(ctx, actor)
	if err != nil {
		return nil, err
	}
	body := gen.KeyRotation{State: gen.KeyRotationState(rot.State), Kid: rot.KID, ActiveKid: rot.ActiveKID}
	if rot.PreviousKID != "" {
		body.PreviousKid = &rot.PreviousKID
	}
	if rot.RequestedBy != "" {
		body.RequestedBy = &rot.RequestedBy
	}
	if !rot.ConfirmBefore.IsZero() {
		cb := rot.ConfirmBefore.UTC()
		body.ConfirmBefore = &cb
	}
	if rot.State == "requested" {
		return gen.RotateSigningKey202JSONResponse(body), nil
	}
	return gen.RotateSigningKey200JSONResponse(body), nil
}

func clientToAPI(c *ClientRecord) (gen.OAuthClient, error) {
	out := gen.OAuthClient{
		ClientId: c.ID, System: gen.OAuthClientSystem(c.System), Scopes: nonNil(c.Scopes), Audiences: nonNil(c.Audiences),
		AuthMethod: gen.OAuthAuthMethod(c.AuthMethod), Status: gen.OAuthClientStatus(c.Status), Note: c.Note,
		CreatedAt: c.CreatedAt.UTC(), CreatedBy: c.CreatedBy, UpdatedAt: c.UpdatedAt.UTC(), UpdatedBy: c.UpdatedBy,
		MtlsSubject: optional(c.MTLSSubject), CertificateId: optional(c.CertificateID),
	}
	if len(c.JWKS) > 0 {
		var set gen.JWKS
		if err := json.Unmarshal(c.JWKS, &set); err != nil {
			return gen.OAuthClient{}, err
		}
		out.Jwks = &set
	}
	return out, nil
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
