package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
)

// operatorAuthorityClass is the concrete operator bearer class of one
// authenticated request. There are exactly three operator authorities; the
// Session capability (dht_...) is a data-plane token and is never one of
// them. Zero is reserved for the invalid/uninitialized class: the zero value
// of operatorAuthority is never a valid authority, so a missing
// initialization fails closed instead of naming a privileged authority.
type operatorAuthorityClass int

const (
	operatorAuthorityInvalid operatorAuthorityClass = iota
	operatorAuthorityAdmin
	operatorAuthorityPrincipal
	operatorAuthorityLauncher
)

// operatorAuthority is the single authenticated operator authority shared by
// every control-plane family. Exactly one authority class is effective per
// successful authentication: the class discriminator names it and the
// matching owner projection carries its provenance. It is authentication
// identity only — it never carries policy data (allowed roots, scopes, or
// preloaded owner enumerations), which remain owned by the policy and
// session-lifecycle paths.
type operatorAuthority struct {
	class     operatorAuthorityClass
	principal *PrincipalCredentialAuth // set iff class == operatorAuthorityPrincipal
	launcher  *LauncherCredentialAuth  // set iff class == operatorAuthorityLauncher
}

// validate reports whether the authority is structurally coherent: the class
// discriminator names exactly one of the three valid authorities and the
// matching owner projection is present while the others are nil. The zero
// value, a nil authority, a class without its owner projection, an owner
// projection under the wrong class, and any unknown class value are all
// invalid: an invalid authority is an internal authentication anomaly, never
// an authorized credential.
func (a *operatorAuthority) validate() error {
	if a == nil {
		return errors.New("nil operator authority")
	}
	switch a.class {
	case operatorAuthorityAdmin:
		if a.principal != nil || a.launcher != nil {
			return errors.New("admin authority carries an owner projection")
		}
	case operatorAuthorityPrincipal:
		if a.principal == nil {
			return errors.New("principal authority carries no principal owner")
		}
		if a.launcher != nil {
			return errors.New("principal authority carries a launcher owner")
		}
	case operatorAuthorityLauncher:
		if a.launcher == nil {
			return errors.New("launcher authority carries no launcher owner")
		}
		if a.principal != nil {
			return errors.New("launcher authority carries a principal owner")
		}
	default:
		return fmt.Errorf("unknown operator authority class %d", int(a.class))
	}
	return nil
}

// matchAdminToken returns the SHA-256 hash of the supplied bearer token and
// whether it matches the current admin token hash under constant-time
// comparison. It is the single admin-token comparison primitive: the admin
// request wrapper uses it for the exact authorizing hash (rotation
// commit-point validation), the general operator authenticator uses it for
// admin classification. It never consults the credential database, so an
// admin-only endpoint must not treat a non-admin token as a credential
// lookup.
func (a *App) matchAdminToken(token string) ([sha256.Size]byte, bool) {
	tokenHash := sha256.Sum256([]byte(token))
	currentHash := a.getAdminTokenHash()
	matched := subtle.ConstantTimeCompare(tokenHash[:], currentHash[:]) == 1
	return tokenHash, matched
}

// credentialAuthFailure is the canonical classification of a credential
// bearer-authentication failure from authenticateCredential. It is shared
// truth: each request wrapper maps it to its own established audit and wire
// contract. Exactly one expected non-disclosing outcome per failure mode,
// and every other error fails closed as a database error so an unknown
// failure can never be silently converted into a 401.
type credentialAuthFailure int

const (
	credentialAuthNotFound credentialAuthFailure = iota
	credentialAuthRevoked
	credentialAuthPrincipalDisabled
	credentialAuthLauncherDisabled
	credentialAuthDatabaseError
)

// classifyCredentialAuthFailure classifies a non-nil authenticateCredential
// error into the canonical credential-auth failure classes. The disabled
// states are classified explicitly — a disabled Launcher is never folded
// into an unknown-token result.
func classifyCredentialAuthFailure(err error) credentialAuthFailure {
	switch {
	case errors.Is(err, ErrCredentialNotFound):
		return credentialAuthNotFound
	case errors.Is(err, ErrCredentialRevoked):
		return credentialAuthRevoked
	case errors.Is(err, ErrPrincipalDisabled):
		return credentialAuthPrincipalDisabled
	case errors.Is(err, ErrLauncherDisabled):
		return credentialAuthLauncherDisabled
	default:
		return credentialAuthDatabaseError
	}
}

// isExpectedAuthFailure reports whether the classification is an expected
// non-disclosing authentication outcome (which the caller answers with its
// established 401 contract) rather than a database failure (HTTP 500).
func (f credentialAuthFailure) isExpectedAuthFailure() bool {
	return f != credentialAuthDatabaseError
}

// authenticateOperatorToken classifies an operator bearer token without
// writing HTTP responses or audit records: admin constant-time comparison
// first, then the single credential-token lookup. The concrete owner is
// determined from persistent state, so the result names exactly one
// authority class, and every returned authority passes structural
// validation — the producer never emits a structurally invalid authority.
// Authentication only — authorization (which authority classes a family
// accepts) remains with the request wrappers and endpoint families.
func (a *App) authenticateOperatorToken(token string) (*operatorAuthority, error) {
	if _, matched := a.matchAdminToken(token); matched {
		auth := &operatorAuthority{class: operatorAuthorityAdmin}
		if err := auth.validate(); err != nil {
			return nil, err
		}
		return auth, nil
	}

	result, err := authenticateCredential(a.DB, token)
	if err != nil {
		return nil, err
	}
	switch {
	case result.Principal != nil:
		auth := &operatorAuthority{class: operatorAuthorityPrincipal, principal: result.Principal}
		if err := auth.validate(); err != nil {
			return nil, err
		}
		return auth, nil
	case result.Launcher != nil:
		auth := &operatorAuthority{class: operatorAuthorityLauncher, launcher: result.Launcher}
		if err := auth.validate(); err != nil {
			return nil, err
		}
		return auth, nil
	default:
		// A successful lookup must name exactly one concrete owner (the
		// schema's concrete-owner CHECK guarantees it); anything else is a
		// fail-closed anomaly classified as a database error.
		return nil, fmt.Errorf("credential authentication returned no concrete owner: %w", sql.ErrNoRows)
	}
}
