package vaultapi

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"sort"
	"time"
)

// API documentation for AppRole
// https://www.vaultproject.io/api/auth/approle


var basePath				string			= "/auth/approle/role"


type AppRoleOptions struct {
	RoleName				string 			`json:role_name`							// Required: Name of the AppRole.
	bind_secret_id			bool			`json:bind_secret_id,omitempty`				// default true - Require secret_id to be presented when logging in using this AppRole.
	SecretIDBoundCiders		[]string		`json:"secret_id_bound_cidrs,omitempty"`	// Default: [] - Comma-separated string or list of CIDR blocks; if set, specifies blocks of IP addresses which can perform the login operation.
	SecretIDNumUses			int				`json:"secret_id_num_uses,omitempty"`		// Default: 0 - Number of times any particular SecretID can be used to fetch a token from this AppRole, after which the SecretID will expire. A value of zero will allow unlimited uses.
	SecretIDTTL				string			`json:"secret_id_ttl,omitempty"`			// Default: "" - Duration in either an integer number of seconds (3600) or an integer time unit (60m) after which any SecretID expires.
	EnableLocalSecretIDs	bool			`json:"enable_local_secret_ids,omitempty"`	// Default: false - If set, the secret IDs generated using this role will be cluster local. This can only be set during role creation and once set, it can't be reset later.
	TokenTTL				time.Duration	`json:"token_ttl,omitempty"`				// (integer: 0 or string: "") - The incremental lifetime for generated tokens. This current value of this will be referenced at renewal time.
	TokenMaxTTL				time.Duration	`json:"token_max_ttl,omitempty"`			// (integer: 0 or string: "") - The maximum lifetime for generated tokens. This current value of this will be referenced at renewal time.
	TokenPolicies			[]string		`json:"token_policies,omitempty"`			// (array: [] or comma-delimited string: "") - List of policies to encode onto generated tokens. Depending on the auth method, this list may be supplemented by user/group/other values.
	TokenBoundCIDRs			[]string		`json:"token_bound_cidrs,omitempty"`		// List of CIDR blocks; if set, specifies blocks of IP addresses which can authenticate successfully, and ties the resulting token to these blocks as well.
	TokenExplicitMaxTTL		time.Duration	`json:"token_explicit_max_ttl,omitempty"`	// Default 0 - If set, will encode an explicit max TTL onto the token. This is a hard cap even if token_ttl and token_max_ttl would otherwise allow a renewal.
	TokenNoDefaultPolicy	bool			`json:"token_no_default_policy,omitempty"`	// Default: false - If set, the default policy will not be set on generated tokens; otherwise it will be added to the policies set in token_policies.
	TokenNumUses			int				`json:"token_num_uses,omitempty"`			// Default: 0 - The maximum number of times a generated token may be used (within its lifetime); 0 means unlimited. If you require the token to have the ability to create child tokens, you will need to set this value to 0.
	TokenPeriod				time.Duration	`json:"token_period,omitempty"`				//(integer: 0 or string: "") - The period, if any, to set on the token. https://www.vaultproject.io/docs/concepts/tokens#periodic-tokens
	TokenType				string			`json:"token_type,omitempty"`				// Default: "" - The type of token that should be generated. Can be service, batch, or default to use the mount's tuned default (which unless changed will be service tokens). For token store roles, there are two additional possibilities: default-service and default-batch which specify the type to return unless the client requests a different type at generation time.
}

//TODO: Figure out this rolesWratpper thing and decide if we really need it.

// Fetch the list of AppRoles
// https://www.vaultproject.io/api/auth/approle#list-roles
func (c *client) ListAppRoles() ([]string, error) {
	//method := "LIST"
	requestPath := basePath

	var rolesWrapper rolesWrapper
	if err := c.list(requestPath, &rolesWrapper); err != nil {
		return nil, errors.Wrapf(err, "failed to list token roles at %q", requestPath)
	}
	sort.Strings(rolesWrapper.Data.Keys)
	return rolesWrapper.Data.Keys, nil
}


// Create or Update an AppRole
// https://www.vaultproject.io/api/auth/approle#create-update-approle
func (c *client) CreateAppRole(roleData AppRoleOptions) error {
	byteArray, err := json.Marshal(roleData)
	if err != nil {
		return errors.Wrap(err, "marshalling role data to JSON request body")
	}
	c.opts.Logger.Printf("role-create request: %v", string(byteArray))

	requestPath := fmt.Sprintf("/v1/auth/approle/role/%s", roleData.RoleName)
	if err := c.post(requestPath, string(byteArray), nil); err != nil {
		return errors.Wrapf(err, "creating role at %q", requestPath)
	}

	return nil
}

// Read Role
// https://www.vaultproject.io/api/auth/approle#read-approle

// Delete Role
// https://www.vaultproject.io/api/auth/approle#delete-approle

// Read Role ID
// https://www.vaultproject.io/api/auth/approle#read-approle-role-id

// Update Role ID
// https://www.vaultproject.io/api/auth/approle#update-approle-role-id

// Generate New Secret ID
// https://www.vaultproject.io/api/auth/approle#generate-new-secret-id


// List Secret ID Accessors
// https://www.vaultproject.io/api/auth/approle#list-secret-id-accessors


// Read Secret ID
// https://www.vaultproject.io/api/auth/approle#read-approle-secret-id

// Destroy Secret ID
// https://www.vaultproject.io/api/auth/approle#destroy-approle-secret-id


// Read Secret ID Accessor
// https://www.vaultproject.io/api/auth/approle#read-approle-secret-id-accessor

// Destroy Secret ID Accessor
// https://www.vaultproject.io/api/auth/approle#destroy-approle-secret-id-accessor

// Create custom secret ID
// https://www.vaultproject.io/api/auth/approle#create-custom-approle-secret-id

// Authenticate With AppRole
// https://www.vaultproject.io/api/auth/approle#login-with-approle

// ReadUpdateDelete AppRole Properties
// https://www.vaultproject.io/api/auth/approle#read-update-or-delete-approle-properties

// Tidy Tokens
// https://www.vaultproject.io/api/auth/approle#tidy-tokens
