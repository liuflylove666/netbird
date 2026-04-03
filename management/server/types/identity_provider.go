package types

import (
	"errors"
	"net/url"
	"strings"
)

// Identity provider validation errors
var (
	ErrIdentityProviderNameRequired      = errors.New("identity provider name is required")
	ErrIdentityProviderTypeRequired      = errors.New("identity provider type is required")
	ErrIdentityProviderTypeUnsupported   = errors.New("unsupported identity provider type")
	ErrIdentityProviderIssuerRequired    = errors.New("identity provider issuer is required")
	ErrIdentityProviderIssuerInvalid     = errors.New("identity provider issuer must be a valid URL")
	ErrIdentityProviderIssuerUnreachable = errors.New("identity provider issuer is unreachable")
	ErrIdentityProviderIssuerMismatch    = errors.New("identity provider issuer does not match the issuer returned by the provider")
	ErrIdentityProviderClientIDRequired  = errors.New("identity provider client ID is required")
	ErrIdentityProviderLDAPHostRequired  = errors.New("LDAP host is required")
	ErrIdentityProviderLDAPBindDNRequired = errors.New("LDAP bind DN is required")
	ErrIdentityProviderLDAPUserSearchBaseDNRequired = errors.New("LDAP user search base DN is required")
)

// IdentityProviderType is the type of identity provider
type IdentityProviderType string

const (
	// IdentityProviderTypeOIDC is a generic OIDC identity provider
	IdentityProviderTypeOIDC IdentityProviderType = "oidc"
	// IdentityProviderTypeZitadel is the Zitadel identity provider
	IdentityProviderTypeZitadel IdentityProviderType = "zitadel"
	// IdentityProviderTypeEntra is the Microsoft Entra (Azure AD) identity provider
	IdentityProviderTypeEntra IdentityProviderType = "entra"
	// IdentityProviderTypeGoogle is the Google identity provider
	IdentityProviderTypeGoogle IdentityProviderType = "google"
	// IdentityProviderTypeOkta is the Okta identity provider
	IdentityProviderTypeOkta IdentityProviderType = "okta"
	// IdentityProviderTypePocketID is the PocketID identity provider
	IdentityProviderTypePocketID IdentityProviderType = "pocketid"
	// IdentityProviderTypeMicrosoft is the Microsoft identity provider
	IdentityProviderTypeMicrosoft IdentityProviderType = "microsoft"
	// IdentityProviderTypeAuthentik is the Authentik identity provider
	IdentityProviderTypeAuthentik IdentityProviderType = "authentik"
	// IdentityProviderTypeKeycloak is the Keycloak identity provider
	IdentityProviderTypeKeycloak IdentityProviderType = "keycloak"
	// IdentityProviderTypeLDAP is the LDAP identity provider
	IdentityProviderTypeLDAP IdentityProviderType = "ldap"
)

// IdentityProvider represents an identity provider configuration
type IdentityProvider struct {
	// ID is the unique identifier of the identity provider
	ID string `gorm:"primaryKey"`
	// AccountID is a reference to Account that this object belongs
	AccountID string `json:"-" gorm:"index"`
	// Type is the type of identity provider
	Type IdentityProviderType
	// Name is a human-readable name for the identity provider
	Name string
	// Issuer is the OIDC issuer URL
	Issuer string
	// ClientID is the OAuth2 client ID
	ClientID string
	// ClientSecret is the OAuth2 client secret
	ClientSecret string

	// LDAP-specific fields (only used when Type == "ldap")
	LDAPHost               string `gorm:"column:ldap_host"`
	LDAPInsecureNoSSL      bool   `gorm:"column:ldap_insecure_no_ssl"`
	LDAPInsecureSkipVerify bool   `gorm:"column:ldap_insecure_skip_verify"`
	LDAPStartTLS           bool   `gorm:"column:ldap_start_tls"`
	LDAPRootCA             string `gorm:"column:ldap_root_ca"`
	LDAPBindDN             string `gorm:"column:ldap_bind_dn"`
	LDAPBindPW             string `gorm:"column:ldap_bind_pw"`
	LDAPUserSearchBaseDN    string `gorm:"column:ldap_user_search_base_dn"`
	LDAPUserSearchFilter    string `gorm:"column:ldap_user_search_filter"`
	LDAPUserSearchUsername  string `gorm:"column:ldap_user_search_username"`
	LDAPUserSearchIDAttr    string `gorm:"column:ldap_user_search_id_attr"`
	LDAPUserSearchEmailAttr string `gorm:"column:ldap_user_search_email_attr"`
	LDAPUserSearchNameAttr  string `gorm:"column:ldap_user_search_name_attr"`
	LDAPGroupSearchBaseDN    string `gorm:"column:ldap_group_search_base_dn"`
	LDAPGroupSearchFilter    string `gorm:"column:ldap_group_search_filter"`
	LDAPGroupSearchUserAttr  string `gorm:"column:ldap_group_search_user_attr"`
	LDAPGroupSearchGroupAttr string `gorm:"column:ldap_group_search_group_attr"`
	LDAPGroupSearchNameAttr  string `gorm:"column:ldap_group_search_name_attr"`
	// LDAPRequiredGroups is a comma-separated list of group names that restrict login.
	LDAPRequiredGroups string `gorm:"column:ldap_required_groups"`
}

// GetRequiredGroups returns the required groups as a string slice.
func (idp *IdentityProvider) GetRequiredGroups() []string {
	if idp.LDAPRequiredGroups == "" {
		return nil
	}
	return strings.Split(idp.LDAPRequiredGroups, ",")
}

// SetRequiredGroups sets the required groups from a string slice.
func (idp *IdentityProvider) SetRequiredGroups(groups []string) {
	idp.LDAPRequiredGroups = strings.Join(groups, ",")
}

// Copy returns a copy of the IdentityProvider
func (idp *IdentityProvider) Copy() *IdentityProvider {
	c := &IdentityProvider{
		ID:           idp.ID,
		AccountID:    idp.AccountID,
		Type:         idp.Type,
		Name:         idp.Name,
		Issuer:       idp.Issuer,
		ClientID:     idp.ClientID,
		ClientSecret: idp.ClientSecret,

		LDAPHost:                 idp.LDAPHost,
		LDAPInsecureNoSSL:        idp.LDAPInsecureNoSSL,
		LDAPInsecureSkipVerify:   idp.LDAPInsecureSkipVerify,
		LDAPStartTLS:             idp.LDAPStartTLS,
		LDAPRootCA:               idp.LDAPRootCA,
		LDAPBindDN:               idp.LDAPBindDN,
		LDAPBindPW:               idp.LDAPBindPW,
		LDAPUserSearchBaseDN:     idp.LDAPUserSearchBaseDN,
		LDAPUserSearchFilter:     idp.LDAPUserSearchFilter,
		LDAPUserSearchUsername:   idp.LDAPUserSearchUsername,
		LDAPUserSearchIDAttr:     idp.LDAPUserSearchIDAttr,
		LDAPUserSearchEmailAttr:  idp.LDAPUserSearchEmailAttr,
		LDAPUserSearchNameAttr:   idp.LDAPUserSearchNameAttr,
		LDAPGroupSearchBaseDN:    idp.LDAPGroupSearchBaseDN,
		LDAPGroupSearchFilter:    idp.LDAPGroupSearchFilter,
		LDAPGroupSearchUserAttr:  idp.LDAPGroupSearchUserAttr,
		LDAPGroupSearchGroupAttr: idp.LDAPGroupSearchGroupAttr,
		LDAPGroupSearchNameAttr:  idp.LDAPGroupSearchNameAttr,
		LDAPRequiredGroups:       idp.LDAPRequiredGroups,
	}
	return c
}

// EventMeta returns a map of metadata for activity events
func (idp *IdentityProvider) EventMeta() map[string]any {
	return map[string]any{
		"name":   idp.Name,
		"type":   string(idp.Type),
		"issuer": idp.Issuer,
	}
}

// Validate validates the identity provider configuration
func (idp *IdentityProvider) Validate() error {
	if idp.Name == "" {
		return ErrIdentityProviderNameRequired
	}
	if idp.Type == "" {
		return ErrIdentityProviderTypeRequired
	}
	if !idp.Type.IsValid() {
		return ErrIdentityProviderTypeUnsupported
	}

	if idp.Type == IdentityProviderTypeLDAP {
		return idp.validateLDAP()
	}

	if !idp.Type.HasBuiltInIssuer() && idp.Issuer == "" {
		return ErrIdentityProviderIssuerRequired
	}
	if idp.Issuer != "" {
		parsedURL, err := url.Parse(idp.Issuer)
		if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
			return ErrIdentityProviderIssuerInvalid
		}
	}
	if idp.ClientID == "" {
		return ErrIdentityProviderClientIDRequired
	}
	return nil
}

func (idp *IdentityProvider) validateLDAP() error {
	if idp.LDAPHost == "" {
		return ErrIdentityProviderLDAPHostRequired
	}
	if idp.LDAPBindDN == "" {
		return ErrIdentityProviderLDAPBindDNRequired
	}
	if idp.LDAPUserSearchBaseDN == "" {
		return ErrIdentityProviderLDAPUserSearchBaseDNRequired
	}
	return nil
}

// IsValid checks if the given type is a supported identity provider type
func (t IdentityProviderType) IsValid() bool {
	switch t {
	case IdentityProviderTypeOIDC, IdentityProviderTypeZitadel, IdentityProviderTypeEntra,
		IdentityProviderTypeGoogle, IdentityProviderTypeOkta, IdentityProviderTypePocketID,
		IdentityProviderTypeMicrosoft, IdentityProviderTypeAuthentik, IdentityProviderTypeKeycloak,
		IdentityProviderTypeLDAP:
		return true
	}
	return false
}

// HasBuiltInIssuer returns true for types that don't require an issuer URL
func (t IdentityProviderType) HasBuiltInIssuer() bool {
	return t == IdentityProviderTypeGoogle || t == IdentityProviderTypeMicrosoft || t == IdentityProviderTypeLDAP
}
