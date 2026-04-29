// Package dex provides an embedded Dex OIDC identity provider.
package dex

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dexidp/dex/storage"
	ldapv3 "github.com/go-ldap/ldap/v3"
)

// ConnectorConfig represents the configuration for an identity provider connector
type ConnectorConfig struct {
	// ID is the unique identifier for the connector
	ID string
	// Name is a human-readable name for the connector
	Name string
	// Type is the connector type (oidc, google, microsoft, ldap)
	Type string
	// Issuer is the OIDC issuer URL (for OIDC-based connectors)
	Issuer string
	// ClientID is the OAuth2 client ID
	ClientID string
	// ClientSecret is the OAuth2 client secret
	ClientSecret string
	// RedirectURI is the OAuth2 redirect URI
	RedirectURI string
	// LDAP holds LDAP-specific configuration (only used when Type is "ldap")
	LDAP *LDAPConnectorConfig
}

// LDAPConnectorConfig holds configuration for an LDAP connector
type LDAPConnectorConfig struct {
	Host               string `json:"host"`
	InsecureNoSSL      bool   `json:"insecureNoSSL"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	StartTLS           bool   `json:"startTLS"`
	RootCA             string `json:"rootCA,omitempty"`
	BindDN             string `json:"bindDN"`
	BindPW             string `json:"bindPW"`
	// User search
	UserSearchBaseDN    string `json:"userSearchBaseDN"`
	UserSearchFilter    string `json:"userSearchFilter,omitempty"`
	UserSearchUsername  string `json:"userSearchUsername"`
	UserSearchIDAttr    string `json:"userSearchIDAttr"`
	UserSearchEmailAttr string `json:"userSearchEmailAttr"`
	UserSearchNameAttr  string `json:"userSearchNameAttr"`
	// Group search (optional)
	GroupSearchBaseDN    string `json:"groupSearchBaseDN,omitempty"`
	GroupSearchFilter    string `json:"groupSearchFilter,omitempty"`
	GroupSearchUserAttr  string `json:"groupSearchUserAttr,omitempty"`
	GroupSearchGroupAttr string `json:"groupSearchGroupAttr,omitempty"`
	GroupSearchNameAttr  string `json:"groupSearchNameAttr,omitempty"`
	// RequiredGroups restricts login to users who are members of at least one of these groups.
	RequiredGroups []string `json:"requiredGroups,omitempty"`
}

// CreateConnector creates a new connector in Dex storage.
// It maps the connector config to the appropriate Dex connector type and configuration.
func (p *Provider) CreateConnector(ctx context.Context, cfg *ConnectorConfig) (*ConnectorConfig, error) {
	// Fill in the redirect URI if not provided
	if cfg.RedirectURI == "" {
		cfg.RedirectURI = p.GetRedirectURI()
	}

	storageConn, err := p.buildStorageConnector(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build connector: %w", err)
	}

	if err := p.storage.CreateConnector(ctx, storageConn); err != nil {
		return nil, fmt.Errorf("failed to create connector: %w", err)
	}

	p.logger.Info("connector created", "id", cfg.ID, "type", cfg.Type)
	return cfg, nil
}

// GetConnector retrieves a connector by ID from Dex storage.
func (p *Provider) GetConnector(ctx context.Context, id string) (*ConnectorConfig, error) {
	conn, err := p.storage.GetConnector(ctx, id)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get connector: %w", err)
	}

	return p.parseStorageConnector(conn)
}

// ListConnectors returns all connectors from Dex storage (excluding the local connector).
func (p *Provider) ListConnectors(ctx context.Context) ([]*ConnectorConfig, error) {
	connectors, err := p.storage.ListConnectors(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list connectors: %w", err)
	}

	result := make([]*ConnectorConfig, 0, len(connectors))
	for _, conn := range connectors {
		// Skip the local password connector
		if conn.ID == "local" && conn.Type == "local" {
			continue
		}

		cfg, err := p.parseStorageConnector(conn)
		if err != nil {
			p.logger.Warn("failed to parse connector", "id", conn.ID, "error", err)
			continue
		}
		result = append(result, cfg)
	}

	return result, nil
}

// UpdateConnector updates an existing connector in Dex storage.
// It merges incoming updates with existing values to prevent data loss on partial updates.
func (p *Provider) UpdateConnector(ctx context.Context, cfg *ConnectorConfig) error {
	if err := p.storage.UpdateConnector(ctx, cfg.ID, func(old storage.Connector) (storage.Connector, error) {
		oldCfg, err := p.parseStorageConnector(old)
		if err != nil {
			return storage.Connector{}, fmt.Errorf("failed to parse existing connector: %w", err)
		}

		mergeConnectorConfig(cfg, oldCfg)

		storageConn, err := p.buildStorageConnector(cfg)
		if err != nil {
			return storage.Connector{}, fmt.Errorf("failed to build connector: %w", err)
		}
		return storageConn, nil
	}); err != nil {
		return fmt.Errorf("failed to update connector: %w", err)
	}

	p.logger.Info("connector updated", "id", cfg.ID, "type", cfg.Type)
	return nil
}

// mergeConnectorConfig preserves existing values for empty fields in the update.
func mergeConnectorConfig(cfg, oldCfg *ConnectorConfig) {
	if cfg.Name == "" {
		cfg.Name = oldCfg.Name
	}
	if cfg.Type == "ldap" {
		if cfg.LDAP == nil && oldCfg.LDAP != nil {
			cfg.LDAP = oldCfg.LDAP
		} else if cfg.LDAP != nil && oldCfg.LDAP != nil {
			if cfg.LDAP.BindPW == "" {
				cfg.LDAP.BindPW = oldCfg.LDAP.BindPW
			}
		}
		return
	}
	if cfg.ClientSecret == "" {
		cfg.ClientSecret = oldCfg.ClientSecret
	}
	if cfg.RedirectURI == "" {
		cfg.RedirectURI = oldCfg.RedirectURI
	}
	if cfg.Issuer == "" && cfg.Type == oldCfg.Type {
		cfg.Issuer = oldCfg.Issuer
	}
	if cfg.ClientID == "" {
		cfg.ClientID = oldCfg.ClientID
	}
}

// DeleteConnector removes a connector from Dex storage.
func (p *Provider) DeleteConnector(ctx context.Context, id string) error {
	// Prevent deletion of the local connector
	if id == "local" {
		return fmt.Errorf("cannot delete the local password connector")
	}

	if err := p.storage.DeleteConnector(ctx, id); err != nil {
		return fmt.Errorf("failed to delete connector: %w", err)
	}

	p.logger.Info("connector deleted", "id", id)
	return nil
}

// GetRedirectURI returns the default redirect URI for connectors.
func (p *Provider) GetRedirectURI() string {
	if p.config == nil {
		return ""
	}
	issuer := strings.TrimSuffix(p.config.Issuer, "/")
	if !strings.HasSuffix(issuer, "/oauth2") {
		issuer += "/oauth2"
	}
	return issuer + "/callback"
}

// buildStorageConnector creates a storage.Connector from ConnectorConfig.
// It handles the type-specific configuration for each connector type.
func (p *Provider) buildStorageConnector(cfg *ConnectorConfig) (storage.Connector, error) {
	redirectURI := p.resolveRedirectURI(cfg.RedirectURI)

	var dexType string
	var configData []byte
	var err error

	switch cfg.Type {
	case "oidc", "zitadel", "entra", "okta", "pocketid", "authentik", "keycloak", "adfs":
		dexType = "oidc"
		configData, err = buildOIDCConnectorConfig(cfg, redirectURI)
	case "google":
		dexType = "google"
		configData, err = buildOAuth2ConnectorConfig(cfg, redirectURI)
	case "microsoft":
		dexType = "microsoft"
		configData, err = buildOAuth2ConnectorConfig(cfg, redirectURI)
	case "ldap":
		dexType = "ldap"
		configData, err = buildLDAPConnectorConfig(cfg)
	default:
		return storage.Connector{}, fmt.Errorf("unsupported connector type: %s", cfg.Type)
	}
	if err != nil {
		return storage.Connector{}, err
	}

	return storage.Connector{ID: cfg.ID, Type: dexType, Name: cfg.Name, Config: configData}, nil
}

// resolveRedirectURI returns the redirect URI, using a default if not provided
func (p *Provider) resolveRedirectURI(redirectURI string) string {
	if redirectURI != "" || p.config == nil {
		return redirectURI
	}
	issuer := strings.TrimSuffix(p.config.Issuer, "/")
	if !strings.HasSuffix(issuer, "/oauth2") {
		issuer += "/oauth2"
	}
	return issuer + "/callback"
}

// buildOIDCConnectorConfig creates config for OIDC-based connectors
func buildOIDCConnectorConfig(cfg *ConnectorConfig, redirectURI string) ([]byte, error) {
	oidcConfig := map[string]interface{}{
		"issuer":               cfg.Issuer,
		"clientID":             cfg.ClientID,
		"clientSecret":         cfg.ClientSecret,
		"redirectURI":          redirectURI,
		"scopes":               []string{"openid", "profile", "email"},
		"insecureEnableGroups": true,
		//some providers don't return email verified, so we need to skip it if not present (e.g., Entra, Okta, Duo)
		"insecureSkipEmailVerified": true,
	}
	switch cfg.Type {
	case "zitadel":
		oidcConfig["getUserInfo"] = true
	case "entra":
		oidcConfig["claimMapping"] = map[string]string{"email": "preferred_username"}
	case "okta":
		oidcConfig["scopes"] = []string{"openid", "profile", "email", "groups"}
	case "pocketid":
		oidcConfig["scopes"] = []string{"openid", "profile", "email", "groups"}
	case "adfs":
		oidcConfig["scopes"] = []string{"openid", "profile", "email", "allatclaims"}
	}
	return encodeConnectorConfig(oidcConfig)
}

// buildOAuth2ConnectorConfig creates config for OAuth2 connectors (google, microsoft)
func buildOAuth2ConnectorConfig(cfg *ConnectorConfig, redirectURI string) ([]byte, error) {
	return encodeConnectorConfig(map[string]interface{}{
		"clientID":     cfg.ClientID,
		"clientSecret": cfg.ClientSecret,
		"redirectURI":  redirectURI,
	})
}

// buildLDAPConnectorConfig creates config for LDAP connectors
func buildLDAPConnectorConfig(cfg *ConnectorConfig) ([]byte, error) {
	if cfg.LDAP == nil {
		return nil, fmt.Errorf("LDAP configuration is required for LDAP connector")
	}
	l := cfg.LDAP

	ldapConfig := map[string]interface{}{
		"host":               l.Host,
		"insecureNoSSL":      l.InsecureNoSSL,
		"insecureSkipVerify": l.InsecureSkipVerify,
		"startTLS":           l.StartTLS,
		"bindDN":             l.BindDN,
		"bindPW":             l.BindPW,
	}
	if l.RootCA != "" {
		ldapConfig["rootCA"] = l.RootCA
	}

	userSearch := map[string]interface{}{
		"baseDN":    l.UserSearchBaseDN,
		"username":  l.UserSearchUsername,
		"idAttr":    l.UserSearchIDAttr,
		"emailAttr": l.UserSearchEmailAttr,
		"nameAttr":  l.UserSearchNameAttr,
	}
	if l.UserSearchFilter != "" {
		userSearch["filter"] = l.UserSearchFilter
	}
	ldapConfig["userSearch"] = userSearch

	if l.GroupSearchBaseDN != "" {
		groupSearch := map[string]interface{}{
			"baseDN": l.GroupSearchBaseDN,
		}
		if l.GroupSearchFilter != "" {
			groupSearch["filter"] = l.GroupSearchFilter
		}
		if l.GroupSearchNameAttr != "" {
			groupSearch["nameAttr"] = l.GroupSearchNameAttr
		}
		userAttr := l.GroupSearchUserAttr
		if userAttr == "" {
			userAttr = "DN"
		}
		groupAttr := l.GroupSearchGroupAttr
		if groupAttr == "" {
			groupAttr = "member"
		}
		groupSearch["userMatchers"] = []map[string]string{
			{"userAttr": userAttr, "groupAttr": groupAttr},
		}
		ldapConfig["groupSearch"] = groupSearch
	}

	if len(l.RequiredGroups) > 0 {
		ldapConfig["requiredGroups"] = l.RequiredGroups
	}

	return encodeConnectorConfig(ldapConfig)
}

// parseStorageConnector converts a storage.Connector back to ConnectorConfig.
// It infers the original identity provider type from the Dex connector type and ID.
func (p *Provider) parseStorageConnector(conn storage.Connector) (*ConnectorConfig, error) {
	cfg := &ConnectorConfig{
		ID:   conn.ID,
		Name: conn.Name,
	}

	if len(conn.Config) == 0 {
		cfg.Type = conn.Type
		return cfg, nil
	}

	var configMap map[string]interface{}
	if err := decodeConnectorConfig(conn.Config, &configMap); err != nil {
		return nil, fmt.Errorf("failed to parse connector config: %w", err)
	}

	// Handle LDAP connectors differently
	if conn.Type == "ldap" {
		cfg.Type = "ldap"
		cfg.LDAP = parseLDAPConfigMap(configMap)
		return cfg, nil
	}

	// Extract common fields for OIDC/OAuth connectors
	if v, ok := configMap["clientID"].(string); ok {
		cfg.ClientID = v
	}
	if v, ok := configMap["clientSecret"].(string); ok {
		cfg.ClientSecret = v
	}
	if v, ok := configMap["redirectURI"].(string); ok {
		cfg.RedirectURI = v
	}
	if v, ok := configMap["issuer"].(string); ok {
		cfg.Issuer = v
	}

	// Infer the original identity provider type from Dex connector type and ID
	cfg.Type = inferIdentityProviderType(conn.Type, conn.ID, configMap)

	return cfg, nil
}

// inferIdentityProviderType determines the original identity provider type
// based on the Dex connector type, connector ID, and configuration.
func inferIdentityProviderType(dexType, connectorID string, _ map[string]interface{}) string {
	if dexType != "oidc" {
		return dexType
	}
	return inferOIDCProviderType(connectorID)
}

// inferOIDCProviderType infers the specific OIDC provider from connector ID
func inferOIDCProviderType(connectorID string) string {
	connectorIDLower := strings.ToLower(connectorID)
	for _, provider := range []string{"pocketid", "zitadel", "entra", "okta", "authentik", "keycloak", "adfs"} {
		if strings.Contains(connectorIDLower, provider) {
			return provider
		}
	}
	return "oidc"
}

// parseLDAPConfigMap extracts LDAPConnectorConfig from a raw config map
func parseLDAPConfigMap(m map[string]interface{}) *LDAPConnectorConfig {
	l := &LDAPConnectorConfig{}
	if v, ok := m["host"].(string); ok {
		l.Host = v
	}
	if v, ok := m["insecureNoSSL"].(bool); ok {
		l.InsecureNoSSL = v
	}
	if v, ok := m["insecureSkipVerify"].(bool); ok {
		l.InsecureSkipVerify = v
	}
	if v, ok := m["startTLS"].(bool); ok {
		l.StartTLS = v
	}
	if v, ok := m["rootCA"].(string); ok {
		l.RootCA = v
	}
	if v, ok := m["bindDN"].(string); ok {
		l.BindDN = v
	}
	if v, ok := m["bindPW"].(string); ok {
		l.BindPW = v
	}
	if us, ok := m["userSearch"].(map[string]interface{}); ok {
		if v, ok := us["baseDN"].(string); ok {
			l.UserSearchBaseDN = v
		}
		if v, ok := us["filter"].(string); ok {
			l.UserSearchFilter = v
		}
		if v, ok := us["username"].(string); ok {
			l.UserSearchUsername = v
		}
		if v, ok := us["idAttr"].(string); ok {
			l.UserSearchIDAttr = v
		}
		if v, ok := us["emailAttr"].(string); ok {
			l.UserSearchEmailAttr = v
		}
		if v, ok := us["nameAttr"].(string); ok {
			l.UserSearchNameAttr = v
		}
	}
	if gs, ok := m["groupSearch"].(map[string]interface{}); ok {
		if v, ok := gs["baseDN"].(string); ok {
			l.GroupSearchBaseDN = v
		}
		if v, ok := gs["filter"].(string); ok {
			l.GroupSearchFilter = v
		}
		if v, ok := gs["nameAttr"].(string); ok {
			l.GroupSearchNameAttr = v
		}
		if matchers, ok := gs["userMatchers"].([]interface{}); ok && len(matchers) > 0 {
			if m0, ok := matchers[0].(map[string]interface{}); ok {
				if v, ok := m0["userAttr"].(string); ok {
					l.GroupSearchUserAttr = v
				}
				if v, ok := m0["groupAttr"].(string); ok {
					l.GroupSearchGroupAttr = v
				}
			}
		}
	}
	if rg, ok := m["requiredGroups"].([]interface{}); ok {
		for _, g := range rg {
			if s, ok := g.(string); ok {
				l.RequiredGroups = append(l.RequiredGroups, s)
			}
		}
	}
	return l
}

// encodeConnectorConfig serializes connector config to JSON bytes.
func encodeConnectorConfig(config map[string]interface{}) ([]byte, error) {
	return json.Marshal(config)
}

// decodeConnectorConfig deserializes connector config from JSON bytes.
func decodeConnectorConfig(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// ensureLocalConnector creates a local (password) connector if it doesn't exist
func ensureLocalConnector(ctx context.Context, stor storage.Storage) error {
	// Check specifically for the local connector
	_, err := stor.GetConnector(ctx, "local")
	if err == nil {
		// Local connector already exists
		return nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("failed to get local connector: %w", err)
	}

	// Create a local connector for password authentication
	localConnector := storage.Connector{
		ID:   "local",
		Type: "local",
		Name: "Email",
	}

	if err := stor.CreateConnector(ctx, localConnector); err != nil {
		return fmt.Errorf("failed to create local connector: %w", err)
	}

	return nil
}

// HasNonLocalConnectors checks if there are any connectors other than the local connector.
func (p *Provider) HasNonLocalConnectors(ctx context.Context) (bool, error) {
	connectors, err := p.storage.ListConnectors(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to list connectors: %w", err)
	}

	p.logger.Info("checking for non-local connectors", "total_connectors", len(connectors))
	for _, conn := range connectors {
		p.logger.Info("found connector in storage", "id", conn.ID, "type", conn.Type, "name", conn.Name)
		if conn.ID != "local" || conn.Type != "local" {
			p.logger.Info("found non-local connector", "id", conn.ID)
			return true, nil
		}
	}
	p.logger.Info("no non-local connectors found")
	return false, nil
}

// DisableLocalAuth removes the local (password) connector.
// Returns an error if no other connectors are configured.
func (p *Provider) DisableLocalAuth(ctx context.Context) error {
	hasOthers, err := p.HasNonLocalConnectors(ctx)
	if err != nil {
		return err
	}
	if !hasOthers {
		return fmt.Errorf("cannot disable local authentication: no other identity providers configured")
	}

	// Check if local connector exists
	_, err = p.storage.GetConnector(ctx, "local")
	if errors.Is(err, storage.ErrNotFound) {
		// Already disabled
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to check local connector: %w", err)
	}

	// Delete the local connector
	if err := p.storage.DeleteConnector(ctx, "local"); err != nil {
		return fmt.Errorf("failed to delete local connector: %w", err)
	}

	p.logger.Info("local authentication disabled")
	return nil
}

// EnableLocalAuth creates the local (password) connector if it doesn't exist.
func (p *Provider) EnableLocalAuth(ctx context.Context) error {
	return ensureLocalConnector(ctx, p.storage)
}

// ensureStaticConnectors creates or updates static connectors in storage
func ensureStaticConnectors(ctx context.Context, stor storage.Storage, connectors []Connector) error {
	for _, conn := range connectors {
		storConn, err := conn.ToStorageConnector()
		if err != nil {
			return fmt.Errorf("failed to convert connector %s: %w", conn.ID, err)
		}
		_, err = stor.GetConnector(ctx, conn.ID)
		if err == storage.ErrNotFound {
			if err := stor.CreateConnector(ctx, storConn); err != nil {
				return fmt.Errorf("failed to create connector %s: %w", conn.ID, err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to get connector %s: %w", conn.ID, err)
		}
		if err := stor.UpdateConnector(ctx, conn.ID, func(old storage.Connector) (storage.Connector, error) {
			old.Name = storConn.Name
			old.Config = storConn.Config
			return old, nil
		}); err != nil {
			return fmt.Errorf("failed to update connector %s: %w", conn.ID, err)
		}
	}
	return nil
}

// CreateLDAPUser creates a new user entry in the LDAP directory using the connector's bind credentials.
// It derives uid from email (local part), and creates an inetOrgPerson with posixAccount attributes.
func CreateLDAPUser(cfg *LDAPConnectorConfig, email, password, fullName string) error {
	if cfg == nil {
		return fmt.Errorf("LDAP connector config is nil")
	}
	if email == "" || password == "" || fullName == "" {
		return fmt.Errorf("email, password and name are required")
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return fmt.Errorf("failed to bind to LDAP: %w", err)
	}

	parts := strings.SplitN(email, "@", 2)
	uid := parts[0]

	nameParts := strings.Fields(fullName)
	sn := nameParts[len(nameParts)-1]
	givenName := fullName
	if len(nameParts) > 1 {
		givenName = strings.Join(nameParts[:len(nameParts)-1], " ")
	}

	dn := fmt.Sprintf("uid=%s,%s", ldapv3.EscapeFilter(uid), cfg.UserSearchBaseDN)

	addReq := ldapv3.NewAddRequest(dn, nil)
	addReq.Attribute("objectClass", []string{"inetOrgPerson", "posixAccount", "shadowAccount"})
	addReq.Attribute("uid", []string{uid})
	addReq.Attribute("cn", []string{fullName})
	addReq.Attribute("sn", []string{sn})
	addReq.Attribute("givenName", []string{givenName})
	addReq.Attribute("mail", []string{email})
	addReq.Attribute("userPassword", []string{password})
	addReq.Attribute("uidNumber", []string{fmt.Sprintf("%d", generateUIDNumber(uid))})
	addReq.Attribute("gidNumber", []string{"500"})
	addReq.Attribute("homeDirectory", []string{fmt.Sprintf("/home/%s", uid)})
	addReq.Attribute("loginShell", []string{"/bin/bash"})

	if err := conn.Add(addReq); err != nil {
		return fmt.Errorf("failed to create LDAP user %q: %w", uid, err)
	}

	return nil
}

// DeleteLDAPUser removes a user entry from the LDAP directory.
func DeleteLDAPUser(cfg *LDAPConnectorConfig, email string) error {
	if cfg == nil {
		return fmt.Errorf("LDAP connector config is nil")
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return fmt.Errorf("failed to bind to LDAP: %w", err)
	}

	parts := strings.SplitN(email, "@", 2)
	uid := parts[0]
	dn := fmt.Sprintf("uid=%s,%s", ldapv3.EscapeFilter(uid), cfg.UserSearchBaseDN)

	if err := conn.Del(ldapv3.NewDelRequest(dn, nil)); err != nil {
		return fmt.Errorf("failed to delete LDAP user %q: %w", uid, err)
	}
	return nil
}

func dialLDAP(cfg *LDAPConnectorConfig) (*ldapv3.Conn, error) {
	host := cfg.Host
	if !strings.Contains(host, ":") {
		if cfg.InsecureNoSSL {
			host += ":389"
		} else {
			host += ":636"
		}
	}

	if cfg.InsecureNoSSL {
		conn, err := ldapv3.Dial("tcp", host)
		if err != nil {
			return nil, err
		}
		if cfg.StartTLS {
			tlsHost := strings.Split(host, ":")[0]
			if err := conn.StartTLS(&tls.Config{
				ServerName:         tlsHost,
				InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec
			}); err != nil {
				conn.Close()
				return nil, fmt.Errorf("StartTLS failed: %w", err)
			}
		}
		return conn, nil
	}

	tlsHost := strings.Split(host, ":")[0]
	return ldapv3.DialTLS("tcp", host, &tls.Config{
		ServerName:         tlsHost,
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec
	})
}

// UpdateLDAPUserPassword changes a user's password in the LDAP directory.
// It first verifies the old password by attempting a bind, then uses the admin
// credentials to perform the password modification.
func UpdateLDAPUserPassword(cfg *LDAPConnectorConfig, uid, oldPassword, newPassword string) error {
	if cfg == nil {
		return fmt.Errorf("LDAP connector config is nil")
	}

	userDN := fmt.Sprintf("uid=%s,%s", ldapv3.EscapeFilter(uid), cfg.UserSearchBaseDN)

	verifyConn, err := dialLDAP(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer verifyConn.Close()

	if err := verifyConn.Bind(userDN, oldPassword); err != nil {
		return fmt.Errorf("current password is incorrect")
	}

	adminConn, err := dialLDAP(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer adminConn.Close()

	if err := adminConn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return fmt.Errorf("failed to bind as admin: %w", err)
	}

	modReq := ldapv3.NewModifyRequest(userDN, nil)
	modReq.Replace("userPassword", []string{newPassword})
	if err := adminConn.Modify(modReq); err != nil {
		return fmt.Errorf("failed to update LDAP password: %w", err)
	}

	return nil
}

// ResetLDAPUserPassword resets an LDAP user's password using admin bind (no old password required).
func ResetLDAPUserPassword(cfg *LDAPConnectorConfig, uid, newPassword string) error {
	if cfg == nil {
		return fmt.Errorf("LDAP connector config is nil")
	}

	userDN := fmt.Sprintf("uid=%s,%s", ldapv3.EscapeFilter(uid), cfg.UserSearchBaseDN)

	conn, err := dialLDAP(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return fmt.Errorf("failed to bind as admin: %w", err)
	}

	modReq := ldapv3.NewModifyRequest(userDN, nil)
	modReq.Replace("userPassword", []string{newPassword})
	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("failed to reset LDAP password: %w", err)
	}

	return nil
}

// CheckUserInLDAPGroups checks if a user is a member of at least one of the required groups.
// Returns true if requiredGroups is empty (no restriction).
func CheckUserInLDAPGroups(cfg *LDAPConnectorConfig, email string) (bool, error) {
	if cfg == nil || len(cfg.RequiredGroups) == 0 {
		return true, nil
	}
	if cfg.GroupSearchBaseDN == "" {
		return false, fmt.Errorf("group search not configured but requiredGroups is set")
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return false, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return false, fmt.Errorf("failed to bind to LDAP: %w", err)
	}

	parts := strings.SplitN(email, "@", 2)
	uid := parts[0]
	userDN := fmt.Sprintf("uid=%s,%s", ldapv3.EscapeFilter(uid), cfg.UserSearchBaseDN)

	groupAttr := cfg.GroupSearchGroupAttr
	if groupAttr == "" {
		groupAttr = "member"
	}
	nameAttr := cfg.GroupSearchNameAttr
	if nameAttr == "" {
		nameAttr = "cn"
	}

	for _, requiredGroup := range cfg.RequiredGroups {
		groupDN := fmt.Sprintf("cn=%s,%s", ldapv3.EscapeFilter(requiredGroup), cfg.GroupSearchBaseDN)
		searchReq := ldapv3.NewSearchRequest(
			groupDN,
			ldapv3.ScopeBaseObject, ldapv3.NeverDerefAliases, 1, 0, false,
			fmt.Sprintf("(%s=%s)", ldapv3.EscapeFilter(groupAttr), ldapv3.EscapeFilter(userDN)),
			[]string{nameAttr},
			nil,
		)
		result, err := conn.Search(searchReq)
		if err != nil {
			continue
		}
		if len(result.Entries) > 0 {
			return true, nil
		}
	}

	return false, nil
}

// ListLDAPGroups returns all group names from the LDAP directory under the configured group search base.
func ListLDAPGroups(cfg *LDAPConnectorConfig) ([]string, error) {
	if cfg == nil || cfg.GroupSearchBaseDN == "" {
		return nil, fmt.Errorf("LDAP group search not configured")
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return nil, fmt.Errorf("failed to bind to LDAP: %w", err)
	}

	nameAttr := cfg.GroupSearchNameAttr
	if nameAttr == "" {
		nameAttr = "cn"
	}

	searchReq := ldapv3.NewSearchRequest(
		cfg.GroupSearchBaseDN,
		ldapv3.ScopeWholeSubtree, ldapv3.NeverDerefAliases, 0, 0, false,
		"(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))",
		[]string{nameAttr},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP groups: %w", err)
	}

	groups := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		name := entry.GetAttributeValue(nameAttr)
		if name != "" {
			groups = append(groups, name)
		}
	}
	return groups, nil
}

// CreateLDAPGroup creates a new groupOfNames in the LDAP directory.
func CreateLDAPGroup(cfg *LDAPConnectorConfig, groupName string) error {
	if cfg == nil || cfg.GroupSearchBaseDN == "" {
		return fmt.Errorf("LDAP group search not configured")
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return fmt.Errorf("failed to bind to LDAP: %w", err)
	}

	dn := fmt.Sprintf("cn=%s,%s", ldapv3.EscapeFilter(groupName), cfg.GroupSearchBaseDN)

	addReq := ldapv3.NewAddRequest(dn, nil)
	addReq.Attribute("objectClass", []string{"groupOfNames"})
	addReq.Attribute("cn", []string{groupName})
	// groupOfNames requires at least one member; use a placeholder that will be replaced
	addReq.Attribute("member", []string{""})

	if err := conn.Add(addReq); err != nil {
		return fmt.Errorf("failed to create LDAP group %q: %w", groupName, err)
	}
	return nil
}

// AddUserToLDAPGroups adds a user to the specified LDAP groups.
// Groups that don't exist will be created first.
func AddUserToLDAPGroups(cfg *LDAPConnectorConfig, email string, groupNames []string) error {
	if cfg == nil || cfg.GroupSearchBaseDN == "" || len(groupNames) == 0 {
		return nil
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return fmt.Errorf("failed to bind to LDAP: %w", err)
	}

	parts := strings.SplitN(email, "@", 2)
	uid := parts[0]
	userDN := fmt.Sprintf("uid=%s,%s", ldapv3.EscapeFilter(uid), cfg.UserSearchBaseDN)

	for _, groupName := range groupNames {
		groupDN := fmt.Sprintf("cn=%s,%s", ldapv3.EscapeFilter(groupName), cfg.GroupSearchBaseDN)

		// Check if group exists
		searchReq := ldapv3.NewSearchRequest(
			groupDN,
			ldapv3.ScopeBaseObject, ldapv3.NeverDerefAliases, 1, 0, false,
			"(objectClass=*)",
			[]string{"member"},
			nil,
		)
		result, err := conn.Search(searchReq)
		if err != nil || len(result.Entries) == 0 {
			// Group doesn't exist, create it with this user as first member
			addReq := ldapv3.NewAddRequest(groupDN, nil)
			addReq.Attribute("objectClass", []string{"groupOfNames"})
			addReq.Attribute("cn", []string{groupName})
			addReq.Attribute("member", []string{userDN})
			if createErr := conn.Add(addReq); createErr != nil {
				return fmt.Errorf("failed to create LDAP group %q: %w", groupName, createErr)
			}
			continue
		}

		// Group exists, check if user is already a member
		members := result.Entries[0].GetAttributeValues("member")
		alreadyMember := false
		for _, m := range members {
			if strings.EqualFold(m, userDN) {
				alreadyMember = true
				break
			}
		}
		if alreadyMember {
			continue
		}

		// Add user to group
		modReq := ldapv3.NewModifyRequest(groupDN, nil)
		modReq.Add("member", []string{userDN})
		if err := conn.Modify(modReq); err != nil {
			return fmt.Errorf("failed to add user to LDAP group %q: %w", groupName, err)
		}

		// Remove empty placeholder member if present
		for _, m := range members {
			if m == "" {
				cleanReq := ldapv3.NewModifyRequest(groupDN, nil)
				cleanReq.Delete("member", []string{""})
				_ = conn.Modify(cleanReq) // best effort
				break
			}
		}
	}
	return nil
}

// RemoveUserFromLDAPGroups removes a user from all LDAP groups.
func RemoveUserFromLDAPGroups(cfg *LDAPConnectorConfig, email string) error {
	if cfg == nil || cfg.GroupSearchBaseDN == "" {
		return nil
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return fmt.Errorf("failed to bind to LDAP: %w", err)
	}

	parts := strings.SplitN(email, "@", 2)
	uid := parts[0]
	userDN := fmt.Sprintf("uid=%s,%s", ldapv3.EscapeFilter(uid), cfg.UserSearchBaseDN)

	// Find all groups containing this user
	searchReq := ldapv3.NewSearchRequest(
		cfg.GroupSearchBaseDN,
		ldapv3.ScopeWholeSubtree, ldapv3.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(member=%s)", ldapv3.EscapeFilter(userDN)),
		[]string{"dn"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return fmt.Errorf("failed to search groups for user: %w", err)
	}

	for _, entry := range result.Entries {
		modReq := ldapv3.NewModifyRequest(entry.DN, nil)
		modReq.Delete("member", []string{userDN})
		if err := conn.Modify(modReq); err != nil {
			// If group requires at least one member, add placeholder
			addPlaceholder := ldapv3.NewModifyRequest(entry.DN, nil)
			addPlaceholder.Add("member", []string{""})
			_ = conn.Modify(addPlaceholder)
			retryDel := ldapv3.NewModifyRequest(entry.DN, nil)
			retryDel.Delete("member", []string{userDN})
			_ = conn.Modify(retryDel)
		}
	}
	return nil
}

func generateUIDNumber(uid string) int {
	h := 10000
	for _, c := range uid {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return (h % 55535) + 10000
}
