package idp

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// handler handles identity provider HTTP endpoints
type handler struct {
	accountManager account.Manager
}

// AddEndpoints registers identity provider endpoints
func AddEndpoints(accountManager account.Manager, router *mux.Router) {
	h := newHandler(accountManager)
	router.HandleFunc("/identity-providers", h.getAllIdentityProviders).Methods("GET", "OPTIONS")
	router.HandleFunc("/identity-providers", h.createIdentityProvider).Methods("POST", "OPTIONS")
	router.HandleFunc("/identity-providers/{idpId}", h.getIdentityProvider).Methods("GET", "OPTIONS")
	router.HandleFunc("/identity-providers/{idpId}", h.updateIdentityProvider).Methods("PUT", "OPTIONS")
	router.HandleFunc("/identity-providers/{idpId}", h.deleteIdentityProvider).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/identity-providers/{idpId}/ldap-groups", h.getLDAPGroups).Methods("GET", "OPTIONS")
}

func newHandler(accountManager account.Manager) *handler {
	return &handler{
		accountManager: accountManager,
	}
}

// getAllIdentityProviders returns all identity providers for the account
func (h *handler) getAllIdentityProviders(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	providers, err := h.accountManager.GetIdentityProviders(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	response := make([]api.IdentityProvider, 0, len(providers))
	for _, p := range providers {
		response = append(response, toAPIResponse(p))
	}

	util.WriteJSONObject(r.Context(), w, response)
}

// getIdentityProvider returns a specific identity provider
func (h *handler) getIdentityProvider(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	vars := mux.Vars(r)
	idpID := vars["idpId"]
	if idpID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "identity provider ID is required"), w)
		return
	}

	provider, err := h.accountManager.GetIdentityProvider(r.Context(), accountID, idpID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toAPIResponse(provider))
}

// createIdentityProvider creates a new identity provider
func (h *handler) createIdentityProvider(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	var req api.IdentityProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	idp := fromAPIRequest(&req)

	created, err := h.accountManager.CreateIdentityProvider(r.Context(), accountID, userID, idp)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toAPIResponse(created))
}

// updateIdentityProvider updates an existing identity provider
func (h *handler) updateIdentityProvider(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	vars := mux.Vars(r)
	idpID := vars["idpId"]
	if idpID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "identity provider ID is required"), w)
		return
	}

	var req api.IdentityProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	idp := fromAPIRequest(&req)

	updated, err := h.accountManager.UpdateIdentityProvider(r.Context(), accountID, idpID, userID, idp)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toAPIResponse(updated))
}

// deleteIdentityProvider deletes an identity provider
func (h *handler) deleteIdentityProvider(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	vars := mux.Vars(r)
	idpID := vars["idpId"]
	if idpID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "identity provider ID is required"), w)
		return
	}

	if err := h.accountManager.DeleteIdentityProvider(r.Context(), accountID, idpID, userID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

// getLDAPGroups returns all LDAP groups for a specific LDAP identity provider
func (h *handler) getLDAPGroups(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	vars := mux.Vars(r)
	idpID := vars["idpId"]
	if idpID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "identity provider ID is required"), w)
		return
	}

	groups, err := h.accountManager.ListLDAPGroups(r.Context(), accountID, idpID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, groups)
}

func toAPIResponse(idp *types.IdentityProvider) api.IdentityProvider {
	resp := api.IdentityProvider{
		Type:     api.IdentityProviderType(idp.Type),
		Name:     idp.Name,
		Issuer:   idp.Issuer,
		ClientId: idp.ClientID,
	}
	if idp.ID != "" {
		resp.Id = &idp.ID
	}
	if idp.Type == types.IdentityProviderTypeLDAP {
		resp.Ldap = &api.IdentityProviderLDAP{
			Host:                 idp.LDAPHost,
			InsecureNoSSL:        idp.LDAPInsecureNoSSL,
			InsecureSkipVerify:   idp.LDAPInsecureSkipVerify,
			StartTLS:             idp.LDAPStartTLS,
			RootCA:               idp.LDAPRootCA,
			BindDN:               idp.LDAPBindDN,
			UserSearchBaseDN:     idp.LDAPUserSearchBaseDN,
			UserSearchFilter:     idp.LDAPUserSearchFilter,
			UserSearchUsername:   idp.LDAPUserSearchUsername,
			UserSearchIDAttr:     idp.LDAPUserSearchIDAttr,
			UserSearchEmailAttr:  idp.LDAPUserSearchEmailAttr,
			UserSearchNameAttr:   idp.LDAPUserSearchNameAttr,
			GroupSearchBaseDN:    idp.LDAPGroupSearchBaseDN,
			GroupSearchFilter:    idp.LDAPGroupSearchFilter,
			GroupSearchUserAttr:  idp.LDAPGroupSearchUserAttr,
			GroupSearchGroupAttr: idp.LDAPGroupSearchGroupAttr,
			GroupSearchNameAttr:  idp.LDAPGroupSearchNameAttr,
			RequiredGroups:       idp.GetRequiredGroups(),
		}
	}
	return resp
}

func fromAPIRequest(req *api.IdentityProviderRequest) *types.IdentityProvider {
	idp := &types.IdentityProvider{
		Type:         types.IdentityProviderType(req.Type),
		Name:         req.Name,
		Issuer:       req.Issuer,
		ClientID:     req.ClientId,
		ClientSecret: req.ClientSecret,
	}
	if req.Ldap != nil {
		idp.LDAPHost = req.Ldap.Host
		idp.LDAPInsecureNoSSL = req.Ldap.InsecureNoSSL
		idp.LDAPInsecureSkipVerify = req.Ldap.InsecureSkipVerify
		idp.LDAPStartTLS = req.Ldap.StartTLS
		idp.LDAPRootCA = req.Ldap.RootCA
		idp.LDAPBindDN = req.Ldap.BindDN
		idp.LDAPBindPW = req.Ldap.BindPW
		idp.LDAPUserSearchBaseDN = req.Ldap.UserSearchBaseDN
		idp.LDAPUserSearchFilter = req.Ldap.UserSearchFilter
		idp.LDAPUserSearchUsername = req.Ldap.UserSearchUsername
		idp.LDAPUserSearchIDAttr = req.Ldap.UserSearchIDAttr
		idp.LDAPUserSearchEmailAttr = req.Ldap.UserSearchEmailAttr
		idp.LDAPUserSearchNameAttr = req.Ldap.UserSearchNameAttr
		idp.LDAPGroupSearchBaseDN = req.Ldap.GroupSearchBaseDN
		idp.LDAPGroupSearchFilter = req.Ldap.GroupSearchFilter
		idp.LDAPGroupSearchUserAttr = req.Ldap.GroupSearchUserAttr
		idp.LDAPGroupSearchGroupAttr = req.Ldap.GroupSearchGroupAttr
		idp.LDAPGroupSearchNameAttr = req.Ldap.GroupSearchNameAttr
		if len(req.Ldap.RequiredGroups) > 0 {
			idp.SetRequiredGroups(req.Ldap.RequiredGroups)
		}
	}
	return idp
}
