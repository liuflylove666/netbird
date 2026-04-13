export interface GoogleWorkspaceIntegration {
  id: string;
  customer_id: string;
  sync_interval: number;
  enabled: boolean;
  group_prefixes: string[];
  user_group_prefixes: string[];
  connector_id?: string;
}

export interface AzureADIntegration {
  id: string;
  client_id: string;
  tenant_id: string;
  sync_interval: number;
  enabled: boolean;
  group_prefixes: string[];
  user_group_prefixes: string[];
  connector_id?: string;
}

export interface OktaIntegration {
  id: string;
  enabled: boolean;
  group_prefixes: string[];
  user_group_prefixes: string[];
  auth_token: string;
  connection_name?: string;
  connector_id?: string;
}

export interface IdentityProviderLog {
  id: number;
  level: string;
  timestamp: Date;
}

export type SSOIdentityProviderType =
  | "oidc"
  | "ldap"
  | "zitadel"
  | "entra"
  | "google"
  | "okta"
  | "pocketid"
  | "microsoft"
  | "authentik"
  | "keycloak";

export const SSOIdentityProviderOptions: {
  value: SSOIdentityProviderType;
  label: string;
}[] = [
  { value: "oidc", label: "OIDC (Generic)" },
  { value: "ldap", label: "LDAP / OpenLDAP" },
  { value: "google", label: "Google" },
  { value: "microsoft", label: "Microsoft" },
  { value: "entra", label: "Microsoft Entra" },
  { value: "okta", label: "Okta" },
  { value: "zitadel", label: "Zitadel" },
  { value: "pocketid", label: "PocketID" },
  { value: "authentik", label: "Authentik" },
  { value: "keycloak", label: "Keycloak" },
];

export const getSSOIdentityProviderLabelByType = (
  type: SSOIdentityProviderType,
) => {
  return (
    SSOIdentityProviderOptions.find((option) => option.value === type)?.label ??
    type
  );
};

export interface IdentityProviderLDAP {
  host: string;
  insecure_no_ssl?: boolean;
  insecure_skip_verify?: boolean;
  start_tls?: boolean;
  root_ca?: string;
  bind_dn: string;
  bind_pw?: string;
  user_search_base_dn: string;
  user_search_filter?: string;
  user_search_username?: string;
  user_search_id_attr?: string;
  user_search_email_attr?: string;
  user_search_name_attr?: string;
  group_search_base_dn?: string;
  group_search_filter?: string;
  group_search_user_attr?: string;
  group_search_group_attr?: string;
  group_search_name_attr?: string;
  required_groups?: string[];
}

export interface SSOIdentityProvider {
  id: string;
  type: SSOIdentityProviderType;
  name: string;
  issuer: string;
  client_id: string;
  redirect_url?: string;
  ldap?: IdentityProviderLDAP;
}

export interface SSOIdentityProviderRequest {
  type: SSOIdentityProviderType;
  name: string;
  issuer: string;
  client_id: string;
  client_secret: string;
  ldap?: IdentityProviderLDAP;
}
