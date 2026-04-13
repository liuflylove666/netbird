import Button from "@components/Button";
import Code from "@components/Code";
import HelpText from "@components/HelpText";
import { Input } from "@components/Input";
import { Label } from "@components/Label";
import {
  Modal,
  ModalClose,
  ModalContent,
  ModalFooter,
} from "@components/modal/Modal";
import ModalHeader from "@components/modal/ModalHeader";
import { notify } from "@components/Notification";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@components/Select";
import Separator from "@components/Separator";
import { useApiCall } from "@utils/api";
import loadConfig from "@utils/config";
import { trim } from "lodash";
import {
  ChevronDown,
  ChevronUp,
  FingerprintIcon,
  GlobeIcon,
  IdCard,
  KeyIcon,
  PlusCircle,
  SaveIcon,
  ServerIcon,
  TagIcon,
} from "lucide-react";
import React, { useMemo, useState } from "react";
import { useSWRConfig } from "swr";
import { usePermissions } from "@/contexts/PermissionsProvider";
import {
  IdentityProviderLDAP,
  SSOIdentityProvider,
  SSOIdentityProviderOptions,
  SSOIdentityProviderRequest,
  SSOIdentityProviderType,
} from "@/interfaces/IdentityProvider";
import { idpIcon } from "@/assets/icons/IdentityProviderIcons";

const issuerHints: Partial<Record<SSOIdentityProviderType, string>> = {
  keycloak: "https://keycloak.example.com/realms/{REALM}",
  authentik: "https://authentik.example.com/application/o/{APP_SLUG}/",
  zitadel: "https://{INSTANCE}.zitadel.cloud",
  okta: "https://{ORG}.okta.com",
  entra: "https://login.microsoftonline.com/{TENANT_ID}/v2.0",
  pocketid: "https://pocketid.example.com",
};

const defaultNames: Record<SSOIdentityProviderType, string> = {
  oidc: "Generic OIDC",
  ldap: "OpenLDAP",
  google: "Google",
  microsoft: "Microsoft",
  entra: "Microsoft Entra",
  okta: "Okta",
  zitadel: "Zitadel",
  pocketid: "PocketID",
  authentik: "Authentik",
  keycloak: "Keycloak",
};

type Props = {
  open: boolean;
  onClose: () => void;
  provider?: SSOIdentityProvider | null;
};

const copyMessage = "Redirect URL was copied to your clipboard!";
const config = loadConfig();
const redirectUrl = `${config.apiOrigin}/oauth2/callback`;

export default function IdentityProviderModal({
  open,
  onClose,
  provider,
}: Readonly<Props>) {
  const { mutate } = useSWRConfig();
  const { permission } = usePermissions();
  const isEditing = !!provider;

  const createRequest = useApiCall<SSOIdentityProvider>("/identity-providers");
  const updateRequest = useApiCall<SSOIdentityProvider>(
    "/identity-providers/" + provider?.id,
  );

  const [type, setType] = useState<SSOIdentityProviderType>(
    provider?.type ?? "oidc",
  );
  const [name, setName] = useState(provider?.name ?? "");
  const [issuer, setIssuer] = useState(provider?.issuer ?? "");
  const [clientId, setClientId] = useState(provider?.client_id ?? "");
  const [clientSecret, setClientSecret] = useState("");

  const isLdap = type === "ldap";

  const [ldapHost, setLdapHost] = useState(provider?.ldap?.host ?? "");
  const [ldapInsecureNoSSL, setLdapInsecureNoSSL] = useState(
    provider?.ldap?.insecure_no_ssl ?? true,
  );
  const [ldapInsecureSkipVerify, setLdapInsecureSkipVerify] = useState(
    provider?.ldap?.insecure_skip_verify ?? false,
  );
  const [ldapStartTLS, setLdapStartTLS] = useState(
    provider?.ldap?.start_tls ?? false,
  );
  const [ldapBindDN, setLdapBindDN] = useState(provider?.ldap?.bind_dn ?? "");
  const [ldapBindPW, setLdapBindPW] = useState(provider?.ldap?.bind_pw ?? "");
  const [ldapUserSearchBaseDN, setLdapUserSearchBaseDN] = useState(
    provider?.ldap?.user_search_base_dn ?? "",
  );
  const [ldapUserSearchUsername, setLdapUserSearchUsername] = useState(
    provider?.ldap?.user_search_username ?? "mail",
  );
  const [ldapUserSearchIDAttr, setLdapUserSearchIDAttr] = useState(
    provider?.ldap?.user_search_id_attr ?? "uid",
  );
  const [ldapUserSearchEmailAttr, setLdapUserSearchEmailAttr] = useState(
    provider?.ldap?.user_search_email_attr ?? "mail",
  );
  const [ldapUserSearchNameAttr, setLdapUserSearchNameAttr] = useState(
    provider?.ldap?.user_search_name_attr ?? "cn",
  );
  const [ldapGroupSearchBaseDN, setLdapGroupSearchBaseDN] = useState(
    provider?.ldap?.group_search_base_dn ?? "",
  );
  const [ldapGroupSearchNameAttr, setLdapGroupSearchNameAttr] = useState(
    provider?.ldap?.group_search_name_attr ?? "cn",
  );
  const [ldapGroupSearchUserAttr, setLdapGroupSearchUserAttr] = useState(
    provider?.ldap?.group_search_user_attr ?? "DN",
  );
  const [ldapGroupSearchGroupAttr, setLdapGroupSearchGroupAttr] = useState(
    provider?.ldap?.group_search_group_attr ?? "member",
  );
  const [ldapRequiredGroups, setLdapRequiredGroups] = useState<string[]>(
    provider?.ldap?.required_groups ?? [],
  );
  const [newRequiredGroup, setNewRequiredGroup] = useState("");

  const [showAdvanced, setShowAdvanced] = useState(false);

  const requiresIssuer = !isLdap && type !== "google" && type !== "microsoft";
  const requiresOIDCFields = !isLdap;

  const clientIdChanged = isEditing && trim(clientId) !== provider?.client_id;

  const isDisabled = useMemo(() => {
    const trimmedName = trim(name);
    if (trimmedName.length === 0) return true;

    if (isLdap) {
      if (trim(ldapHost).length === 0) return true;
      if (trim(ldapBindDN).length === 0) return true;
      if (trim(ldapUserSearchBaseDN).length === 0) return true;
      if (!isEditing && trim(ldapBindPW).length === 0) return true;
      return false;
    }

    const trimmedIssuer = trim(issuer);
    const trimmedClientId = trim(clientId);
    const trimmedClientSecret = trim(clientSecret);

    if (requiresIssuer && trimmedIssuer.length === 0) return true;
    if (trimmedClientId.length === 0) return true;
    if ((!isEditing || clientIdChanged) && trimmedClientSecret.length === 0)
      return true;

    return false;
  }, [
    name,
    issuer,
    clientId,
    clientSecret,
    isEditing,
    clientIdChanged,
    requiresIssuer,
    isLdap,
    ldapHost,
    ldapBindDN,
    ldapBindPW,
    ldapUserSearchBaseDN,
  ]);

  const submit = () => {
    const payload: SSOIdentityProviderRequest = {
      type,
      name: trim(name),
      issuer: isLdap ? "" : trim(issuer),
      client_id: isLdap ? "" : trim(clientId),
      client_secret: isLdap ? "" : trim(clientSecret),
    };

    if (isLdap) {
      const ldapConfig: IdentityProviderLDAP = {
        host: trim(ldapHost),
        insecure_no_ssl: ldapInsecureNoSSL,
        insecure_skip_verify: ldapInsecureSkipVerify,
        start_tls: ldapStartTLS,
        bind_dn: trim(ldapBindDN),
        bind_pw: trim(ldapBindPW),
        user_search_base_dn: trim(ldapUserSearchBaseDN),
        user_search_username: trim(ldapUserSearchUsername) || "mail",
        user_search_id_attr: trim(ldapUserSearchIDAttr) || "uid",
        user_search_email_attr: trim(ldapUserSearchEmailAttr) || "mail",
        user_search_name_attr: trim(ldapUserSearchNameAttr) || "cn",
        group_search_base_dn: trim(ldapGroupSearchBaseDN),
        group_search_name_attr: trim(ldapGroupSearchNameAttr) || "cn",
        group_search_user_attr: trim(ldapGroupSearchUserAttr) || "DN",
        group_search_group_attr: trim(ldapGroupSearchGroupAttr) || "member",
        required_groups: ldapRequiredGroups.length > 0 ? ldapRequiredGroups : undefined,
      };
      payload.ldap = ldapConfig;
    }

    if (isEditing) {
      notify({
        title: "Update Identity Provider",
        description: "Identity provider was updated successfully.",
        promise: updateRequest.put(payload).then(() => {
          mutate("/identity-providers");
          onClose();
        }),
        loadingMessage: "Updating identity provider...",
      });
    } else {
      notify({
        title: "Create Identity Provider",
        description: "Identity provider was created successfully.",
        promise: createRequest.post(payload).then(() => {
          mutate("/identity-providers");
          onClose();
        }),
        loadingMessage: "Creating identity provider...",
      });
    }
  };

  return (
    <>
      <Modal
        open={open}
        onOpenChange={(state) => !state && onClose()}
        key={open ? 1 : 0}
      >
        <ModalContent maxWidthClass={"max-w-xl"}>
          <ModalHeader
            icon={<FingerprintIcon size={20} />}
            title={
              isEditing ? "Edit Identity Provider" : "Add Identity Provider"
            }
            description={
              isEditing
                ? "Update the identity provider configuration"
                : "Configure a new identity provider for authentication"
            }
            color={"netbird"}
          />

          <Separator />

          <div className={"px-8 py-6 flex flex-col gap-6 max-h-[70vh] overflow-y-auto"}>
            <div>
              <Label>Provider Type</Label>
              <HelpText>Select the type of identity provider</HelpText>
              <Select
                value={type}
                onValueChange={(v) => {
                  const newType = v as SSOIdentityProviderType;
                  setType(newType);
                  if (!isEditing) {
                    setName(defaultNames[newType]);
                  }
                }}
              >
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="Select provider type..." />
                </SelectTrigger>
                <SelectContent>
                  {SSOIdentityProviderOptions.map((idp) => (
                    <SelectItem key={idp.value} value={idp.value}>
                      <div className="flex items-center gap-2">
                        {idpIcon(idp.value)}
                        <span>{idp.label}</span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label>Name</Label>
              <HelpText>A friendly name to identify this provider</HelpText>
              <Input
                placeholder={"e.g., Corporate SSO"}
                value={name}
                onChange={(e) => setName(e.target.value)}
                customPrefix={
                  <TagIcon size={16} className="text-nb-gray-300" />
                }
              />
            </div>

            {isLdap ? (
              <>
                <Separator />
                <h3 className="text-sm font-medium text-nb-gray-200">
                  LDAP Server Connection
                </h3>

                <div>
                  <Label>Host</Label>
                  <HelpText>
                    LDAP server host and port (e.g. ldap.example.com:389)
                  </HelpText>
                  <Input
                    placeholder={"openldap:389"}
                    value={ldapHost}
                    onChange={(e) => setLdapHost(e.target.value)}
                    customPrefix={
                      <ServerIcon size={16} className="text-nb-gray-300" />
                    }
                  />
                </div>

                <div className="flex flex-col gap-3">
                  <div className="flex items-center gap-4">
                    <label className="flex items-center gap-2 cursor-pointer text-sm text-nb-gray-300">
                      <input
                        type="checkbox"
                        checked={ldapInsecureNoSSL}
                        onChange={(e) => setLdapInsecureNoSSL(e.target.checked)}
                        className="rounded border-nb-gray-700"
                      />
                      No SSL
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer text-sm text-nb-gray-300">
                      <input
                        type="checkbox"
                        checked={ldapInsecureSkipVerify}
                        onChange={(e) =>
                          setLdapInsecureSkipVerify(e.target.checked)
                        }
                        className="rounded border-nb-gray-700"
                      />
                      Skip TLS Verify
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer text-sm text-nb-gray-300">
                      <input
                        type="checkbox"
                        checked={ldapStartTLS}
                        onChange={(e) => setLdapStartTLS(e.target.checked)}
                        className="rounded border-nb-gray-700"
                      />
                      StartTLS
                    </label>
                  </div>
                </div>

                <div>
                  <Label>Bind DN</Label>
                  <HelpText>
                    Distinguished name used to bind to the LDAP server
                  </HelpText>
                  <Input
                    placeholder={"cn=admin,dc=example,dc=org"}
                    value={ldapBindDN}
                    onChange={(e) => setLdapBindDN(e.target.value)}
                  />
                </div>

                <div>
                  <Label>Bind Password</Label>
                  <HelpText>
                    {isEditing
                      ? "Leave empty to keep the existing password"
                      : "Password for the bind DN"}
                  </HelpText>
                  <Input
                    type="password"
                    placeholder={isEditing ? "••••••••" : "Enter bind password"}
                    value={ldapBindPW}
                    onChange={(e) => setLdapBindPW(e.target.value)}
                    customPrefix={
                      <KeyIcon size={16} className="text-nb-gray-300" />
                    }
                  />
                </div>

                <Separator />
                <h3 className="text-sm font-medium text-nb-gray-200">
                  User Search
                </h3>

                <div>
                  <Label>User Search Base DN</Label>
                  <HelpText>Base DN for searching users</HelpText>
                  <Input
                    placeholder={"ou=users,dc=example,dc=org"}
                    value={ldapUserSearchBaseDN}
                    onChange={(e) => setLdapUserSearchBaseDN(e.target.value)}
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>Username Attr</Label>
                    <HelpText>Login username attribute</HelpText>
                    <Input
                      placeholder={"mail"}
                      value={ldapUserSearchUsername}
                      onChange={(e) => setLdapUserSearchUsername(e.target.value)}
                    />
                  </div>
                  <div>
                    <Label>ID Attr</Label>
                    <HelpText>Unique user ID attribute</HelpText>
                    <Input
                      placeholder={"uid"}
                      value={ldapUserSearchIDAttr}
                      onChange={(e) => setLdapUserSearchIDAttr(e.target.value)}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>Email Attr</Label>
                    <HelpText>User email attribute</HelpText>
                    <Input
                      placeholder={"mail"}
                      value={ldapUserSearchEmailAttr}
                      onChange={(e) =>
                        setLdapUserSearchEmailAttr(e.target.value)
                      }
                    />
                  </div>
                  <div>
                    <Label>Name Attr</Label>
                    <HelpText>User display name attribute</HelpText>
                    <Input
                      placeholder={"cn"}
                      value={ldapUserSearchNameAttr}
                      onChange={(e) =>
                        setLdapUserSearchNameAttr(e.target.value)
                      }
                    />
                  </div>
                </div>

                <div>
                  <button
                    type="button"
                    onClick={() => setShowAdvanced(!showAdvanced)}
                    className="flex items-center gap-1 text-sm text-nb-gray-400 hover:text-nb-gray-200 transition-colors"
                  >
                    {showAdvanced ? (
                      <ChevronUp size={14} />
                    ) : (
                      <ChevronDown size={14} />
                    )}
                    Group Search (Optional)
                  </button>
                </div>

                {showAdvanced && (
                  <>
                    <div>
                      <Label>Group Search Base DN</Label>
                      <HelpText>Base DN for searching groups</HelpText>
                      <Input
                        placeholder={"ou=groups,dc=example,dc=org"}
                        value={ldapGroupSearchBaseDN}
                        onChange={(e) =>
                          setLdapGroupSearchBaseDN(e.target.value)
                        }
                      />
                    </div>

                    <div className="grid grid-cols-3 gap-3">
                      <div>
                        <Label>Name Attr</Label>
                        <Input
                          placeholder={"cn"}
                          value={ldapGroupSearchNameAttr}
                          onChange={(e) =>
                            setLdapGroupSearchNameAttr(e.target.value)
                          }
                        />
                      </div>
                      <div>
                        <Label>User Attr</Label>
                        <Input
                          placeholder={"DN"}
                          value={ldapGroupSearchUserAttr}
                          onChange={(e) =>
                            setLdapGroupSearchUserAttr(e.target.value)
                          }
                        />
                      </div>
                      <div>
                        <Label>Group Attr</Label>
                        <Input
                          placeholder={"member"}
                          value={ldapGroupSearchGroupAttr}
                          onChange={(e) =>
                            setLdapGroupSearchGroupAttr(e.target.value)
                          }
                        />
                      </div>
                    </div>

                    <Separator />
                    <div>
                      <Label>Required Groups (Login Restriction)</Label>
                      <HelpText>
                        Only users in these LDAP groups can log in. Leave empty
                        to allow all LDAP users.
                      </HelpText>
                      <div className="flex flex-wrap gap-2 mb-2">
                        {ldapRequiredGroups.map((g) => (
                          <span
                            key={g}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded-md bg-nb-gray-800 text-sm text-nb-gray-200 border border-nb-gray-700"
                          >
                            {g}
                            <button
                              type="button"
                              onClick={() =>
                                setLdapRequiredGroups((prev) =>
                                  prev.filter((x) => x !== g),
                                )
                              }
                              className="ml-1 text-nb-gray-400 hover:text-red-400 transition-colors"
                            >
                              ×
                            </button>
                          </span>
                        ))}
                      </div>
                      <div className="flex gap-2">
                        <Input
                          className="flex-1"
                          placeholder="e.g. netbird-users"
                          value={newRequiredGroup}
                          onChange={(e) => setNewRequiredGroup(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              e.preventDefault();
                              const v = newRequiredGroup.trim();
                              if (v && !ldapRequiredGroups.includes(v)) {
                                setLdapRequiredGroups((prev) => [...prev, v]);
                              }
                              setNewRequiredGroup("");
                            }
                          }}
                        />
                        <Button
                          variant="secondary"
                          className="shrink-0"
                          disabled={!newRequiredGroup.trim()}
                          onClick={() => {
                            const v = newRequiredGroup.trim();
                            if (v && !ldapRequiredGroups.includes(v)) {
                              setLdapRequiredGroups((prev) => [...prev, v]);
                            }
                            setNewRequiredGroup("");
                          }}
                        >
                          Add
                        </Button>
                      </div>
                    </div>
                  </>
                )}
              </>
            ) : (
              <>
                {requiresIssuer && (
                  <div>
                    <Label>Issuer URL</Label>
                    <HelpText>The OIDC issuer URL for this provider</HelpText>
                    <Input
                      placeholder={
                        issuerHints[type] ?? "https://login.example.com"
                      }
                      value={issuer}
                      onChange={(e) => setIssuer(e.target.value)}
                      customPrefix={
                        <GlobeIcon size={16} className="text-nb-gray-300" />
                      }
                    />
                  </div>
                )}

                <div>
                  <Label>Client ID</Label>
                  <HelpText>The OAuth2 confidential client ID</HelpText>
                  <Input
                    placeholder={"Enter client ID"}
                    value={clientId}
                    onChange={(e) => setClientId(e.target.value)}
                    customPrefix={
                      <IdCard size={16} className="text-nb-gray-300" />
                    }
                  />
                </div>

                <div>
                  <Label>Client Secret</Label>
                  <HelpText>
                    {isEditing
                      ? clientIdChanged
                        ? "Required when client ID is changed"
                        : "Leave empty to keep the existing secret, or enter a new one"
                      : "The OAuth2 client secret"}
                  </HelpText>
                  <Input
                    type="password"
                    placeholder={
                      isEditing ? "••••••••" : "Enter client secret"
                    }
                    value={clientSecret}
                    onChange={(e) => setClientSecret(e.target.value)}
                    customPrefix={
                      <KeyIcon size={16} className="text-nb-gray-300" />
                    }
                  />
                </div>

                <Separator />

                <div>
                  <Label>Redirect / Callback URL</Label>
                  <HelpText>
                    Copy this URL to your identity provider configuration
                  </HelpText>
                  <Code codeToCopy={redirectUrl} message={copyMessage}>
                    <Code.Line>{redirectUrl}</Code.Line>
                  </Code>
                </div>
              </>
            )}
          </div>

          <ModalFooter className={"items-center"}>
            <div className={"flex gap-3 w-full justify-end"}>
              <ModalClose asChild={true}>
                <Button variant={"secondary"}>Cancel</Button>
              </ModalClose>

              <Button
                variant={"primary"}
                onClick={submit}
                disabled={
                  isDisabled ||
                  (isEditing
                    ? !permission.identity_providers.update
                    : !permission.identity_providers.create)
                }
              >
                {isEditing ? (
                  <>
                    <SaveIcon size={16} />
                    Save Changes
                  </>
                ) : (
                  <>
                    <PlusCircle size={16} />
                    Add Provider
                  </>
                )}
              </Button>
            </div>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </>
  );
}
