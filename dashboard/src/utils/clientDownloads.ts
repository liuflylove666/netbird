import type { Account } from "@/interfaces/Account";
import { GRPC_API_ORIGIN } from "@utils/netbird";

/** Official NetBird package CDN (default install UI). */
export const OFFICIAL_CLIENT_PKGS_BASE = "https://pkgs.netbird.io";

/** True when install instructions use `{management URL}/downloads/` instead of pkgs.netbird.io. */
export function isSelfHostedPkgsBase(pkgsBase: string): boolean {
  return pkgsBase !== OFFICIAL_CLIENT_PKGS_BASE;
}

/**
 * Base URL for client packages (install script, Windows/macOS/Linux artifacts).
 * When the account opts into self-hosted downloads and the dashboard has a management URL,
 * files are expected under `{GRPC_API_ORIGIN}/downloads/` on the management server
 * (see NB_CLIENT_DOWNLOADS_DIR).
 */
export function getClientPkgsBaseUrl(account: Account | undefined): string {
  if (
    account?.settings?.client_downloads_use_management_server &&
    GRPC_API_ORIGIN
  ) {
    return `${GRPC_API_ORIGIN.replace(/\/$/, "")}/downloads`;
  }
  return OFFICIAL_CLIENT_PKGS_BASE;
}

/** Docker Hub image for the NetBird client container, pinned to management version when known. */
export function getDockerClientImage(managementVersion: string | undefined): string {
  const tag = normalizeDockerTag(managementVersion);
  return `netbirdio/netbird:${tag}`;
}

function normalizeDockerTag(v: string | undefined): string {
  if (!v) return "latest";
  const t = v.trim().toLowerCase();
  if (t === "development" || t === "dev" || t === "latest") return "latest";
  return v.replace(/^v/i, "");
}
