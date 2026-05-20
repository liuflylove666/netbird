export const OIDC_AUTH_ERROR_KEY = "netbird-oidc-auth-error";

export function storeOidcAuthError(data: unknown): void {
  try {
    const message =
      data instanceof Error
        ? data.message
        : typeof data === "string"
          ? data
          : JSON.stringify(data);
    sessionStorage.setItem(OIDC_AUTH_ERROR_KEY, message);
  } catch {}
}

export function readOidcAuthError(): string | null {
  try {
    return sessionStorage.getItem(OIDC_AUTH_ERROR_KEY);
  } catch {
    return null;
  }
}

export function clearOidcAuthError(): void {
  try {
    sessionStorage.removeItem(OIDC_AUTH_ERROR_KEY);
  } catch {}
}
