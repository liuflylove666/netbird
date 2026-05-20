import { OidcUserStatus, useOidc, useOidcUser } from "@axa-fr/react-oidc";
import Button from "@components/Button";
import Paragraph from "@components/Paragraph";
import loadConfig from "@utils/config";
import { ArrowRightIcon, RefreshCw } from "lucide-react";
import { useSearchParams } from "next/navigation";
import * as React from "react";
import { useEffect, useMemo, useState } from "react";
import NetBirdIcon from "@/assets/icons/NetBirdIcon";
import {
  clearOidcAuthError,
  readOidcAuthError,
} from "@/auth/oidcAuthError";

const config = loadConfig();

export const OIDCError = () => {
  const { oidcUserLoadingState } = useOidcUser();
  const params = useSearchParams();
  const errorParam = params.get("error");
  const accessDenied = errorParam === "access_denied";
  const [title, setTitle] = useState(params.get("error_description"));
  const errorDescription = params.get("error_description");
  const { logout } = useOidc();
  const [storedError, setStoredError] = useState<string | null>(null);

  useEffect(() => {
    setStoredError(readOidcAuthError());
  }, []);

  const errorMessage = useMemo(() => {
    if (errorParam && errorDescription) {
      return `${errorParam}: ${errorDescription}`;
    }
    if (errorParam) {
      return errorParam;
    }
    if (storedError) {
      return storedError;
    }
    if (oidcUserLoadingState === OidcUserStatus.Unauthenticated) {
      return "Session exchange failed. Your login may have succeeded, but the dashboard could not obtain a token.";
    }
    return oidcUserLoadingState;
  }, [errorDescription, errorParam, oidcUserLoadingState, storedError]);

  useEffect(() => {
    if (accessDenied) {
      if (title === "account linked successfully") {
        setTitle(
          "Your account has been linked successfully. Please log in again to complete the setup.",
        );
      }
    } else {
      setTitle("Oops, something went wrong");
    }
  }, [accessDenied, title]);

  const handleLogout = () => {
    clearOidcAuthError();
    logout("/", { client_id: config.clientId });
  };

  const handleTryAgain = () => {
    clearOidcAuthError();
    logout("/", { client_id: config.clientId });
  };

  return (
    <div
      className={
        "flex items-center justify-center flex-col h-screen max-w-lg mx-auto"
      }
    >
      <div
        className={
          "bg-nb-gray-930 mb-3 border border-nb-gray-900 h-12 w-12 rounded-md flex items-center justify-center "
        }
      >
        <NetBirdIcon size={23} />
      </div>
      <h1 className={"text-center mt-2"}>{title}</h1>

      {accessDenied ? (
        <>
          <Paragraph className={"text-center mt-2"}>
            Already verified your email address?
          </Paragraph>

          <Button
            variant={"primary"}
            size={"sm"}
            className={"mt-5"}
            onClick={handleLogout}
          >
            Continue
            <ArrowRightIcon size={16} />
          </Button>

          <Button
            variant={"default-outline"}
            size={"sm"}
            className={"mt-5"}
            onClick={handleLogout}
          >
            Trouble logging in? Try again.
          </Button>
        </>
      ) : (
        <>
          <Paragraph className={"text-center mt-2 block"}>
            There was an error logging you in. <br />
            Error: <span className={"inline"}>{errorMessage}</span>
          </Paragraph>
          {!errorParam && (
            <Paragraph className={"text-center mt-3 text-sm text-nb-gray-400"}>
              Try again in a normal browser window without privacy extensions.
              Do not refresh the login callback page.
            </Paragraph>
          )}
          <div className={"mt-5 flex flex-col gap-3"}>
            <Button variant={"primary"} size={"sm"} onClick={handleTryAgain}>
              <RefreshCw size={16} className={"mr-2"} />
              Try Again
            </Button>
            <Button variant={"default-outline"} size={"sm"} onClick={handleLogout}>
              Logout
            </Button>
          </div>
        </>
      )}
    </div>
  );
};
