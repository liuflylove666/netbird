"use client";

import FullTooltip from "@components/FullTooltip";
import { cn } from "@utils/helpers";
import { ArrowUpCircle } from "lucide-react";
import * as React from "react";
import Skeleton from "react-loading-skeleton";
import useFetchApi from "@utils/api";
import { isNetBirdHosted } from "@utils/netbird";
import { useApplicationContext } from "@/contexts/ApplicationProvider";
import { VersionInfo as VersionInfoType } from "@/interfaces/Instance";

function formatVersion(version: string): string {
  if (!version) return "";
  // Add "v" prefix if version starts with a number
  if (/^\d/.test(version)) return `v${version}`;
  return version;
}

/** Extract MAJOR.MINOR.PATCH numeric parts (ignores prerelease like 0.68.1-16-gabc). */
function extractSemverCoreParts(version: string): [number, number, number] | null {
  const normalized = version.replace(/^v/i, "");
  const m = normalized.match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10)];
}

/**
 * Returns true if `latest` is strictly newer than `current` (by semver core only).
 * Git describe builds (e.g. 0.68.1-16-g93eb2ab9) compare as 0.68.1.
 */
function compareSemverCore(current: string, latest: string): boolean {
  if (!current || !latest) return false;
  if (current === "development") return false;

  const c = extractSemverCoreParts(current);
  const l = extractSemverCoreParts(latest);
  if (!c || !l) return false;

  for (let i = 0; i < 3; i++) {
    if (l[i] > c[i]) return true;
    if (l[i] < c[i]) return false;
  }
  return false;
}

/** Docker tag "latest" / "dev" is not a semver — never treat as outdated vs GitHub. */
function isComparableDashboardVersion(version: string): boolean {
  const t = version.trim().toLowerCase();
  if (!t || t === "latest" || t === "dev" || t === "development") return false;
  return extractSemverCoreParts(version) !== null;
}

export const NavigationVersionInfo = () => {
  const { isNavigationCollapsed, mobileNavOpen } = useApplicationContext();

  // Only show for self-hosted, not cloud
  if (isNetBirdHosted()) return null;

  return (
    <div
      className={cn(
        "px-4 py-4 animate-fade-in",
        isNavigationCollapsed &&
          !mobileNavOpen &&
          "hidden md:group-hover/navigation:block",
      )}
    >
      <NavigationVersionInfoContent />
    </div>
  );
};

const NavigationVersionInfoContent = () => {
  const { data: versionInfo, isLoading } = useFetchApi<VersionInfoType>(
    "/instance/version",
    true, // ignore errors
    false, // don't revalidate on focus
  );

  const dashboardVersion =
    process.env.NEXT_PUBLIC_DASHBOARD_VERSION || "development";

  if (isLoading)
    return <Skeleton height={80} className={"rounded-lg opacity-60"} />;

  if (!versionInfo) return null;

  const managementUpdateAvailable =
    typeof versionInfo.management_update_available === "boolean"
      ? versionInfo.management_update_available
      : compareSemverCore(
          versionInfo.management_current_version,
          versionInfo.management_available_version ?? "",
        );

  const dashboardUpdateAvailable =
    isComparableDashboardVersion(dashboardVersion) &&
    !!versionInfo.dashboard_available_version &&
    compareSemverCore(
      dashboardVersion,
      versionInfo.dashboard_available_version,
    );

  const hasUpdate = managementUpdateAvailable || dashboardUpdateAvailable;

  return (
    <div
      className={cn(
        "w-full rounded-md text-xs flex flex-col gap-2 whitespace-normal border text-left",
        "bg-nb-gray-900/20 py-3 px-3 border-nb-gray-800/30",
      )}
    >
      <div className="flex flex-col gap-1 text-nb-gray-400">
        <FullTooltip
          content={
            <span className="text-xs">
              Latest:{" "}
              {formatVersion(versionInfo.management_available_version ?? "")}
            </span>
          }
          side="top"
          className="w-full"
        >
          <div className="flex items-center justify-between w-full cursor-default">
            <span>Management</span>
            <span className="text-nb-gray-300 font-medium">
              {formatVersion(versionInfo.management_current_version)}
            </span>
          </div>
        </FullTooltip>
        <FullTooltip
          content={
            <span className="text-xs">
              Latest:{" "}
              {formatVersion(versionInfo.dashboard_available_version ?? "")}
            </span>
          }
          side="top"
          className="w-full"
        >
          <div className="flex items-center justify-between w-full cursor-default">
            <span>Dashboard</span>
            <span className="text-nb-gray-300 font-medium">
              {formatVersion(dashboardVersion)}
            </span>
          </div>
        </FullTooltip>
      </div>

      {hasUpdate && (
        <a
          href="https://docs.netbird.io/selfhosted/maintenance/upgrade"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center justify-center gap-1.5 text-white font-medium bg-netbird hover:bg-netbird-500 transition-colors rounded-md py-1.5 px-2 mt-1"
        >
          <ArrowUpCircle size={12} />
          <span>Update available</span>
        </a>
      )}
    </div>
  );
};

export default NavigationVersionInfo;