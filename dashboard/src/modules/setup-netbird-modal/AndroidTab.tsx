import Button from "@components/Button";
import Code from "@components/Code";
import Steps from "@components/Steps";
import TabsContentPadding, { TabsContent } from "@components/Tabs";
import { GRPC_API_ORIGIN } from "@utils/netbird";
import { isSelfHostedPkgsBase } from "@utils/clientDownloads";
import { DownloadIcon, ShoppingBagIcon } from "lucide-react";
import Image from "next/image";
import Link from "next/link";
import React from "react";
import GooglePlayButton from "@/assets/google-play-badge.png";
import { OperatingSystem } from "@/interfaces/OperatingSystem";

type Props = {
  pkgsBase: string;
};

/** APK path under NB_CLIENT_DOWNLOADS_DIR (mirrored on /downloads/). */
const androidApkPath = "/android/netbird.apk";

export default function AndroidTab({ pkgsBase }: Readonly<Props>) {
  const selfHosted = isSelfHostedPkgsBase(pkgsBase);
  const apkUrl = `${pkgsBase}${androidApkPath}`;

  return (
    <TabsContent value={String(OperatingSystem.ANDROID)}>
      <TabsContentPadding>
        <p className={"font-medium flex gap-3 items-center text-base"}>
          <ShoppingBagIcon size={16} />
          Install on Android
        </p>
        <Steps>
          <Steps.Step step={1}>
            {selfHosted ? (
              <>
                <p>
                  Download the APK from your NetBird server (sync this file into
                  your downloads directory, e.g.{" "}
                  <span className={"text-nb-gray-200 font-mono text-xs"}>
                    android/netbird.apk
                  </span>
                  ):
                </p>
                <div className={"flex flex-wrap gap-3 mt-2 items-center"}>
                  <Link href={apkUrl} passHref>
                    <Button variant={"primary"}>
                      <DownloadIcon size={14} />
                      Download APK
                    </Button>
                  </Link>
                </div>
                <p className={"text-xs text-nb-gray-400 mt-3 max-w-md"}>
                  You can still offer the public Play Store build for users who
                  are allowed to install from Google Play.
                </p>
                <div className={"flex gap-4 mt-2"}>
                  <Link
                    href={
                      "https://play.google.com/store/apps/details?id=io.netbird.client"
                    }
                    target={"_blank"}
                  >
                    <Image
                      src={GooglePlayButton}
                      alt={"Download NetBird from Google Play"}
                      height={50}
                    />
                  </Link>
                </div>
              </>
            ) : (
              <>
                <p>
                  Download and install the application from Google Play Store:
                </p>
                <div className={"flex gap-4 mt-1"}>
                  <Link
                    href={
                      "https://play.google.com/store/apps/details?id=io.netbird.client"
                    }
                    target={"_blank"}
                  >
                    <Image
                      src={GooglePlayButton}
                      alt={"Download NetBird from Google Play"}
                      height={50}
                    />
                  </Link>
                </div>
              </>
            )}
          </Steps.Step>
          {GRPC_API_ORIGIN && (
            <Steps.Step step={2}>
              <p>
                {`Click on "Change Server" and enter the following "Server"`}
              </p>
              <Code>
                <Code.Line>{GRPC_API_ORIGIN}</Code.Line>
              </Code>
            </Steps.Step>
          )}

          <Steps.Step step={GRPC_API_ORIGIN ? 3 : 2}>
            <p>
              {/* eslint-disable-next-line react/no-unescaped-entities */}
              Click on the "Connect" button in the middle of the screen
            </p>
          </Steps.Step>
          <Steps.Step step={GRPC_API_ORIGIN ? 4 : 3} line={false}>
            <p>Sign up using your email address</p>
          </Steps.Step>
        </Steps>
      </TabsContentPadding>
    </TabsContent>
  );
}
