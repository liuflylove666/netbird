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
import AppStoreButton from "@/assets/app-store-badge.png";
import { OperatingSystem } from "@/interfaces/OperatingSystem";

type Props = {
  pkgsBase: string;
};

/**
 * IPA path under NB_CLIENT_DOWNLOADS_DIR for MDM / in-house distribution.
 * Consumer devices normally use the App Store; Apple does not allow arbitrary
 * sideloading like Android APK without enterprise program or MDM.
 */
const iosIpaPath = "/ios/netbird.ipa";

export default function IOSTab({ pkgsBase }: Readonly<Props>) {
  const selfHosted = isSelfHostedPkgsBase(pkgsBase);
  const ipaUrl = `${pkgsBase}${iosIpaPath}`;

  return (
    <TabsContent value={String(OperatingSystem.IOS)}>
      <TabsContentPadding>
        <p className={"font-medium flex gap-3 items-center text-base"}>
          <ShoppingBagIcon size={16} />
          Install on iOS
        </p>
        <Steps>
          <Steps.Step step={1}>
            {selfHosted ? (
              <>
                <p>
                  For MDM or in-house distribution, host the IPA on your server
                  (e.g. sync to{" "}
                  <span className={"text-nb-gray-200 font-mono text-xs"}>
                    ios/netbird.ipa
                  </span>
                  ) and distribute with your mobile device management tool.
                </p>
                <div className={"flex flex-wrap gap-3 mt-2 items-center"}>
                  <Link href={ipaUrl} passHref>
                    <Button variant={"primary"}>
                      <DownloadIcon size={14} />
                      Download IPA
                    </Button>
                  </Link>
                </div>
                <p className={"text-xs text-nb-gray-400 mt-3 max-w-md"}>
                  For personal devices, Apple&apos;s App Store build is usually
                  the practical option; your server URL is still entered in the
                  app after install.
                </p>
                <div className={"flex gap-4 mt-2"}>
                  <Link
                    href={
                      "https://apps.apple.com/app/netbird-p2p-vpn/id6469329339"
                    }
                    target={"_blank"}
                  >
                    <Image
                      src={AppStoreButton}
                      alt={"Download NetBird on the App Store"}
                      height={50}
                    />
                  </Link>
                </div>
              </>
            ) : (
              <>
                <p>Download and install the application on the App Store:</p>
                <div className={"flex gap-4 mt-1"}>
                  <Link
                    href={
                      "https://apps.apple.com/app/netbird-p2p-vpn/id6469329339"
                    }
                    target={"_blank"}
                  >
                    <Image
                      src={AppStoreButton}
                      alt={"Download NetBird on the App Store"}
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
