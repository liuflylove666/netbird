import Button from "@components/Button";
import { Input } from "@components/Input";
import {
  Modal,
  ModalContent,
  ModalFooter,
  ModalTrigger,
} from "@components/modal/Modal";
import { notify } from "@components/Notification";
import Paragraph from "@components/Paragraph";
import { useApiCall } from "@utils/api";
import { ShieldCheck, ShieldOff, KeyRound } from "lucide-react";
import React, { useEffect, useRef, useState } from "react";
import { useSWRConfig } from "swr";
import QRCode from "qrcode";
import { User } from "@/interfaces/User";

type Props = {
  user: User;
  children?: React.ReactNode;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
};

export default function MFASetupModal({ user, children, open: controlledOpen, onOpenChange: controlledOnOpenChange }: Readonly<Props>) {
  const [internalOpen, setInternalOpen] = useState(false);
  const isControlled = controlledOpen !== undefined;
  const open = isControlled ? controlledOpen : internalOpen;
  const setOpen = isControlled ? (controlledOnOpenChange ?? (() => {})) : setInternalOpen;

  return (
    <Modal open={open} onOpenChange={setOpen} key={open ? 1 : 0}>
      {children && <ModalTrigger asChild={true}>{children}</ModalTrigger>}
      {user.mfa_enabled ? (
        <MFADisableForm
          userId={user.id}
          onSuccess={() => setOpen(false)}
        />
      ) : (
        <MFAEnableForm
          userId={user.id}
          email={user.email}
          onSuccess={() => setOpen(false)}
        />
      )}
    </Modal>
  );
}

function MFAEnableForm({
  userId,
  email,
  onSuccess,
}: Readonly<{ userId: string; email?: string; onSuccess: () => void }>) {
  const setupRequest = useApiCall<{ secret: string; otp_url: string }>(
    `/users/${userId}/mfa/setup`,
  );
  const enableRequest = useApiCall<{ mfa_enabled: boolean }>(
    `/users/${userId}/mfa/enable`,
  );
  const { mutate } = useSWRConfig();

  const [step, setStep] = useState<"init" | "verify">("init");
  const [secret, setSecret] = useState("");
  const [otpUrl, setOtpUrl] = useState("");
  const [code, setCode] = useState("");

  const handleSetup = async () => {
    try {
      const result = await setupRequest.post({});
      setSecret(result.secret);
      setOtpUrl(result.otp_url);
      setStep("verify");
    } catch {
      notify({
        title: "MFA Setup",
        description: "Failed to generate MFA secret.",
      });
    }
  };

  const handleEnable = async () => {
    notify({
      title: "Enable MFA",
      description: "Verifying code...",
      promise: enableRequest
        .post({ code })
        .then(() => {
          mutate("user-profile");
          mutate("/users?service_user=false");
          onSuccess();
        }),
      loadingMessage: "Verifying...",
    });
  };

  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (otpUrl && canvasRef.current) {
      QRCode.toCanvas(canvasRef.current, otpUrl, {
        width: 200,
        margin: 2,
        color: { dark: "#000000", light: "#ffffff" },
      });
    }
  }, [otpUrl]);

  if (step === "init") {
    return (
      <ModalContent maxWidthClass={"max-w-md"} showClose={true}>
        <div className={"flex flex-col items-center justify-center px-8 pt-4"}>
          <div className="w-12 h-12 rounded-full bg-nb-gray-900 flex items-center justify-center mb-4">
            <ShieldCheck size={24} className={"text-netbird"} />
          </div>
          <h2 className={"text-lg my-0 text-center"}>
            Enable Two-Factor Authentication
          </h2>
          <Paragraph className={"text-sm text-center max-w-xs"}>
            Add an extra layer of security to your account using a TOTP
            authenticator app.
          </Paragraph>
        </div>
        <ModalFooter className={"items-center"}>
          <Button
            variant={"primary"}
            className={"w-full"}
            onClick={handleSetup}
          >
            <ShieldCheck size={14} />
            Set Up MFA
          </Button>
        </ModalFooter>
      </ModalContent>
    );
  }

  return (
    <ModalContent maxWidthClass={"max-w-md"} showClose={true}>
      <div className={"flex flex-col items-center justify-center px-8 pt-4"}>
        <div className="w-12 h-12 rounded-full bg-nb-gray-900 flex items-center justify-center mb-4">
          <ShieldCheck size={24} className={"text-netbird"} />
        </div>
        <h2 className={"text-lg my-0 text-center"}>Scan QR Code</h2>
        <Paragraph className={"text-sm text-center max-w-xs"}>
          Scan this QR code with your authenticator app (Google Authenticator,
          Authy, etc.)
        </Paragraph>
      </div>

      <div className={"px-8 py-4 flex flex-col items-center gap-4"}>
        {otpUrl && (
          <div className="bg-white p-3 rounded-lg">
            <canvas ref={canvasRef} />
          </div>
        )}
        <div className="w-full">
          <p className="text-xs text-nb-gray-400 mb-1 text-center">
            Or enter this key manually:
          </p>
          <div className="bg-nb-gray-900 rounded-md px-3 py-2 text-center font-mono text-sm text-nb-gray-200 select-all break-all">
            {secret}
          </div>
        </div>
        <Input
          type={"text"}
          customPrefix={<KeyRound size={16} className={"text-nb-gray-300"} />}
          placeholder={"Enter 6-digit code"}
          value={code}
          maxLength={6}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
          onKeyDown={(e) => {
            if (e.key === "Enter" && code.length === 6) handleEnable();
          }}
        />
      </div>

      <ModalFooter className={"items-center"}>
        <Button
          variant={"primary"}
          className={"w-full"}
          disabled={code.length !== 6}
          onClick={handleEnable}
        >
          <ShieldCheck size={14} />
          Verify &amp; Enable MFA
        </Button>
      </ModalFooter>
    </ModalContent>
  );
}

function MFADisableForm({
  userId,
  onSuccess,
}: Readonly<{ userId: string; onSuccess: () => void }>) {
  const disableRequest = useApiCall<{ mfa_enabled: boolean }>(
    `/users/${userId}/mfa/disable`,
  );
  const { mutate } = useSWRConfig();
  const [code, setCode] = useState("");

  const handleDisable = async () => {
    notify({
      title: "Disable MFA",
      description: "Disabling two-factor authentication...",
      promise: disableRequest
        .post({ code })
        .then(() => {
          mutate("user-profile");
          mutate("/users?service_user=false");
          onSuccess();
        }),
      loadingMessage: "Disabling MFA...",
    });
  };

  return (
    <ModalContent maxWidthClass={"max-w-md"} showClose={true}>
      <div className={"flex flex-col items-center justify-center px-8 pt-4"}>
        <div className="w-12 h-12 rounded-full bg-nb-gray-900 flex items-center justify-center mb-4">
          <ShieldOff size={24} className={"text-red-400"} />
        </div>
        <h2 className={"text-lg my-0 text-center"}>
          Disable Two-Factor Authentication
        </h2>
        <Paragraph className={"text-sm text-center max-w-xs"}>
          Enter a code from your authenticator app to confirm disabling MFA.
        </Paragraph>
      </div>

      <div className={"px-8 py-4 flex flex-col gap-4"}>
        <Input
          type={"text"}
          customPrefix={<KeyRound size={16} className={"text-nb-gray-300"} />}
          placeholder={"Enter 6-digit code"}
          value={code}
          maxLength={6}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
          onKeyDown={(e) => {
            if (e.key === "Enter" && code.length === 6) handleDisable();
          }}
        />
      </div>

      <ModalFooter className={"items-center"}>
        <Button
          variant={"danger"}
          className={"w-full"}
          disabled={code.length !== 6}
          onClick={handleDisable}
        >
          <ShieldOff size={14} />
          Disable MFA
        </Button>
      </ModalFooter>
    </ModalContent>
  );
}
