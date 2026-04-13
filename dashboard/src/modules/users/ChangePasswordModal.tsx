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
import { KeyRound, Lock, ShieldCheck } from "lucide-react";
import React, { useMemo, useState } from "react";
import { User } from "@/interfaces/User";

type Props = {
  user: User;
  children: React.ReactNode;
};

export default function ChangePasswordModal({
  user,
  children,
  isAdminReset = false,
}: Readonly<Props & { isAdminReset?: boolean }>) {
  const [open, setOpen] = useState(false);

  return (
    <Modal open={open} onOpenChange={setOpen} key={open ? 1 : 0}>
      <ModalTrigger asChild={true}>{children}</ModalTrigger>
      <ChangePasswordForm userId={user.id} email={user.email} onSuccess={() => setOpen(false)} isAdminReset={isAdminReset} />
    </Modal>
  );
}

type ModalContentProps = {
  userId?: string;
  email?: string;
  onSuccess: () => void;
};

export function ChangePasswordModalContent({
  userId,
  email,
  onSuccess,
}: Readonly<ModalContentProps>) {
  return <ChangePasswordForm userId={userId} email={email} onSuccess={onSuccess} />;
}

export function ChangePasswordForm({
  userId,
  email,
  onSuccess,
  title,
  description,
  showClose = true,
  preventDismiss = false,
  isAdminReset = false,
}: Readonly<{
  userId?: string;
  email?: string;
  onSuccess: () => void;
  title?: string;
  description?: string;
  showClose?: boolean;
  preventDismiss?: boolean;
  isAdminReset?: boolean;
}>) {
  const passwordRequest = useApiCall<Record<string, never>>(
    `/users/${userId}/password`,
  );
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const passwordsMatch = newPassword === confirmPassword;
  const isStrongPassword = useMemo(() => {
    if (newPassword.length < 8) return false;
    if (!/[A-Z]/.test(newPassword)) return false;
    if (!/[0-9]/.test(newPassword)) return false;
    if (!/[^A-Za-z0-9]/.test(newPassword)) return false;
    return true;
  }, [newPassword]);

  const isDisabled = useMemo(() => {
    if (!isAdminReset && oldPassword.length === 0) return true;
    if (newPassword.length === 0) return true;
    if (!passwordsMatch) return true;
    if (!isStrongPassword) return true;
    if (!isAdminReset && oldPassword === newPassword) return true;
    return false;
  }, [oldPassword, newPassword, passwordsMatch, isStrongPassword, isAdminReset]);

  const handleSubmit = async () => {
    const actionTitle = isAdminReset ? "Reset Password" : "Change Password";
    const actionMsg = isAdminReset ? "Resetting password..." : "Updating your password...";
    notify({
      title: actionTitle,
      description: actionMsg,
      promise: passwordRequest
        .put({
          old_password: isAdminReset ? "" : oldPassword,
          new_password: newPassword,
        })
        .then(() => {
          onSuccess();
        }),
      loadingMessage: isAdminReset ? "Resetting password..." : "Changing password...",
    });
  };

  const defaultTitle = isAdminReset ? "Reset Password" : "Change Password";
  const defaultDescription = isAdminReset ? (
    <>
      Set a new password for{" "}
      <span className="font-medium text-white">{email || "this user"}</span>
    </>
  ) : (
    <>
      Update the password for{" "}
      <span className="font-medium text-white">{email || "your account"}</span>
    </>
  );

  return (
    <ModalContent
      maxWidthClass={"max-w-md"}
      showClose={showClose}
      {...(preventDismiss ? {
        onEscapeKeyDown: (e: Event) => e.preventDefault(),
        onInteractOutside: (e: Event) => e.preventDefault(),
        onPointerDownOutside: (e: Event) => e.preventDefault(),
      } : {})}
    >
      <div className={"flex flex-col items-center justify-center px-8 pt-4"}>
        <div
          className={
            "w-12 h-12 rounded-full bg-nb-gray-900 flex items-center justify-center mb-4"
          }
        >
          <ShieldCheck size={24} className={"text-netbird"} />
        </div>
        <h2 className={"text-lg my-0 text-center"}>{title || defaultTitle}</h2>
        <Paragraph className={"text-sm text-center max-w-xs"}>
          {description || defaultDescription}
        </Paragraph>
      </div>

      <div className={"px-8 py-4 flex flex-col gap-4"}>
        {!isAdminReset && (
          <Input
            type={"password"}
            customPrefix={
              <Lock size={16} className={"text-nb-gray-300"} />
            }
            placeholder={"Current password"}
            value={oldPassword}
            onChange={(e) => setOldPassword(e.target.value)}
          />
        )}
        <Input
          type={"password"}
          customPrefix={
            <KeyRound size={16} className={"text-nb-gray-300"} />
          }
          placeholder={"New password"}
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          error={
            newPassword.length > 0 && !isStrongPassword
              ? "Min 8 chars, 1 uppercase, 1 digit, 1 special char"
              : undefined
          }
        />
        <Input
          type={"password"}
          customPrefix={
            <KeyRound size={16} className={"text-nb-gray-300"} />
          }
          placeholder={"Confirm new password"}
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          error={
            confirmPassword.length > 0 && !passwordsMatch
              ? "Passwords do not match"
              : undefined
          }
        />
        {!isAdminReset && oldPassword.length > 0 &&
          newPassword.length > 0 &&
          oldPassword === newPassword && (
            <Paragraph className="text-xs text-red-400 mt-0 text-center">
              New password must be different from current password
            </Paragraph>
          )}
      </div>

      <ModalFooter className={"items-center"}>
        <Button
          variant={"primary"}
          className={"w-full"}
          disabled={isDisabled}
          onClick={handleSubmit}
        >
          <KeyRound size={14} />
          {isAdminReset ? "Reset Password" : "Update Password"}
        </Button>
      </ModalFooter>
    </ModalContent>
  );
}
