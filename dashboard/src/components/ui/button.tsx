// SPDX-License-Identifier: AGPL-3.0-only

import type { LucideIcon } from "lucide-react";
import Link from "next/link";
import type { ButtonHTMLAttributes, ReactNode } from "react";

import { cx, focusRing } from "./cx";

export type ButtonVariant = "primary" | "secondary" | "quiet" | "danger";
export type ButtonSize = "default" | "compact";

const base =
  "inline-flex items-center justify-center gap-2 rounded-lg px-4 font-semibold whitespace-nowrap no-underline " +
  "disabled:cursor-not-allowed disabled:border disabled:border-(--line) disabled:bg-(--fog) disabled:text-(--muted) " +
  focusRing;

const variants: Record<ButtonVariant, string> = {
  primary: "border border-transparent bg-(--primary-strong) text-white hover:bg-(--primary-press)",
  secondary: "border border-(--line-strong) bg-(--paper) text-(--slate) hover:bg-(--primary-tint)",
  quiet: "border border-transparent bg-transparent text-(--primary-strong) hover:bg-(--primary-tint)",
  danger: "border border-(--red) bg-(--paper) text-(--red) hover:bg-(--red-soft)",
};

const sizes: Record<ButtonSize, string> = {
  default: "h-10",
  compact: "h-9",
};

export function buttonClass(variant: ButtonVariant = "secondary", size: ButtonSize = "default", extra?: string) {
  return cx(base, variants[variant], sizes[size], extra);
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: LucideIcon;
};

/**
 * One primary per screen. `danger` is the high-risk style and must open a
 * ConfirmDialog rather than act directly.
 */
export function Button({ variant = "secondary", size = "default", icon: Icon, className, children, type = "button", ...rest }: ButtonProps) {
  return (
    <button type={type} className={buttonClass(variant, size, className)} {...rest}>
      {Icon ? <Icon size={16} aria-hidden="true" /> : null}
      {children}
    </button>
  );
}

type ButtonLinkProps = {
  href: string;
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: LucideIcon;
  className?: string;
  children: ReactNode;
};

/** Navigation styled as a button; navigation is never high-risk. */
export function ButtonLink({ href, variant = "secondary", size = "default", icon: Icon, className, children }: ButtonLinkProps) {
  return (
    <Link href={href} className={buttonClass(variant === "danger" ? "secondary" : variant, size, className)}>
      {Icon ? <Icon size={16} aria-hidden="true" /> : null}
      {children}
    </Link>
  );
}
