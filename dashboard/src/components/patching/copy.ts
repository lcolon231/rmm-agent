// SPDX-License-Identifier: AGPL-3.0-only
//
// Page descriptions shared by the client screens and their server-rendered
// error states. Kept out of the "use client" modules so server components get
// the plain strings rather than client references.

export const PATCH_POLICIES_DESCRIPTION =
  "The rules for which updates are approved, and when they are allowed to install.";

export const MAINTENANCE_WINDOWS_DESCRIPTION =
  "Agreed times when restarts and shutdowns are allowed. While a window is open, alert notifications for the devices it covers are not sent.";
