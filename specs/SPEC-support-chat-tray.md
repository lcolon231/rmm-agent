# Spec: support-chat-tray

Module id: `support-chat-tray` — a system-tray launcher for the support chat
shipped in v0.1.9 (`specs/SPEC-support-chat.md`).

## Objective

Give the person at a managed Windows endpoint a persistent, always-visible way
to start a support conversation: a NodeLink logo in the system tray that opens
the chat on click, instead of typing `rmm-agent chat`.

## Why this revisits a rejected decision

`specs/SPEC-support-chat.md` ("Why the browser, and not a tray app") rejected a
tray app for two recorded reasons. This spec revisits it because one no longer
applies and the other is unchanged and accepted:

1. **Dependency footprint — resolved.** The rejection assumed "a Go GUI toolkit
   is a large transitive dependency tree." This module uses **no GUI toolkit**:
   the tray icon is drawn with `Shell_NotifyIcon` and a hidden message window
   called directly through `golang.org/x/sys/windows`, the agent's sole existing
   dependency. `agent/go.mod` stays byte-identical, exactly as the chat feature
   required.
2. **Authenticode signing — unchanged, accepted.** A tray app is a persistent
   user-session process and draws more SmartScreen/AV attention than a transient
   CLI. This does not introduce a new risk *class*: `#24` (unsigned Windows
   artifacts) is already an open pilot limitation. The tray makes that existing,
   documented limitation more visible; it is accepted for pilot and revisited
   when signing lands.

Everything else in `SPEC-support-chat.md` still holds. The tray is only a new
*launcher* for the exact same flow — it changes nothing about the pipe, the
token, redaction, or the server.

## Design

- **New Windows-only package `agent/internal/chattray`**, built like
  `internal/chatpipe` and `internal/chatlaunch`: a portable file with the API
  and `ErrUnsupported`, a `_windows.go` with the syscalls, and an `_other.go`
  returning `ErrUnsupported` so `go build ./...` stays green on Linux/macOS.
- **New subcommand `rmm-agent tray`.** It runs the message loop and blocks until
  the user exits or the session ends. It runs in the *interactive user's*
  session, so it is a normal (non-elevated) process — the same identity the
  pipe's `INTERACTIVE`-only ACL already admits.
- **Activation reuses the shipped path.** On left-click or double-click, the
  tray calls `chatpipe.Request` — the identical one-parameterless-message pipe
  call that `rmm-agent chat` makes today. The service opens the conversation and
  launches the browser; the URL/token still never crosses the pipe or a log.
- **Right-click menu:** "Open support chat" and "Exit". Failures (service not
  running, `support_chat_base_url` unset) surface as a tray balloon tip carrying
  the existing friendly `chatpipe` error text, never a crash and never a secret.
- **Single instance per session** via a named mutex; the icon re-adds itself on
  `TaskbarCreated` (Explorer restart).
- **Autostart:** the installer drops an all-users Startup shortcut
  "NodeLink Support" → `rmm-agent.exe tray`, created on install and removed on
  uninstall, launching for every user at logon as a non-elevated process.
- **Icon:** a multi-resolution `.ico` embedded with `//go:embed`; loaded with
  `CreateIconFromResourceEx` (no temp file). Swapping the `.ico` file needs no
  code change.

## Boundaries

- **Always:** keep `agent/go.mod` byte-identical; keep the tray a pure launcher
  over the existing `chatpipe.Request`; keep `_other.go` returning
  `ErrUnsupported`.
- **Never:** log or display the chat URL/token; add a GUI dependency; reach the
  server directly from the tray (it goes through the service pipe like the CLI).

## Testing

- Pure helpers unit-tested: `.ico` entry selection over the embedded asset, and
  the tray-message → action mapping.
- `_other.go` returns `ErrUnsupported`; `go build ./...` green on both targets.
- The message loop and visible icon require **manual verification on a logged-in
  Windows desktop** (like the session-0 browser launch in `#233`): confirm the
  icon appears, click opens the chat, the menu works, and a stopped service
  shows the balloon.
