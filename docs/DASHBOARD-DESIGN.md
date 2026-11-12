# NodeLink dashboard design

The dashboard presents device operations, review queues and audit evidence using live data. The design reference is `design_handoff_nodelink_dashboard_redesign/README.md`; its sample records and proposed controls are not product capabilities. Screens must never imply certification, successful delivery, consent or verification without supporting data.

## Navigation and scope

The shared shell has seven groups:

| Group | Destinations |
| --- | --- |
| Overview | Operations overview |
| Devices | Endpoints, Alerts, Monitoring, webhook destinations |
| Patching | Patch compliance, Patch policies, Maintenance windows |
| Automation | Script library, Community scripts, Tasks, Schedules |
| Support | Support chat, AI assistant |
| Compliance | Approvals, Audit events and integrity anchors, Emergency overrides |
| Administration | Enrollment, Operators, Security keys and MFA, Break-glass |

Operators and Break-glass navigation remain administrator-only. Server authorization remains authoritative. Enrollment now uses DashboardSectionShell. Client/site scope and existing URL filters remain addressable; a view must label page-local counts and sorting instead of implying fleet-wide results. Community scripts remain discoverable although absent from the prototype navigation table.

The sidebar is full width at 1100px and above, a rail between 720px and 1099px, and hidden below 720px. The toggle opens the appropriate rail or overlay. Tables scroll inside their cards. Content is capped at 1360px. No dark theme is implemented.

## Tokens and components

Violet is the action and navigation color: `--primary-strong` #6C2CE9, pressed #5416CF, with #F6F2FE and #ECE3FD washes. Dark chrome uses #17132A and #221D3A. Page and card surfaces use #F5F3FA and white. Borders use #E3DFEC and #CEC8DD. Green means healthy/completed/active; amber means attention; red means failure; gray means offline/disabled/unknown; violet status means waiting or in progress, never health.

Use the interface font for prose and the data font for hostnames, IDs, hashes and code. Titles are 24px, section headings 16px, body 14px and secondary text at least 12px. Labels are sentence case without tracking. Cards have 10px corners, controls 8px, and focus uses a 2px violet outline. Section gaps are 24px.

The page pattern is PageHeader with breadcrumb, one primary action, real StatTiles where meaningful, optional route tabs, and a filtered DataTable or cards. Detail pages use definition lists, code blocks and recorded activity; unsupported tabs are omitted. Forms retain existing field validation and request bodies. Complex administration and community forms keep their established structure with the shared typography and controls.

Drawers and ConfirmDialog trap focus, close on Escape, and restore focus. High-risk confirmations require a reason. The label is **Reason (required)**: some existing APIs do not accept a reason, so the shared primitive must not promise that it is stored. Where accepted, the reason is forwarded unchanged after existing validation. Network uncertainty must not be presented as proof that a mutation failed.

The shell owns the record footer. Audit integrity comes from actual verification responses; unavailable data stays unknown. Opening a normal screen must not invent an audit receipt or imply that every displayed event is signed.

## Implemented views

Overview emphasizes devices needing attention, alerts, patch compliance, approvals and recent activity. Endpoint lists use page-local risk ordering and preview drawers. Device detail keeps real readings and exact values, inventory, commands and existing remote-access controls. Missing telemetry stays missing.

All six continuation groups were reviewed and merged separately, with typechecking and tests after each merge. The Support group and foundation were already merged before this continuation. Existing server loaders, API routes, role gates and mutation payloads remain the basis of every screen.

Sign-in, MFA and emergency sign-in share a scrollable 420px card on the fog background. Login links to emergency access. MFA still supports mandatory enrollment, security keys, email codes and recovery codes according to the existing method hints and server rules. Email acknowledgement is described as a request, not proof of delivery.

## Deliberate differences from the prototype

| Area | Difference and reason |
| --- | --- |
| Patching | Counts and risk sorting describe loaded data. Missing update names remain in inventory; no fabricated policy targets or failure totals. A future maintenance window is described by its actual state. Delete reasons cannot be persisted by APIs that accept no reason. |
| Automation | No unsupported Runs tab or Run again control. Task metrics and sorting are page-local; dispatch is not completion. Community retains hierarchical package cards. Schedule deletion keeps its existing bodyless API. |
| Device subpages | Command custody shows only recorded timestamps/states, without invented policy, approval or device-verification milestones. Inventory-section headers use the endpoint ID rather than adding a new fetch. Power operations retain hostname confirmation and payload rules, with a final required-reason dialog. |
| Devices | No invented bulk acknowledgement, policy creation or policy editing controls. Alert timelines describe loaded events and delivery attempts. Webhook rotation/removal retain version checks; those APIs do not accept the confirmation reason. |
| Administration | Operator creation remains the existing account workflow, not a fictional invitation flow. Security and emergency-access forms retain one-time secrets and recovery flows. Enrollment adds the navigation read required by the shared shell. Existing complex forms remain forms rather than artificial preview records. |
| Compliance | Approval detail shows command identity, field names and fingerprint; values are not returned by that API. No unsupported per-entry verification, related-entry tab or new evidence-export endpoint. Audit ordering remains sequence-based, with the existing 25-anchor verification limit. Override notifications describe attempts/provider acceptance. Override run uses the activation justification because its API takes no additional reason. |
| Sign-in | Emergency access takes the existing sealed credential and reason, not invented account/passphrase fields. No blanket promise that every failed attempt is recorded or every administrator is notified. The MFA page does not invent an email address it has not loaded. |

## Verification and maintenance

From `dashboard/`: `npx tsc --noEmit`, `npx eslint src test`, `npm test`, `npm run test:coverage`, and `npx next build`. Keep coverage floors intact and raise them when justified. UI tests exercise role gates, reason requirements, exact request bodies, refused changes, masked credentials, URL pagination and unknown states. Browser checks were not run during this work, as required by the continuation brief.

`scripts/prune-unused-css.mjs` parses globals.css with PostCSS, checks TypeScript string/template references, removes dead selectors individually, and drops empty at-rules. It preserves dynamic class prefixes and conservatively keeps complex selectors. Run without `--write` to inspect, with `--write` to apply. Retained legacy remote-session and unavailable-state styles must continue to work; typography remains at least 12px.

This redesign requires no database migration or agent protocol change. Local commits and merges do not publish a release; pushing or opening a PR requires user authorization.
