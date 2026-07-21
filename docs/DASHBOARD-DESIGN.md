# NodeLink dashboard design

## Purpose

NodeLink's dashboard is a risk-first operations cockpit for technicians who
manage Windows endpoints for regulated small businesses. Its primary job is to
show what needs attention, explain why, and make the response safe and
auditable.

The interface should not imply regulatory certification. It exposes the
controls and evidence NodeLink can actually produce.

## Current implementation

Desktop overview:

![NodeLink desktop operations overview](images/nodelink-dashboard-overview.png)

Mobile overview:

![NodeLink mobile operations overview](images/nodelink-dashboard-mobile.png)

## Product principles

1. **Action before analytics.** Ranked issues and concrete next steps appear
   before aggregate charts or fleet totals.
2. **Scope is always visible.** Client and site context persists across every
   route and action.
3. **Trust is part of the workflow.** Signing, policy checks, command expiry,
   endpoint acceptance, and audit recording are visible during normal work.
4. **Dense, not crowded.** The desktop interface favors compact tables,
   deliberate hierarchy, and quiet healthy states.
5. **Color is semantic.** Teal means verified, amber means operator attention,
   and red means failed or critical. Status never depends on color alone.
6. **Current capability is honest.** Screens appear when their backend
   workflows are operational, not as non-functional roadmap placeholders.

## Information architecture

The persistent navigation model is:

- Overview
- Endpoints
- Alerts
- Automation
- Audit
- Administration

Client and site selection is separate from route navigation. Changing scope
filters the current route without making the technician rebuild their context.

The first implementation delivers the Overview route. Endpoint detail, command
review, audit, enrollment, and operator administration follow the same shell.

## Overview layout

```text
+----------------+-------------------------------------+----------------+
| Client tree    | Operations overview                 | Trust status   |
|                |                                     |                |
| Acme Health    | Endpoints needing attention         | Audit chain    |
|  - HQ          |                                     | Last anchor    |
|  - West Clinic | Fleet status and endpoint table     | Signing key    |
| Northstar      |                                     |                |
|                |                                     | Signed actions |
+----------------+-------------------------------------+----------------+
```

### Primary regions

- **Top bar:** global client scope, endpoint search, audit state,
  notifications, and operator identity.
- **Client tree:** persistent client and site context plus route navigation.
- **Attention queue:** ranked operational risks with example endpoint, first
  observation, and a specific action.
- **Fleet table:** endpoint identity, location, state, freshness, user,
  telemetry, and queued work.
- **Trust rail:** audit verification, anchor freshness, signing-key state, and
  a connected chain-of-custody timeline.

## Signature interaction

The chain-of-custody rail is NodeLink's signature element. Every sensitive
action should eventually expose these checkpoints:

1. Requested by an identified operator or automation policy.
2. Checked against the applicable policy.
3. Signed with a named active key.
4. Accepted or rejected by the target endpoint.
5. Completed with timestamps and result metadata.
6. Recorded in the append-only audit chain.

The chain is operational evidence, not decoration. Each checkpoint must map to
real backend state before it is presented as complete.

## Visual system

### Color tokens

| Token | Value | Use |
| --- | --- | --- |
| Ink | `#12202B` | Primary text and controls |
| Ink deep | `#081B2A` | Navigation and application chrome |
| Slate | `#344653` | Secondary text and icons |
| Fog | `#F2F5F6` | Application background |
| Paper | `#FFFFFF` | Working surfaces |
| Verification teal | `#16867A` | Verified and healthy trust states |
| Warning amber | `#C77A13` | Attention and review states |
| Critical red | `#B83A3A` | Failed and critical states |
| Action blue | `#1768C4` | Navigation and non-destructive actions |

### Typography

- Interface text uses a compact humanist sans-serif stack beginning with
  Segoe UI Variable.
- Hostnames, hashes, signatures, percentages, timestamps, and command output
  use a monospaced stack beginning with Cascadia Mono.
- Headings use tight tracking and restrained weight. Large marketing-style
  display type is not used in the application shell.

### Shape and elevation

- Working panels use a 7px radius.
- Controls use a 4px to 5px radius.
- Dividers communicate structure more often than shadows.
- Shadows are reserved for temporary layers such as endpoint drawers.
- Gradients, glass effects, and decorative floating cards are excluded.

## Component behavior

### Attention queue

- Selecting an issue filters the fleet table to affected endpoints.
- A selected issue receives a left-edge marker and can be cleared from the
  panel header.
- Severity is expressed through icon, label, and color.

### Fleet table

- Global search matches endpoint name, client, site, user, and operating
  system.
- Client scope and issue filters compose with search.
- Selecting a row opens a quick endpoint preview.
- Export creates a CSV from the currently visible endpoint set.
- Telemetry bars reserve red for values at or above 90 percent and amber for
  values at or above 68 percent.

### Endpoint preview

- The quick preview preserves the overview context.
- It includes identity, status, last-seen time, user, endpoint group, trust,
  and telemetry.
- Sensitive actions begin with review rather than immediate execution.

## Responsive behavior

- Above 1220px, the client tree, operations surface, and trust rail are all
  visible.
- Between 880px and 1220px, the trust rail is removed from the persistent
  layout and should later be available through a trust drawer.
- Below 880px, the client tree becomes an off-canvas navigation drawer.
- Below 660px, secondary top-bar controls collapse and the endpoint table
  remains horizontally scrollable rather than discarding operational fields.

## Accessibility requirements

- Every interactive element has a visible keyboard focus state.
- Icon-only controls have accessible labels.
- Status never relies on color alone.
- Text and controls target WCAG AA contrast.
- Drawer scrims close the active layer and keyboard escape handling should be
  added with the production dialog primitive.
- Motion is disabled when the user requests reduced motion.

## Backend mapping

The initial dashboard can map to the existing management API as follows:

| Interface area | API |
| --- | --- |
| Client scope | `GET /api/v1/clients` |
| Endpoint table | `GET /api/v1/agents` |
| Endpoint preview | `GET /api/v1/agents/{agent_id}` |
| Command history | `GET /api/v1/agents/{agent_id}/commands` |
| Command review and dispatch | `POST /api/v1/agents/{agent_id}/commands` |
| Signing-key status | `GET /api/v1/signing-keys` |
| Audit verification | `GET /api/v1/audit/verify` |
| Anchor history | `GET /api/v1/audit/anchors` |

The overview currently uses typed local fixtures so the interaction and visual
system can be reviewed independently. The dashboard foundation includes a
server-only API client and validates its non-public API URL at runtime.
Dashboard sign-in is a same-origin backend-for-frontend flow: the browser
receives an HTTP-only, same-site cookie while server code verifies the current
operator and forwards the bearer token to the API. Fixture data must remain
visibly non-production until live API integration is complete.

This foundation performs no dashboard mutation, so there is no
dashboard-specific audit event, persisted dashboard state, schema migration,
retry policy, or idempotency behavior to claim yet. Later workflows must define
and test those properties before becoming available to technicians.

## Delivery sequence

1. Operations overview and responsive application shell.
2. Endpoint table backed by live agents and telemetry.
4. Endpoint detail with command history.
5. Signed command review and dispatch.
6. Audit verification and anchor management.
7. Enrollment-token and operator administration.
8. Inventory, monitoring, notifications, and automation as their backend
   models become operational.
