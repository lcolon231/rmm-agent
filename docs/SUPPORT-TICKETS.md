# Endpoint support tickets

> **Status: in progress.** Nothing here has shipped. Each section is filled in
> as the support-tickets work lands. Until a section is filled in, it states
> what that section will cover. It does not describe behavior.

A **ticket** (see [`../GLOSSARY.md`](../GLOSSARY.md)) is a request an end user
submits from an endpoint for an operator to triage and resolve. Unlike
[support chat](SUPPORT-CHAT.md), it is asynchronous: the end user submits it and
walks away, and an operator picks it up later.
[ADR-0002](adr/0002-tickets-are-separate-from-support-chat-and-the-tray-polls.md)
records why tickets are separate from chat and why end users are notified by
tray polling.

## Flow

_To be written: how an end user submits a ticket, and how an operator triages
and resolves it._

## Threat model and authorization

_To be written: each surface, what authorizes it, and the claim it enforces.
The local pipe stays parameterless (ADR-0002)._

## Bounds

_To be written: the limits the server enforces, with their settings and
defaults._

## Notifications

_To be written: the tray's parameterless poll and what the end user sees. There
is no service-to-tray push (ADR-0002)._

## Retention

_To be written: how long ticket data is kept, and how that differs from
lifecycle audit events, which are never pruned
([`RETENTION.md`](RETENTION.md))._
