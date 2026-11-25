# Endpoint support tickets

> **Status: design in progress.** Nothing here has shipped. This skeleton is
> filled in by the support-tickets issues as each piece lands. Until a section
> says otherwise, it describes intent, not behavior.

A **ticket** (see [`../GLOSSARY.md`](../GLOSSARY.md)) is a request the person at
a managed endpoint submits for a technician to triage and resolve. Unlike
[support chat](SUPPORT-CHAT.md), it is asynchronous: the end user submits it and
walks away, and a technician picks it up later. The decision to keep tickets
separate from chat, and to notify end users by tray polling, is recorded in
[ADR-0002](adr/0002-tickets-are-separate-from-support-chat-and-the-tray-polls.md).

## Flow

_To be written: how an end user submits a ticket from the endpoint, how a
technician triages, answers, and resolves it on the dashboard, and how the end
user reads the reply._

## Threat model and authorization

_To be written: one row per surface (local pipe, agent router, end-user page,
operator router), what authorizes it, and the claim it enforces. Same shape as
support chat's table. The pipe stays parameterless (ADR-0002)._

## Bounds

_To be written: server-enforced limits with their settings and defaults (body
size, open tickets per endpoint, submission rate, tray poll interval)._

## Notifications

_To be written: the tray's parameterless poll, what the service returns, the
poll interval, and what the end user sees. There is no service-to-tray push
(ADR-0002)._

## Retention

_To be written: how long ticket bodies are kept after a ticket is resolved, and
how that differs from the lifecycle audit events, which are never pruned
([`RETENTION.md`](RETENTION.md))._
