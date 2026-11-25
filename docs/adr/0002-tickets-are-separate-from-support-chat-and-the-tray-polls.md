# Tickets are separate from support chat; the tray polls for ticket notifications

Status: accepted (not implemented yet; see [`../SUPPORT-TICKETS.md`](../SUPPORT-TICKETS.md))

A **Ticket** (see `GLOSSARY.md`) is a separate concept, not a mode of support chat. A support chat is a live conversation. It is reached through a browser tab opened with a short-lived chat token, and nothing tells the end user when an operator replies, so a reply is seen only if someone looks. A ticket is a record the end user submits and walks away from. An operator triages and resolves it later, and the end user is told when it changes. Tickets are designed as their own concept, and support chat keeps its "not a ticketing system" boundary.

End users will learn that a ticket changed through **tray-initiated, parameterless polling**. The tray will periodically send the agent service one parameterless message over the local named pipe. The service will answer using its own agent credential and the endpoint identity it already holds. The service will never push to the tray. This keeps the guarantee the support chat pipe already provides (`SUPPORT-CHAT.md`): a local caller can ask, but cannot choose the agent, the ticket, or a URL, and nothing on the pipe carries a credential.

## Considered Options

- **Tickets as a mode of support chat** (a chat that may be left open, or a "leave a message" state). This would reuse the chat tables and token, but chat's rules are tuned for a live conversation: one open conversation per endpoint, a 15-minute token, and a transcript pruned after close. Each rule would need a ticket exception. It would also blur what an operator promises when they answer.
- **Service-to-tray push** (the service connects to a pipe or socket the tray listens on). This would notify faster, but the service would have to find and trust a listener in a user session. Any local process that claimed that listener's name could receive or spoof notifications, and the channel would need a protocol that carries ticket data. That reverses the direction of trust the chat pipe was designed around.
- **Parameterized tray polling** (the tray asks about a specific ticket id). This would be simpler to render, but it lets a local caller choose what to ask about, which is exactly what the parameterless pipe exists to prevent.

## Consequences

- Notification latency is bounded by the tray's poll interval, not by when the operator acts.
- A poll can only ever concern the calling endpoint, because the pipe carries nothing that could name another endpoint.
- Ticket bounds, retention, and audit actions are decided for tickets themselves. They are not inherited from support chat.
- Code and docs say "ticket" for this concept, never "issue", "case", "incident", or "helpdesk request".
