# Tickets are separate from support chat; the tray polls for ticket notifications

Status: accepted

A **Ticket** (see `GLOSSARY.md`) is a new concept, not a mode of support chat. A support chat is a live conversation: the end user stays on it, and it has one open conversation per endpoint, a short-lived chat token, and a browser tab that is only useful while someone is there. A ticket is a record the end user submits and walks away from. It is triaged and resolved later, possibly days later and possibly by someone else, and it outlives any browser session. Tickets get their own tables, routes, bounds, retention and audit actions, and support chat keeps its "not a ticketing system" boundary.

End users find out a ticket changed by **tray-initiated, parameterless polling**. The tray periodically sends the agent service one parameterless "any ticket updates?" message over the local named pipe. The service answers using its own agent credential and the endpoint identity it already holds. The service never pushes to the tray. This keeps the pipe's existing guarantee from support chat (`SUPPORT-CHAT.md`): a local caller can ask, but cannot choose the agent, the ticket, or a URL, and nothing on the pipe carries a credential.

## Considered Options

- **Tickets as a mode of support chat** (a chat that may be left open, or a "leave a message" state). It reuses the chat tables and token, but every chat bound and rule (one open conversation per endpoint, a 15-minute token, a transcript that is pruned after close, no idle auto-close) is tuned for a live conversation and would have to grow a ticket exception. It also blurs what an operator is promising when they answer.
- **Service-to-tray push** (the service connects to a pipe or socket the tray listens on). It is faster to notify, but it means the service has to find and trust a listener in a user session. Any local process that can claim that listener's name could receive or spoof notifications, and the channel would need a protocol carrying ticket ids and content. That reverses the direction of trust the chat pipe was designed around.
- **Parameterized tray polling** (the tray asks about a specific ticket id). It is simpler to render, but it lets a local caller pick what to ask about. That is the property the parameterless pipe exists to deny.

## Consequences

- Notification latency is bounded by the tray's poll interval, not by when the operator acts. The interval is a bound the support-tickets doc must set ([`../SUPPORT-TICKETS.md`](../SUPPORT-TICKETS.md)).
- The poll response can only describe the calling endpoint's own tickets, and only to the extent the tray needs to show a notification. Ticket content is read through an authenticated end-user page, as chat is, not over the pipe.
- Ticket bodies, retention, and audit actions are designed separately from support chat's and are not inherited from it.
- Code and docs say "ticket", never "issue", "case", or "incident", for this concept.
