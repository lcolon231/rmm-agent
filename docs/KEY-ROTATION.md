# Command signing-key rotation

NodeLink signs every agent command with an Ed25519 key. Agents trust the
public keys the server hands them (the `active` key plus any `overlap` keys)
and refuse commands signed by an unknown or `retired` key. This runbook covers
rotating that key without a mixed-version fleet ever rejecting a valid command,
and responding to a suspected key compromise.

Private keys live on disk beside the registry, never in the database. The
registry is the JSON file named by `COMMAND_SIGNING_KEYRING_PATH`; the operator
tool is `server/scripts/rotate_command_key.py`. Every mutation is written
atomically and appended to `<registry>.rotation.log` (append-only JSON lines)
so the rotation history is auditable.

## Key states

| State | Signs new commands | In agent trust bundle | Meaning |
|-------|:---:|:---:|---------|
| `active` | yes | yes | exactly one; the current signing key |
| `overlap` | no | yes | trusted but idle — a new key before promotion, or the outgoing key during a rotation |
| `retired` | no | no | no longer trusted |

The tool enforces the invariants keyring loading requires — exactly one active
key, `active_key_id` points at it — and refuses any operation that would break
them, so the registry is never left in a state the server would reject.

## Enabling the registry

A deployment without a registry runs a single key named `default` (from
`COMMAND_SIGNING_KEY_PATH`). To adopt rotation, create a registry seeded with
your current key, then point the server at it:

```bash
cd server
python scripts/rotate_command_key.py --registry /etc/nodelink/keys/registry.json \
    --operator "$USER" \
    init --active-id key-2026-01 \
        --private /etc/nodelink/keys/command_signing_key.pem \
        --public  /etc/nodelink/keys/command_public_key.pem

# then set, and restart the server:
export COMMAND_SIGNING_KEYRING_PATH=/etc/nodelink/keys/registry.json
```

## Planned rotation (staged — no rejected commands)

Rotate on a schedule with the fleet online. Each step is a separate tool
invocation; wait between them.

```bash
R=/etc/nodelink/keys/registry.json
ROT="python scripts/rotate_command_key.py --registry $R --operator $USER"

# 1. Bring up the new key as overlap. Restart the server so it serves the new
#    public key in the heartbeat bundle; agents pick it up on their next beat.
$ROT generate --key-id key-2026-04 --dir /etc/nodelink/keys
#    -> restart server; wait at least one heartbeat interval for the fleet.

# 2. Promote it. The old key steps down to overlap so any command it already
#    signed still verifies. Restart the server to sign with the new key.
$ROT activate --key-id key-2026-04
#    -> restart server; wait until every command signed by the old key has
#       passed its TTL (default 5 min, or your longest configured TTL).

# 3. Retire the old key once nothing it signed is still in flight.
$ROT retire --key-id key-2026-01
#    -> restart server; the old public key leaves the bundle.

$ROT status   # confirm: one active, the old key retired
```

Why the waits matter: promoting before agents know the new public key would
make them reject the first commands signed by it; retiring the old key before
its in-flight commands expire would make agents reject commands that were
legitimately signed. `overlap` is the buffer that removes both races.

## Compromise response (fast path)

If the active private key may be exposed, do not wait — a command signed by the
compromised key must stop being honored, even at the cost of refusing its
in-flight commands (that is the goal):

```bash
$ROT generate --key-id key-incident-0420 --dir /etc/nodelink/keys   # restart server
$ROT activate --key-id key-incident-0420                            # restart server
$ROT retire   --key-id key-2026-04                                  # restart server
```

Then rotate again on the normal schedule once the incident is closed, and
treat the compromised private key file as destroyed (delete it from the host
and any backups per your key-custody policy).

## Rollback

If a freshly activated key turns out to be bad (wrong file, unreadable), and
the previous key is still `overlap` (not yet retired), roll back by
re-activating it:

```bash
$ROT activate --key-id key-2026-01   # restart server; the new key becomes overlap
```

If the previous key was already retired, you cannot roll back to it —
generate and stage a new key instead. Retirement is meant to be final.

## Verifying and auditing

- `python scripts/rotate_command_key.py --registry $R status` prints the
  redacted state (IDs and statuses, never private material).
- `GET /api/v1/signing-keys` (readonly operator) exposes the same state to the
  dashboard/API.
- `<registry>.rotation.log` records each mutation with a UTC timestamp, the
  `--operator` value, and the affected key IDs. Keep it under the same access
  controls and backup as the registry itself.
- Rehearse this runbook against a staging deployment before you need it; the
  full staged rotation and the compromise path are exercised end to end in
  `server/tests/test_key_rotation.py`.
