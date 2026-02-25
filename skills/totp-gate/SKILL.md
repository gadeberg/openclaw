---
name: totp-gate
description: >
  TOTP-based identity verification for sensitive agent actions.
  Use when the user wants to set up TOTP/2FA verification before the agent performs
  destructive, external, or privileged operations (SSH, deploy, sending messages, deleting data).
  Provides setup (secret generation, authenticator enrollment), verification (6-digit code check),
  and a kill switch for emergency bypass.
  NOT for user-facing web app 2FA, OAuth flows, or password management.
---

# TOTP Gate

Verify the human's identity via TOTP (RFC 6238) before executing sensitive actions. This adds a defense-in-depth layer against prompt injection and session hijacking — even if an attacker controls the agent session, they can't produce a valid 6-digit code.

## How It Works

1. **Setup**: Generate a shared secret, human adds it to their authenticator app
2. **Gate**: Before sensitive actions, ask the human for a 6-digit code
3. **Verify**: Run the verification script, proceed only if valid
4. **Kill switch**: Human can SSH in and create an override file to bypass TOTP

## Setup

Run the setup script to generate a new TOTP secret:

```bash
node scripts/totp.mjs generate
```

Output includes:
- `secret`: Base32-encoded key for the authenticator app
- `override_passphrase`: Emergency bypass passphrase (human stores offline)
- `manual_entry`: Ready-to-paste summary for authenticator apps

Tell the human to add the secret to their authenticator app (Google Authenticator, Authy, 1Password, etc.) with manual entry: Account name, Key (base32), Time-based, 6 digits.

**Important**: Base32 uses A-Z and 2-7 only. The letter O is common and easily confused with zero — warn the human.

## Verification

Before any sensitive action, ask: "Code? 🔐"

Then verify:

```bash
node scripts/totp.mjs verify <6-digit-code>
```

- Exit code 0 + `verified: true` → proceed
- Exit code 1 + `verified: false` → deny the action, ask to retry
- Accepts codes within a ±1 time-step window (±30s) to handle clock drift

## When to Gate

Gate these actions (ask for code before executing):

- **SSH to servers** or any remote command execution
- **Deploying** code or content to production/staging
- **Sending external messages** (email, social media, public posts)
- **Destructive commands** (rm, drop, delete, format)
- **Modifying security settings** (firewall, SSH keys, credentials)
- **Accessing secrets** or credentials stores

Do NOT gate:
- Reading local files, searching, browsing
- Writing code or content within the workspace
- Internal tool use (memory, web search)
- Responding to the human in the current session

## Kill Switch

If the human loses access to their authenticator or TOTP breaks:

1. Human SSHes into the machine directly
2. Creates the override file with the correct passphrase:
   ```bash
   echo "<passphrase>" > ~/.openclaw/.totp-override
   ```
3. TOTP verification is bypassed until the file is removed
4. To re-enable: `rm ~/.openclaw/.totp-override`

The override passphrase is generated during setup and must be stored offline by the human.

## Status Check

```bash
node scripts/totp.mjs status
```

Returns whether TOTP is configured and whether the override is active.

## File Locations

| File | Purpose |
|---|---|
| `~/.openclaw/.totp-secret` | TOTP shared secret (mode 600) |
| `~/.openclaw/.totp-override` | Kill switch file (must contain passphrase) |
| `~/.openclaw/.totp-override-passphrase` | Expected passphrase for kill switch (mode 600) |

## Security Notes

- The shared secret is stored on disk — if the machine is fully compromised, the attacker could extract it. TOTP primarily protects against prompt injection and session hijacking, not full machine compromise.
- The kill switch file is itself an attack surface. Requiring a passphrase (not just file existence) adds friction.
- This is defense-in-depth, not a silver bullet. Combine with restricted SSH keys, least-privilege access, and good operational hygiene.
