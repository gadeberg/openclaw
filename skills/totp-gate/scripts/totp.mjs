#!/usr/bin/env node
// TOTP verification for OpenClaw agent actions (RFC 6238)
// Zero external dependencies — uses Node.js crypto only.
//
// Commands:
//   generate  — Create new TOTP secret + kill switch passphrase
//   verify    — Verify a 6-digit code (exit 0 = valid, exit 1 = invalid)
//   status    — Check if TOTP is configured and override state
//
// Files:
//   ~/.openclaw/.totp-secret              — Base32-encoded shared secret (mode 600)
//   ~/.openclaw/.totp-override            — Kill switch (must contain correct passphrase)
//   ~/.openclaw/.totp-override-passphrase — Expected passphrase for kill switch (mode 600)

import { createHmac, randomBytes } from 'crypto'
import { readFileSync, writeFileSync, existsSync, chmodSync, mkdirSync } from 'fs'
import { join } from 'path'
import { homedir } from 'os'

const OPENCLAW_DIR = join(homedir(), '.openclaw')
const SECRET_PATH = join(OPENCLAW_DIR, '.totp-secret')
const OVERRIDE_PATH = join(OPENCLAW_DIR, '.totp-override')
const OVERRIDE_PASSPHRASE_PATH = join(OPENCLAW_DIR, '.totp-override-passphrase')

// --- Base32 (RFC 4648) ---

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function base32Encode(buf) {
  let bits = ''
  for (const b of buf) bits += b.toString(2).padStart(8, '0')
  let out = ''
  for (let i = 0; i < bits.length; i += 5)
    out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]
  return out
}

function base32Decode(str) {
  let bits = ''
  for (const c of str.toUpperCase().replace(/=+$/, '')) {
    const v = B32.indexOf(c)
    if (v >= 0) bits += v.toString(2).padStart(5, '0')
  }
  const bytes = []
  for (let i = 0; i + 8 <= bits.length; i += 8)
    bytes.push(parseInt(bits.slice(i, i + 8), 2))
  return Buffer.from(bytes)
}

// --- TOTP (RFC 6238) ---

function totp(secret, offset = 0, digits = 6, step = 30) {
  const time = Math.floor(Date.now() / 1000 / step) + offset
  const buf = Buffer.alloc(8)
  buf.writeBigUInt64BE(BigInt(time))
  const hmac = createHmac('sha1', secret).update(buf).digest()
  const off = hmac[hmac.length - 1] & 0x0f
  const code = (
    ((hmac[off] & 0x7f) << 24) |
    ((hmac[off + 1] & 0xff) << 16) |
    ((hmac[off + 2] & 0xff) << 8) |
    (hmac[off + 3] & 0xff)
  ) % 10 ** digits
  return code.toString().padStart(digits, '0')
}

function verify(secret, code, window = 1) {
  for (let i = -window; i <= window; i++)
    if (totp(secret, i) === code) return true
  return false
}

// --- Kill switch ---

function isOverrideActive() {
  if (!existsSync(OVERRIDE_PATH) || !existsSync(OVERRIDE_PASSPHRASE_PATH)) return false
  try {
    const a = readFileSync(OVERRIDE_PATH, 'utf-8').trim()
    const b = readFileSync(OVERRIDE_PASSPHRASE_PATH, 'utf-8').trim()
    return a === b && b.length > 0
  } catch { return false }
}

// --- Helpers ---

function out(obj) { console.log(JSON.stringify(obj, null, 2)) }
function die(msg) { out({ status: 'error', error: msg }); process.exit(1) }

function ensureDir() {
  if (!existsSync(OPENCLAW_DIR)) mkdirSync(OPENCLAW_DIR, { recursive: true })
}

function readSecret() {
  if (!existsSync(SECRET_PATH)) die('TOTP not configured. Run: node totp.mjs generate')
  return base32Decode(readFileSync(SECRET_PATH, 'utf-8').trim())
}

// --- Commands ---

const cmd = process.argv[2]

if (cmd === 'generate') {
  ensureDir()
  const secret = base32Encode(randomBytes(20))
  const passphrase = randomBytes(16).toString('hex')
  writeFileSync(SECRET_PATH, secret, { mode: 0o600 })
  chmodSync(SECRET_PATH, 0o600)
  writeFileSync(OVERRIDE_PASSPHRASE_PATH, passphrase, { mode: 0o600 })
  chmodSync(OVERRIDE_PASSPHRASE_PATH, 0o600)
  out({
    status: 'ok',
    secret,
    account: 'OpenClaw Agent',
    issuer: 'OpenClaw',
    digits: 6,
    period: 30,
    algorithm: 'SHA1',
    override_passphrase: passphrase,
    manual_entry: `Account: OpenClaw Agent | Key: ${secret} | Time-based | 6 digits`,
    note: 'Base32 uses A-Z and 2-7 only. Letter O is not zero.',
  })
} else if (cmd === 'verify') {
  const code = process.argv[3]
  if (!code) die('Usage: node totp.mjs verify <6-digit-code>')
  if (isOverrideActive()) {
    out({ status: 'ok', verified: true, method: 'override' })
    process.exit(0)
  }
  const ok = verify(readSecret(), code)
  out({ status: 'ok', verified: ok })
  process.exit(ok ? 0 : 1)
} else if (cmd === 'status') {
  out({
    status: 'ok',
    configured: existsSync(SECRET_PATH),
    override_active: isOverrideActive(),
  })
} else {
  console.log('TOTP Gate — identity verification for OpenClaw agents')
  console.log('')
  console.log('Usage: node totp.mjs <command>')
  console.log('')
  console.log('Commands:')
  console.log('  generate       Create new TOTP secret')
  console.log('  verify <code>  Verify a 6-digit code')
  console.log('  status         Check configuration state')
  process.exit(1)
}
