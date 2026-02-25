#!/usr/bin/env node
// Tests for totp.mjs — run with: node test_totp.mjs
// Uses Node.js assert (no external deps)

import { execSync } from 'child_process'
import { readFileSync, writeFileSync, unlinkSync, existsSync, mkdirSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { createHmac } from 'crypto'
import assert from 'assert'
import { homedir } from 'os'

const __dirname = dirname(fileURLToPath(import.meta.url))
const SCRIPT = join(__dirname, 'totp.mjs')
const OPENCLAW_DIR = join(homedir(), '.openclaw')
const SECRET_PATH = join(OPENCLAW_DIR, '.totp-secret')
const OVERRIDE_PATH = join(OPENCLAW_DIR, '.totp-override')
const OVERRIDE_PP_PATH = join(OPENCLAW_DIR, '.totp-override-passphrase')

// Backup existing files
const backups = {}
for (const f of [SECRET_PATH, OVERRIDE_PATH, OVERRIDE_PP_PATH]) {
  if (existsSync(f)) {
    backups[f] = readFileSync(f)
  }
}

function run(args) {
  try {
    const out = execSync(`node ${SCRIPT} ${args}`, { encoding: 'utf-8', timeout: 5000 })
    return { code: 0, output: JSON.parse(out.trim()) }
  } catch (e) {
    try {
      return { code: e.status, output: JSON.parse(e.stdout.trim()) }
    } catch {
      return { code: e.status, output: e.stdout }
    }
  }
}

function cleanup() {
  for (const f of [SECRET_PATH, OVERRIDE_PATH, OVERRIDE_PP_PATH]) {
    try { unlinkSync(f) } catch {}
  }
}

// Base32 decode (minimal, for test code generation)
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
function b32decode(str) {
  let bits = ''
  for (const c of str.toUpperCase().replace(/=+$/, '')) {
    const v = B32.indexOf(c); if (v >= 0) bits += v.toString(2).padStart(5, '0')
  }
  const bytes = []
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2))
  return Buffer.from(bytes)
}

function generateCode(secret, offset = 0) {
  const time = Math.floor(Date.now() / 1000 / 30) + offset
  const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(time))
  const hmac = createHmac('sha1', secret).update(buf).digest()
  const off = hmac[hmac.length - 1] & 0x0f
  const code = (((hmac[off] & 0x7f) << 24) | ((hmac[off + 1] & 0xff) << 16) |
    ((hmac[off + 2] & 0xff) << 8) | (hmac[off + 3] & 0xff)) % 1000000
  return code.toString().padStart(6, '0')
}

let passed = 0
let failed = 0

function test(name, fn) {
  try {
    fn()
    console.log(`  ✅ ${name}`)
    passed++
  } catch (e) {
    console.log(`  ❌ ${name}: ${e.message}`)
    failed++
  }
}

console.log('\nTOTP Gate Tests\n')

// Clean slate
cleanup()

test('status: not configured initially', () => {
  const r = run('status')
  assert.strictEqual(r.output.configured, false)
  assert.strictEqual(r.output.override_active, false)
})

test('verify: fails when not configured', () => {
  const r = run('verify 123456')
  assert.strictEqual(r.code, 1)
  assert.strictEqual(r.output.status, 'error')
})

test('generate: creates secret and override passphrase', () => {
  const r = run('generate')
  assert.strictEqual(r.output.status, 'ok')
  assert.ok(r.output.secret.length > 10)
  assert.ok(r.output.override_passphrase.length > 10)
  assert.strictEqual(r.output.digits, 6)
  assert.strictEqual(r.output.period, 30)
  assert.ok(existsSync(SECRET_PATH))
  assert.ok(existsSync(OVERRIDE_PP_PATH))
})

test('status: configured after generate', () => {
  const r = run('status')
  assert.strictEqual(r.output.configured, true)
  assert.strictEqual(r.output.override_active, false)
})

test('verify: rejects wrong code', () => {
  const r = run('verify 000000')
  assert.strictEqual(r.code, 1)
  assert.strictEqual(r.output.verified, false)
})

test('verify: accepts correct code', () => {
  const secretB32 = readFileSync(SECRET_PATH, 'utf-8').trim()
  const secret = b32decode(secretB32)
  const code = generateCode(secret)
  const r = run(`verify ${code}`)
  assert.strictEqual(r.code, 0)
  assert.strictEqual(r.output.verified, true)
})

test('verify: accepts code from previous window (±1)', () => {
  const secretB32 = readFileSync(SECRET_PATH, 'utf-8').trim()
  const secret = b32decode(secretB32)
  const code = generateCode(secret, -1)
  const r = run(`verify ${code}`)
  assert.strictEqual(r.code, 0)
  assert.strictEqual(r.output.verified, true)
})

test('override: bypass when passphrase matches', () => {
  const pp = readFileSync(OVERRIDE_PP_PATH, 'utf-8').trim()
  writeFileSync(OVERRIDE_PATH, pp)
  const r = run('verify 000000')
  assert.strictEqual(r.code, 0)
  assert.strictEqual(r.output.verified, true)
  assert.strictEqual(r.output.method, 'override')
  unlinkSync(OVERRIDE_PATH)
})

test('override: does not bypass with wrong passphrase', () => {
  writeFileSync(OVERRIDE_PATH, 'wrong-passphrase')
  const r = run('verify 000000')
  assert.strictEqual(r.code, 1)
  assert.strictEqual(r.output.verified, false)
  unlinkSync(OVERRIDE_PATH)
})

test('status: override_active reflects state correctly', () => {
  const pp = readFileSync(OVERRIDE_PP_PATH, 'utf-8').trim()
  writeFileSync(OVERRIDE_PATH, pp)
  let r = run('status')
  assert.strictEqual(r.output.override_active, true)
  unlinkSync(OVERRIDE_PATH)
  r = run('status')
  assert.strictEqual(r.output.override_active, false)
})

// Restore original files
cleanup()
for (const [f, data] of Object.entries(backups)) {
  writeFileSync(f, data, { mode: 0o600 })
}

console.log(`\nResults: ${passed} passed, ${failed} failed\n`)
process.exit(failed > 0 ? 1 : 0)
