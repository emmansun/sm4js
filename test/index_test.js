import test from 'tape'
import { spawnSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

test('initialize installs all binders and is idempotent', function (t) {
  const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
  const script = `
    import sjcl from 'sjcl-with-all'
    import { initialize } from './src/index.js'

    const initialized = initialize(sjcl)
    if (initialized !== sjcl) throw new Error('initialize must return SJCL')
    if (typeof sjcl.misc.kdf !== 'function') throw new Error('KDF not bound')
    if (typeof sjcl.hash.sm3 !== 'function') throw new Error('SM3 not bound')
    if (typeof sjcl.cipher.sm4 !== 'function') throw new Error('SM4 not bound')
    if (typeof sjcl.ecc.sm2.generateKeys !== 'function') throw new Error('SM2 not bound')
    if (typeof sjcl.pkix.marshalPKIXPublicKey !== 'function') throw new Error('PKIX not bound')
    if (typeof sjcl.pkcs8.marshalPKCS8ECPrivateKey !== 'function') throw new Error('PKCS#8 not bound')
    if (initialize(sjcl) !== sjcl) throw new Error('initialize must be idempotent')
  `
  const result = spawnSync(
    process.execPath,
    ['--input-type=module', '-e', script],
    { cwd: projectRoot, encoding: 'utf8' }
  )

  t.equal(result.status, 0, result.stderr || result.error?.message)
  t.end()
})
