import test from 'tape'
import sjcl from 'sjcl-with-all'
import bindPKIX from '../src/pkix.js'
bindPKIX(sjcl)

const BigInt = sjcl.bn

const sm2PKIXPublicKeyHex =
  '3059301306072a8648ce3d020106082a811ccf5501822d03420004ef7db908af06082ef4a30e0ec28623371c106a53296a7b0e1a9b5717bd9cb81beb20d094aba685fd0f6a7ecc007ccf797ba634476326723b303d9dec873f440b'

test('pkix: parse SM2 public key', function (t) {
  const pk = sjcl.pkix.parsePKIXPublicKey(
    sjcl.bytescodec.hex.toBytes(sm2PKIXPublicKeyHex)
  )
  const serialized = pk.serialize()
  t.equals(serialized.type, 'sm2')
  t.equals(serialized.secretKey, false)
  t.equals(
    serialized.point,
    'ef7db908af06082ef4a30e0ec28623371c106a53296a7b0e1a9b5717bd9cb81beb20d094aba685fd0f6a7ecc007ccf797ba634476326723b303d9dec873f440b'
  )
  t.equals(serialized.curve, 'sm2p256v1')

  t.end()
})

test('pkix: marshal SM2 public key', function (t) {
  const keys = sjcl.ecc.sm2.generateKeys()
  const pk = sjcl.pkix.parsePKIXPublicKey(
    sjcl.pkix.marshalPKIXPublicKey(keys.pub)
  )
  const serialized = pk.serialize()
  t.equals(serialized.type, 'sm2')
  t.equals(serialized.secretKey, false)
  t.equals(serialized.curve, 'sm2p256v1')
  t.deepEqual(pk._point, keys.pub._point)
  t.end()
})

test('pkix: marshal K256 public key', function (t) {
  const keys = sjcl.ecc.ecdsa.generateKeys(sjcl.ecc.curves.k256, 0)
  const pk = sjcl.pkix.parsePKIXPublicKey(
    sjcl.pkix.marshalPKIXPublicKey(keys.pub)
  )
  const serialized = pk.serialize()
  t.equals(serialized.type, 'ecdsa')
  t.equals(serialized.secretKey, false)
  t.equals(serialized.curve, 'k256')
  t.deepEqual(pk._point, keys.pub._point)
  t.end()
})

test('pkix: marshal C224/C256/C384/C521 public key', function (t) {
  const curves = [224, 256, 384, 521]
  for (let i = 0; i < curves.length; i++) {
    const keys = sjcl.ecc.ecdsa.generateKeys(curves[i], 0)
    const pk = sjcl.pkix.parsePKIXPublicKey(
      sjcl.pkix.marshalPKIXPublicKey(keys.pub)
    )
    const serialized = pk.serialize()
    t.equals(serialized.type, 'ecdsa')
    t.equals(serialized.secretKey, false)
    t.equals(serialized.curve, `c${curves[i]}`)
    t.deepEqual(pk._point, keys.pub._point)
  }
  t.end()
})

test('pkix: marshal SM2 SEC1 private key', function (t) {
  const keys = sjcl.ecc.sm2.generateKeys(
    new BigInt(
      '0x8604263B78B289BDD6B927D543B36088479688E7171099AD36328829C3CDE2A5'
    )
  )
  let bytes = sjcl.pkix.marshalECPrivateKey(keys.sec)
  t.equal(
    sjcl.bytescodec.hex.fromBytes(bytes),
    '307702010104208604263b78b289bdd6b927d543b36088479688e7171099ad36328829c3cde2a5a00a06082a811ccf5501822da1440342000427b8a4ded46ab34c1bff39077ee08404c39a34dcace2d7da09c3867571a87b601a05f6d0b023c0c39fd1f730c806ab17afb5bc92300f37765cbc24b15a22171d'
  )

  // exlude public key
  bytes = sjcl.pkix.marshalECPrivateKey(keys.sec, false)
  t.equal(
    sjcl.bytescodec.hex.fromBytes(bytes),
    '303102010104208604263b78b289bdd6b927d543b36088479688e7171099ad36328829c3cde2a5a00a06082a811ccf5501822d'
  )

  t.end()
})

test('pkix: parse SM2 SEC1 private key', function (t) {
  let prv = sjcl.pkix.parseECPrivateKey(
    sjcl.bytescodec.hex.toBytes(
      '307702010104208604263b78b289bdd6b927d543b36088479688e7171099ad36328829c3cde2a5a00a06082a811ccf5501822da1440342000427b8a4ded46ab34c1bff39077ee08404c39a34dcace2d7da09c3867571a87b601a05f6d0b023c0c39fd1f730c806ab17afb5bc92300f37765cbc24b15a22171d'
    )
  )
  let serializedPrv = prv.serialize()
  t.equals(serializedPrv.curve, 'sm2p256v1')
  t.equals(
    serializedPrv.exponent,
    '8604263b78b289bdd6b927d543b36088479688e7171099ad36328829c3cde2a5'
  )
  t.equals(serializedPrv.secretKey, true)

  // without public key
  prv = sjcl.pkix.parseECPrivateKey(
    sjcl.bytescodec.hex.toBytes(
      '303102010104208604263b78b289bdd6b927d543b36088479688e7171099ad36328829c3cde2a5a00a06082a811ccf5501822d'
    )
  )
  serializedPrv = prv.serialize()
  t.equals(serializedPrv.curve, 'sm2p256v1')
  t.equals(
    serializedPrv.exponent,
    '8604263b78b289bdd6b927d543b36088479688e7171099ad36328829c3cde2a5'
  )
  t.equals(serializedPrv.secretKey, true)
  t.end()
})
