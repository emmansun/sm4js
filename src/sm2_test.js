const test = require('tape')
const sjcl = require('sjcl-with-all')
require('./sm3').bindSM3(sjcl)
require('./kdf').bindKDF(sjcl)
require('./sm2').bindSM2(sjcl)

test('SM2 public key', function (t) {
  const SM2PublicKey = sjcl.ecc.sm2.publicKey
  const pk = new SM2PublicKey(
    sjcl.codec.hex.toBits(
      '8356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1'
    )
  )
  const serialized = pk.serialize()
  t.equals(serialized.type, 'sm2')
  t.equals(serialized.secretKey, false)
  t.equals(
    serialized.point,
    '8356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1'
  )
  t.equals(serialized.curve, 'sm2p256v1')
  t.end()
})

test('SM2 generatekeys by given sec', function (t) {
  const BigInt = sjcl.bn
  const keys = sjcl.ecc.sm2.generateKeys(
    new BigInt('0x6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85')
  )
  const serializedPrv = keys.sec.serialize()
  t.equals(serializedPrv.curve, 'sm2p256v1')
  t.equals(
    serializedPrv.exponent,
    '6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85'
  )
  t.equals(serializedPrv.secretKey, true)
  const serializedPub = keys.pub.serialize()
  t.equals(serializedPub.secretKey, false)
  t.equals(serializedPub.point, '8356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1')
  t.end()
})

test('SM2 private key', function (t) {
  const SM2PrivateKey = sjcl.ecc.sm2.secretKey
  const prv = new SM2PrivateKey(
    sjcl.codec.hex.toBits(
      '6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85'
    )
  )
  const serializedPrv = prv.serialize()
  t.equals(serializedPrv.curve, 'sm2p256v1')
  t.equals(
    serializedPrv.exponent,
    '6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85'
  )
  t.equals(serializedPrv.secretKey, true)

  t.end()
})

test('SM2 generatekeys by randomly', function (t) {
  const keys = sjcl.ecc.sm2.generateKeys()
  const serializedPrv = keys.sec.serialize()
  const serializedPub = keys.pub.serialize()
  t.equals(serializedPub.curve, 'sm2p256v1')
  t.false(serializedPub.secretKey)
  t.true(serializedPrv.secretKey)
  t.end()
})

test('ZA', function (t) {
  const SM2PublicKey = sjcl.ecc.sm2.publicKey
  const pk = new SM2PublicKey(
    sjcl.codec.hex.toBits(
      '46bb0b1f6e732e6d8b228ead8af64cf5a7cba6b497e9308a02640902b00eed53ad6725b83d0c1f693b14205ec85c4146e2223c6cdb93430332914ccbbb6ca910'
    )
  )
  t.equals(sjcl.codec.hex.fromBits(pk.za()), '17e7fc071f1418200aeead3c5118a2f18381431d92b808a3bd1ba2d8270c2914')
  t.end()
})

test('verify hash', function (t) {
  const SM2PublicKey = sjcl.ecc.sm2.publicKey
  const pk = new SM2PublicKey(
    sjcl.codec.hex.toBits(
      '46bb0b1f6e732e6d8b228ead8af64cf5a7cba6b497e9308a02640902b00eed53ad6725b83d0c1f693b14205ec85c4146e2223c6cdb93430332914ccbbb6ca910'
    )
  )
  t.true(pk.verifyHash(sjcl.codec.hex.toBits('66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'), sjcl.codec.hex.toBits('757984E0A063394EE0792B52172DD4273C05E2A66D734FF804A37B9AC639C098D9739A8D7A37FC88A1B4210998DA489AD5B0DEE1C8CB9097E532318ADED5D204')))
  t.end()
})

test('verify message', function (t) {
  const SM2PublicKey = sjcl.ecc.sm2.publicKey
  const pk = new SM2PublicKey(
    sjcl.codec.hex.toBits(
      '8356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1'
    )
  )
  t.true(pk.verify('ShangMi SM2 Sign Standard', sjcl.codec.hex.toBits('5B3A799BD94C9063120D7286769220AF6B0FA127009AF3E873C0E8742EDC5F89097968A4C8B040FD548D1456B33F470CABD8456BFEA53E8A828F92F6D4BDCD77')))
  t.end()
})

test('sign/verify', function (t) {
  const BigInt = sjcl.bn
  const keys = sjcl.ecc.sm2.generateKeys(
    new BigInt('0x6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85')
  )
  const hashValue = keys.pub.hash('ShangMi SM2 Sign Standar')
  const signature = keys.sec.signHash(hashValue)
  t.true(keys.pub.verifyHash(hashValue, signature))
  t.end()
})

test('decryption', function (t) {
  const BigInt = sjcl.bn
  const keys = sjcl.ecc.sm2.generateKeys(
    new BigInt('0x6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85')
  )
  const plaintext = keys.sec.decrypt(sjcl.codec.hex.toBits('BD31001CE8D39A4A0119FF96D71334CD12D8B75BBC780F5BFC6E1EFAB535E85A1839C075FF8BF761DCBE185C9750816410517001D6A130F6AB97FB23337CCE15EA82BD58D6A5394EB468A769AB48B6A26870CA075377EB06663780C920EA5EE0E22ABCF48E56AE9D29AC770D9DE0D6B7094A874A2F8D26C26E0B1DAAF4FF50A484B88163D04785B04585BB'))
  t.equals(sjcl.codec.utf8String.fromBits(plaintext), 'send reinforcements, we\'re going to advance')
  t.end()
})

test('encryption/decryption', function (t) {
  const BigInt = sjcl.bn
  const keys = sjcl.ecc.sm2.generateKeys(
    new BigInt('0x6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85')
  )
  const ciphertext = keys.pub.encrypt('send reinforcements, we\'re going to advance')
  const plaintext = keys.sec.decrypt(ciphertext)
  t.equals(sjcl.codec.utf8String.fromBits(plaintext), 'send reinforcements, we\'re going to advance')
  t.end()
})
