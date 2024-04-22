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

test('SM2 Key Exchange test', function (t) {
  const initiator = 'Alice'
  const responder = 'Bob'
  const keyLen = 8 * 48

  const aliceKeys = sjcl.ecc.sm2.generateKeys(
    sjcl.codec.hex.toBits('e04c3fd77408b56a648ad439f673511a2ae248def3bab26bdfc9cdbd0ae9607e')
  ) // share aliceKeys.pub to Bob in advance
  const aliceEphemeralKeys = sjcl.ecc.sm2.generateKeys(undefined, 6, false) // share aliceEphemeralKeys.pub to Bob per key exchange

  const bobKeys = sjcl.ecc.sm2.generateKeys(
    sjcl.codec.hex.toBits('7a1136f60d2c5531447e5a3093078c2a505abf74f33aefed927ac0a5b27e7dd7')
  ) // share bobKeys.pub to Alice in advance
  const bobEphemeralKeys = sjcl.ecc.sm2.generateKeys(undefined, 6, false) // share bobEphemeralKeys.pub to Alice per key exchange

  const aliceKeyMaterial = bobKeys.pub.sharedSecretKey(
    bobEphemeralKeys.pub,
    aliceKeys.sec.implicitSig(
      aliceEphemeralKeys.sec,
      aliceEphemeralKeys.pub
    )
  ).agreedKey(
    keyLen,
    aliceKeys.pub.za(initiator),
    bobKeys.pub.za(responder)
  )

  const bobKeyMaterial = aliceKeys.pub.sharedSecretKey(
    aliceEphemeralKeys.pub,
    bobKeys.sec.implicitSig(
      bobEphemeralKeys.sec,
      bobEphemeralKeys.pub
    )
  ).agreedKey(
    keyLen,
    aliceKeys.pub.za(initiator),
    bobKeys.pub.za(responder)
  )
  t.equals(sjcl.codec.hex.fromBits(aliceKeyMaterial), sjcl.codec.hex.fromBits(bobKeyMaterial))
  t.end()
})

test('SM2 Key Exchange test vector', function (t) {
  const initiator = 'Alice'
  const responder = 'Bob'
  const keyLen = 8 * 48

  const testVector = [
    {
      alicePriv:
        'e04c3fd77408b56a648ad439f673511a2ae248def3bab26bdfc9cdbd0ae9607e',
      aliceEphemeralPriv:
        '6fe0bac5b09d3ab10f724638811c34464790520e4604e71e6cb0e5310623b5b1',
      bobPriv:
        '7a1136f60d2c5531447e5a3093078c2a505abf74f33aefed927ac0a5b27e7dd7',
      bobEphemeralPriv:
        'd0233bdbb0b8a7bfe1aab66132ef06fc4efaedd5d5000692bc21185242a31f6f',
      sharedSecretKey:
        '6ab5c9709277837cedc515730d04751ef81c71e81e0e52357a98cf41796ab560508da6e858b40c6264f17943037434174284a847f32c4f54104a98af5148d89f',
      key: '1ad809ebc56ddda532020c352e1e60b121ebeb7b4e632db4dd90a362cf844f8bba85140e30984ddb581199bf5a9dda22'
    },
    {
      alicePriv:
        'cb5ac204b38d0e5c9fc38a467075986754018f7dbb7cbbc5b4c78d56a88a8ad8',
      aliceEphemeralPriv:
        '1681a66c02b67fdadfc53cba9b417b9499d0159435c86bb8760c3a03ae157539',
      bobPriv:
        '4f54b10e0d8e9e2fe5cc79893e37fd0fd990762d1372197ed92dde464b2773ef',
      bobEphemeralPriv:
        'a2fe43dea141e9acc88226eaba8908ad17e81376c92102cb8186e8fef61a8700',
      sharedSecretKey:
        '677d055355a1dcc9de4df00d3a80b6daa76bdf54ff7e0a3a6359fcd0c6f1e4b4697fffc41bbbcc3a28ea3aa1c6c380d1e92f142233afa4b430d02ab4cebc43b2',
      key: '7a103ae61a30ed9df573a5febb35a9609cbed5681bcb98a8545351bf7d6824cc4635df5203712ea506e2e3c4ec9b12e7'
    },
    {
      alicePriv:
        'ee690a34a779ab48227a2f68b062a80f92e26d82835608dd01b7452f1e4fb296',
      aliceEphemeralPriv:
        '2046c6cee085665e9f3abeba41fd38e17a26c08f2f5e8f0e1007afc0bf6a2a5d',
      bobPriv:
        '8ef49ea427b13cc31151e1c96ae8a48cb7919063f2d342560fb7eaaffb93d8fe',
      bobEphemeralPriv:
        '9baf8d602e43fbae83fedb7368f98c969d378b8a647318f8cafb265296ae37de',
      sharedSecretKey:
        'f7e9f1447968b284ff43548fcec3752063ea386b48bfabb9baf2f9c1caa05c2fb12c2cca37326ce27e68f8cc6414c2554895519c28da1ca21e61890d0bc525c4',
      key: 'b18e78e5072f301399dc1f4baf2956c0ed2d5f52f19abb1705131b0865b079031259ee6c629b4faed528bcfa1c5d2cbc'
    }
  ]

  for (let i = 0; i < testVector.length; i++) {
    const aliceKeys = sjcl.ecc.sm2.generateKeys(
      sjcl.codec.hex.toBits(testVector[i].alicePriv)
    )
    const aliceEphemeralKeys = sjcl.ecc.sm2.generateKeys(
      sjcl.codec.hex.toBits(testVector[i].aliceEphemeralPriv)
    )
    const bobKeys = sjcl.ecc.sm2.generateKeys(
      sjcl.codec.hex.toBits(testVector[i].bobPriv)
    )
    const bobEphemeralKeys = sjcl.ecc.sm2.generateKeys(
      sjcl.codec.hex.toBits(testVector[i].bobEphemeralPriv)
    )

    const tA = aliceKeys.sec.implicitSig(
      aliceEphemeralKeys.sec,
      aliceEphemeralKeys.pub
    )
    const aliceSecretKey = bobKeys.pub.sharedSecretKey(
      bobEphemeralKeys.pub,
      tA
    )
    t.equals(aliceSecretKey.serialize().point, testVector[i].sharedSecretKey)
    const aliceSharedKey = aliceSecretKey.agreedKey(
      keyLen,
      aliceKeys.pub.za(initiator),
      bobKeys.pub.za(responder)
    )
    t.equals(sjcl.codec.hex.fromBits(aliceSharedKey), testVector[i].key)

    const tB = bobKeys.sec.implicitSig(
      bobEphemeralKeys.sec,
      bobEphemeralKeys.pub
    )
    const bobSecretKey = aliceKeys.pub.sharedSecretKey(
      aliceEphemeralKeys.pub,
      tB
    )
    t.equals(bobSecretKey.serialize().point, testVector[i].sharedSecretKey)
    const bobSharedKey = bobSecretKey.agreedKey(
      keyLen,
      aliceKeys.pub.za(initiator),
      bobKeys.pub.za(responder)
    )
    t.equals(sjcl.codec.hex.fromBits(bobSharedKey), testVector[i].key)
  }

  t.end()
})
