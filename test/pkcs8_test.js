const test = require('tape')
const sjcl = require('sjcl-with-all')
require('../src/pkcs8').bindPKCS8(sjcl)

const BigInt = sjcl.bn

test('pkcs8: parse private key', function (t) {
  let prv = sjcl.pkcs8.parsePKCS8ECPrivateKey(sjcl.bytescodec.hex.toBytes('308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420dad6b2f49ca774c36d8ae9517e935226f667c929498f0343d2424d0b9b591b43a14403420004b9c9b90095476afe7b860d8bd43568cab7bcb2eed7b8bf2fa0ce1762dd20b04193f859d2d782b1e4cbfd48492f1f533113a6804903f292258513837f07fda735'))
  let serializedPrv = prv.serialize()
  t.equals(serializedPrv.curve, 'c256')
  t.equals(
    serializedPrv.exponent,
    'dad6b2f49ca774c36d8ae9517e935226f667c929498f0343d2424d0b9b591b43'
  )
  t.equals(serializedPrv.secretKey, true)

  // normal SM2 key
  prv = sjcl.pkcs8.parsePKCS8ECPrivateKey(sjcl.bytescodec.hex.toBytes('308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b26da57ba53004ddcd387ad46a361b51b308481f2327d47fb10c5fb3a8c86b92a144034200040d5365bfdbdc564c5b0eda0a85ddbd753821a709de90efe0666ba2544766acf1100ac0484d166842011da5cd6139e53dedb99ce37cea9edf4941628066e861bf'))
  serializedPrv = prv.serialize()
  t.equals(serializedPrv.curve, 'sm2p256v1')
  t.equals(
    serializedPrv.exponent,
    'b26da57ba53004ddcd387ad46a361b51b308481f2327d47fb10c5fb3a8c86b92'
  )
  t.equals(serializedPrv.secretKey, true)

  // RSA key
  t.throws(() => {
    sjcl.pkcs8.parsePKCS8ECPrivateKey(sjcl.bytescodec.hex.toBytes('30820278020100300d06092a864886f70d0101010500048202623082025e02010002818100cfb1b5bf9685ffa97b4f99df4ff122b70e59ac9b992f3bc2b3dde17d53c1a34928719b02e8fd17839499bfbd515bd6ef99c7a1c47a239718fe36bfd824c0d96060084b5f67f0273443007a24dfaf5634f7772c9346e10eb294c2306671a5a5e719ae24b4de467291bc571014b0e02dec04534d66a9bb171d644b66b091780e8d020301000102818100b595778383c4afdbab95d2bfed12b3f93bb0a73a7ad952f44d7185fd9ec6c34de8f03a48770f2009c8580bcd275e9632714e9a5e3f32f29dc55474b2329ff0ebc08b3ffcb35bc96e6516b483df80a4a59cceb71918cbabf91564e64a39d7e35dce21cb3031824fdbc845dba6458852ec16af5dddf51a8397a8797ae0337b1439024100ea0eb1b914158c70db39031dd8904d6f18f408c85fbbc592d7d20dee7986969efbda081fdf8bc40e1b1336d6b638110c836bfdc3f314560d2e49cd4fbde1e20b024100e32a4e793b574c9c4a94c8803db5152141e72d03de64e54ef2c8ed104988ca780cd11397bc359630d01b97ebd87067c5451ba777cf045ca23f5912f1031308c702406dfcdbbd5a57c9f85abc4edf9e9e29153507b07ce0a7ef6f52e60dcfebe1b8341babd8b789a837485da6c8d55b29bbb142ace3c24a1f5b54b454d01b51e2ad03024100bd6a2b60dee01e1b3bfcef6a2f09ed027c273cdbbaf6ba55a80f6dcc64e4509ee560f84b4f3e076bd03b11e42fe71a3fdd2dffe7e0902c8584f8cad877cdc945024100aa512fa4ada69881f1d8bb8ad6614f192b83200aef5edf4811313d5ef30a86cbd0a90f7b025c71ea06ec6b34db6306c86b1040670fd8654ad7291d066d06d031'))
  }, /pkcs8: invalid pkcs8 EC private key asn1/, 'pkcs8: invalid pkcs8 EC private key asn1')

  // SM2 key which was generated with OpenSSL v3.1.3
  t.throws(() => {
    sjcl.pkcs8.parsePKCS8ECPrivateKey(sjcl.bytescodec.hex.toBytes('308188020100301406082a811ccf5501822d06082a811ccf5501822d046d306b020101042087d86c005f449379641916b5e5f1cd5d21ccdad60613741669f470946acb9d17a144034200046f233f11f15549701dc5e677a2f5d202d1b7183d6f6affb16a76558afab3cca537e482c56d779ff589311d03a94114627c88fdf67252ed21fe7051f94b48ca2f'))
  }, /pkcs8: unsupported alg <1.2.156.10197.1.301>/, 'pkcs8: unsupported alg <1.2.156.10197.1.301>')

  t.end()
})

test('pkcs8: marshal SM2 private key', function (t) {
  const keys = sjcl.ecc.sm2.generateKeys(
    new BigInt('0x8604263B78B289BDD6B927D543B36088479688E7171099AD36328829C3CDE2A5')
  )
  let bytes = sjcl.pkcs8.marshalPKCS8ECPrivateKey(keys.sec)
  t.equal(
    sjcl.bytescodec.hex.fromBytes(bytes),
    '308193020100301306072a8648ce3d020106082a811ccf5501822d0479307702010104208604263b78b289bdd6b927d543b36088479688e7171099ad36328829c3cde2a5a00a06082a811ccf5501822da1440342000427b8a4ded46ab34c1bff39077ee08404c39a34dcace2d7da09c3867571a87b601a05f6d0b023c0c39fd1f730c806ab17afb5bc92300f37765cbc24b15a22171d'
  )

  let prv = sjcl.pkcs8.parsePKCS8ECPrivateKey(bytes)
  let serializedPrv = prv.serialize()
  t.equals(
    serializedPrv.exponent,
    '8604263b78b289bdd6b927d543b36088479688e7171099ad36328829c3cde2a5'
  )

  // exlude public key
  bytes = sjcl.pkcs8.marshalPKCS8ECPrivateKey(keys.sec, false)
  t.equal(
    sjcl.bytescodec.hex.fromBytes(bytes),
    '304d020100301306072a8648ce3d020106082a811ccf5501822d0433303102010104208604263b78b289bdd6b927d543b36088479688e7171099ad36328829c3cde2a5a00a06082a811ccf5501822d'
  )
  prv = sjcl.pkcs8.parsePKCS8ECPrivateKey(bytes)
  serializedPrv = prv.serialize()
  t.equals(
    serializedPrv.exponent,
    '8604263b78b289bdd6b927d543b36088479688e7171099ad36328829c3cde2a5'
  )

  t.end()
})

const encryptedEC256aes128sha1 = '3081de304906092a864886f70d01050d303c301b06092a864886f70d01050c300e040804a051b7c74ec36d02020800301d060960864801650304010204109137d3cd5fdac1a9785a1cb50eb2fed804819015f5c03cf57e08e5800497526aba207941c535a43e47ac79e53cff9aab8d23088eacff4336811dd4f1ad29a1da3be00248443031fac67a1f01b8d57af44c0f6e1b286ff31979ec516eb2ded9837b63bfd8d30a6e8da94696588cbecdf97f57e9abff517d553ea91a45103da54f8766cceba1302f4ea37a0c6256c45c04fd9aadf732418a314b61d9e93f6d022f9c21c6'
const encryptedEC256aes = '3081ec305706092a864886f70d01050d304a302906092a864886f70d01050c301c0408d5bca66d1e59886c02020800300c06082a864886f70d02090500301d060960864801650304012a0410bde376406f39b9fe4042e0295136727304819025c20a37023b577af25a1a07a9e46b16da4af0f52edd0bbc46f5d477dd9fdaf670673b5aca9bb1ed7f4fbdf3ac3fd6f9a3e24dccd90888fd563eb670c513ee3a0cb2ca62d246453d5aa001fe9b08736901b0cc99ca85b780db7684d1feca58200af9ff7df7e49e1d6ae8ec58916631c461554b190aff23b2b95b2876e188cdda7478094e17f86414db9332fe98124688'
const pkcs8SM2P256PrivateKeyHex = '3081f6306106092a864886f70d01050d3054303406092a864886f70d01050c30270410dae9c91624d3f74010fb30817ce2756a020110020110300d06092a811ccf55018311020500301c06082a811ccf550168020410cc520afee58fd737683d98f1a2212cc6048190cadc0af7cfc44f85ab4b41fb02c52b8ba153ab3b6bcc0be0cc5977facf40b1a62d525cc4dc4cc4c7a456c68f24a4a3b6ca3d1afc987d599083e1701ca19f5a328a625a539da5726bfe2425306762ac2608a05dfb94731c8d91cd7df9a4e228bb37109f8ebce9885ab872562c34c5de4849ead6db8e12eaf89187231d848815cf5b3c6eb9e9aeb4f92209b09b8f162d1f'

test('pkcs8: parse encrypted key material', function (t) {
  // sha1 + aes128-CBC
  let prv = sjcl.pkcs8.parsePKCS8ECPrivateKey(sjcl.bytescodec.hex.toBytes(encryptedEC256aes128sha1), 'password')
  let serializedPrv = prv.serialize()
  t.equals(
    serializedPrv.exponent,
    '8cb17329bffc86c75298f7edb3df1167b016cd09cb0ec321cbabfeff7059959e'
  )
  t.equals(serializedPrv.curve, 'c256')

  // wrong password
  t.throws(() => {
    sjcl.pkcs8.parsePKCS8ECPrivateKey(sjcl.bytescodec.hex.toBytes(encryptedEC256aes128sha1), 'wrongpwd')
  }, /pkcs#5 padding corrupt/)

  // sha256 + aes256-CBC
  prv = sjcl.pkcs8.parsePKCS8ECPrivateKey(sjcl.bytescodec.hex.toBytes(encryptedEC256aes), 'password')
  serializedPrv = prv.serialize()
  t.equals(
    serializedPrv.exponent,
    '8cb17329bffc86c75298f7edb3df1167b016cd09cb0ec321cbabfeff7059959e'
  )
  t.equals(serializedPrv.curve, 'c256')

  // sm3 + sm4-CBC
  prv = sjcl.pkcs8.parsePKCS8ECPrivateKey(sjcl.bytescodec.hex.toBytes(pkcs8SM2P256PrivateKeyHex), 'Password1')
  serializedPrv = prv.serialize()
  t.equals(
    serializedPrv.exponent,
    '6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85'
  )
  t.equals(serializedPrv.curve, 'sm2p256v1')
  t.end()
})

test('pkcs8: marshal encrypted key material', function (t) {
  const keys = sjcl.ecc.sm2.generateKeys(
    new BigInt('0x8604263B78B289BDD6B927D543B36088479688E7171099AD36328829C3CDE2A5')
  )

  // sm3+sm4-CBC
  let bytes = sjcl.pkcs8.marshalPKCS8ECPrivateKey(keys.sec, true, 'Password1', { kdfOpts: { hash: 'sm3' }, cipherOpts: { cipher: 'sm4' } })
  let prv = sjcl.pkcs8.parsePKCS8ECPrivateKey(bytes, 'Password1')
  let serializedPrv = prv.serialize()
  t.equals(serializedPrv.exponent, '8604263b78b289bdd6b927d543b36088479688e7171099ad36328829c3cde2a5')

  // all default: aes-128-cbc, sha1
  bytes = sjcl.pkcs8.marshalPKCS8ECPrivateKey(keys.sec, true, 'Password1')
  prv = sjcl.pkcs8.parsePKCS8ECPrivateKey(bytes, 'Password1')
  serializedPrv = prv.serialize()
  t.equals(serializedPrv.exponent, '8604263b78b289bdd6b927d543b36088479688e7171099ad36328829c3cde2a5')

  // sha256+aes256-CBC
  bytes = sjcl.pkcs8.marshalPKCS8ECPrivateKey(keys.sec, true, 'Password1', { kdfOpts: { hash: 'sha256', iter: 2048, saltLen: 128 }, cipherOpts: { cipher: 'aes', keyLen: 32 } })
  prv = sjcl.pkcs8.parsePKCS8ECPrivateKey(bytes, 'Password1')
  serializedPrv = prv.serialize()
  t.equals(serializedPrv.exponent, '8604263b78b289bdd6b927d543b36088479688e7171099ad36328829c3cde2a5')

  // sha256+aes256-GCM
  bytes = sjcl.pkcs8.marshalPKCS8ECPrivateKey(keys.sec, true, 'Password1', { kdfOpts: { hash: 'sha256', iter: 2048, saltLen: 128 }, cipherOpts: { cipher: 'aes', mode: 'gcm', keyLen: 32 } })
  prv = sjcl.pkcs8.parsePKCS8ECPrivateKey(bytes, 'Password1')
  serializedPrv = prv.serialize()
  t.equals(serializedPrv.exponent, '8604263b78b289bdd6b927d543b36088479688e7171099ad36328829c3cde2a5')

  // sm3 + sm4-GCM
  bytes = sjcl.pkcs8.marshalPKCS8ECPrivateKey(keys.sec, true, 'Password1', { kdfOpts: { hash: 'sm3', iter: 2048 }, cipherOpts: { cipher: 'sm4', mode: 'gcm' } })
  prv = sjcl.pkcs8.parsePKCS8ECPrivateKey(bytes, 'Password1')
  serializedPrv = prv.serialize()
  t.equals(serializedPrv.exponent, '8604263b78b289bdd6b927d543b36088479688e7171099ad36328829c3cde2a5')

  // unsupported hash
  t.throws(() => {
    sjcl.pkcs8.marshalPKCS8ECPrivateKey(keys.sec, true, 'Password1', { kdfOpts: { hash: 'sha3' }, cipherOpts: { cipher: 'sm4' } })
  }, /pkcs8: unsupported hash algorithm sha3/)

  // unsupported cipher
  t.throws(() => {
    sjcl.pkcs8.marshalPKCS8ECPrivateKey(keys.sec, true, 'Password1', { kdfOpts: { hash: 'sm3' }, cipherOpts: { cipher: 'des' } })
  }, /pkcs8: unsupported cipher des-128-cbc/)
  t.throws(() => {
    sjcl.pkcs8.marshalPKCS8ECPrivateKey(keys.sec, true, 'Password1', { kdfOpts: { hash: 'sm3' }, cipherOpts: { cipher: 'aes', keyLen: 25 } })
  }, /pkcs8: unsupported cipher aes-200-cbc/)
  t.throws(() => {
    sjcl.pkcs8.marshalPKCS8ECPrivateKey(keys.sec, true, 'Password1', { kdfOpts: { hash: 'sm3' }, cipherOpts: { cipher: 'aes', mode: 'ctr', keyLen: 32 } })
  }, /pkcs8: unsupported cipher aes-256-ctr/)

  // invalid opts type
  t.throws(() => {
    sjcl.pkcs8.marshalPKCS8ECPrivateKey(keys.sec, true, 'Password1', [])
  }, /opts must be an object/)

  t.end()
})
