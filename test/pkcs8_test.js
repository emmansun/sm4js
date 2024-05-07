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
