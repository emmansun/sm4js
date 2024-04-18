# sm4js
[![SM4JS CI](https://github.com/emmansun/sm4js/actions/workflows/ci.yml/badge.svg)](https://github.com/emmansun/sm4js/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/gmsm-sm4js.svg)](https://badge.fury.io/js/gmsm-sm4js)
[![NPM Downloads][npm-downloads-image]][npm-url]

**A Simple Pure JavaScript GM-Standards SM2/SM3/SM4 Implementation based on [sjcl](https://github.com/bitwiseshiftleft/sjcl).**

## SM2
目前实现：签名结果为**r || s**的拼接；加密结果为**C1 || C3 || C2**拼接，且C1没有点格式前缀字节。为了与其它系统兼容，需要进一步处理。具体使用方法，请参考[sm2_test.js](https://github.com/emmansun/sm4js/blob/master/src/sm2_test.js "sm2_test.js")

和[gmsm-sm2js](https://github.com/emmansun/sm2js)互操作示例：
```javascript
const test = require('tape')
const rs = require('jsrsasign')
const sm2 = require('gmsm-sm2js')
const sjclsm = require('gmsm-sm4js')
const sjcl = require('sjcl-with-all')
sjclsm.bindKDF(sjcl)
sjclsm.bindSM3(sjcl)
sjclsm.bindSM2(sjcl)

const sm2PrivateKeyEncryptedPKCS8 = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH2MGEGCSqGSIb3DQEFDTBUMDQGCSqGSIb3DQEFDDAnBBDa6ckWJNP3QBD7MIF8
4nVqAgEQAgEQMA0GCSqBHM9VAYMRAgUAMBwGCCqBHM9VAWgCBBDMUgr+5Y/XN2g9
mPGiISzGBIGQytwK98/ET4WrS0H7AsUri6FTqztrzAvgzFl3+s9AsaYtUlzE3EzE
x6RWxo8kpKO2yj0a/Jh9WZCD4XAcoZ9aMopiWlOdpXJr/iQlMGdirCYIoF37lHMc
jZHNffmk4ii7NxCfjrzpiFq4clYsNMXeSEnq1tuOEur4kYcjHYSIFc9bPG656a60
+SIJsJuPFi0f
-----END ENCRYPTED PRIVATE KEY-----`

test('Parse PKCS8 encrypted SM2 private key and work with sjcl based implementation', function (t) {
  const key = rs.KEYUTIL.getKeyFromEncryptedPKCS8PEM(sm2PrivateKeyEncryptedPKCS8, 'Password1')
  const SM2PublicKey = sjcl.ecc.sm2.publicKey
  const pk = new SM2PublicKey(
    sjcl.codec.hex.toBits(
      key.pubKeyHex.substring(2)
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
  
  const keys = sjcl.ecc.sm2.generateKeys(
    sjcl.codec.hex.toBits(key.prvKeyHex)
  )
  const testString = 'send reinforcements, we\'re going to advance'

  // gmsm-sm2js encrypt, gmsm-sm4js decrypt
  let ciphertext = sm2.encrypt(key.pubKeyHex, testString)
  let plaintext = keys.sec.decrypt(sjcl.codec.hex.toBits(ciphertext.substring(2)))
  t.equals(sjcl.codec.utf8String.fromBits(plaintext), testString)

  // gmsm-sm4js encrypt, gmsm-sm2js decrypt
  ciphertext = keys.pub.encrypt(testString)
  ciphertext = '04'+sjcl.codec.hex.fromBits(ciphertext)
  plaintext = sm2.decryptHex(key.prvKeyHex, ciphertext)
  t.equals(Buffer.from(plaintext, 'hex').toString('ascii'), testString)

  t.end()
})
```

## SM3
位于**sjcl.hash.sm3**中，使用方式和其它哈希算法相同。具体使用方法，请参考[sm3_test.js](https://github.com/emmansun/sm4js/blob/master/src/sm3_test.js "sm3_test.js")


## SM4
位于**sjcl.cipher.sm4**中，使用方式和AES相同。具体使用方法，请参考[sm4_test.js](https://github.com/emmansun/sm4js/blob/master/src/sm4_test.js "sm4_test.js")


如果是NodeJS的后端应用，请直接使用NodeJS提供的SM4实现(基于OpenSSL)。NodeJS目前尚未支持SM4-GCM模式，请参考[一种使用nodejs SM4-ECB和sjcl gcm的SM4-GCM实现](https://gist.github.com/emmansun/2eb37257cfe6ed561d1668f720f51030)。

[npm-downloads-image]: https://badgen.net/npm/dm/gmsm-sm4js
[npm-url]: https://npmjs.org/package/gmsm-sm4js
