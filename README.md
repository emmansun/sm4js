# sm4js (sjcl-sm)
[![SM4JS CI](https://github.com/emmansun/sm4js/actions/workflows/ci.yml/badge.svg)](https://github.com/emmansun/sm4js/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/gmsm-sm4js.svg)](https://badge.fury.io/js/gmsm-sm4js)
[![NPM Downloads][npm-downloads-image]][npm-url]

`gmsm-sm4js` 是基于 [SJCL](https://github.com/bitwiseshiftleft/sjcl) 的 SM2、SM3 和 SM4 实现。调用 `initialize(sjcl)` 即可将全部能力注册到应用提供的 SJCL 实例上；也可按需使用单独的 `bind*` 函数。

> **安全提示：本库不承诺恒定时间（constant-time）运行，也不提供完整的侧信道防护保证。SM4-CBC 不提供消息认证。** 对侧信道防护有严格要求的场景，应使用对目标算法及平台明确提供相应保证的实现。

## 安装

```bash
npm install gmsm-sm4js sjcl-with-all
```

本包提供 CommonJS 和 ESM 入口。以下示例使用 Node.js CommonJS；`sjcl-with-all` 需要由应用单独安装并传给本包的绑定函数。

## 快速开始

### SM2 加解密与签名

```javascript
const sjcl = require('sjcl-with-all')
const { initialize } = require('gmsm-sm4js')
initialize(sjcl)

const keys = sjcl.ecc.sm2.generateKeys()
const message = 'hello SM2'
const ciphertextHex = keys.pub.encrypt(message)
const plaintextBits = keys.sec.decrypt(ciphertextHex)
console.log(sjcl.codec.utf8String.fromBits(plaintextBits))

const signatureHex = keys.sec.signHash(keys.pub.hash(message))
console.log(keys.pub.verify(message, signatureHex))
```

`encrypt` 默认返回 ASN.1 编码的十六进制密文；`decrypt` 返回 SJCL bitArray。SM2 私钥标量范围为 `[1, n-2]`。普通消息签名应先通过 `publicKey.hash(message, uid)` 计算含 ZA 的摘要；签名和验签双方必须使用相同 UID。默认 UID 为 `1234567812345678`。

SM2 密钥交换相关接口为 `secretKey.implicitSig`、`publicKey.sharedSecretKey` 和 `publicKey.agreedKey`。创建密钥交换临时密钥时，可用 `generateKeys(undefined, paranoia, false)` 允许随机标量取到 `n-1`；不要用此选项生成长期签名私钥。完整示例见 [SM2 测试](https://github.com/emmansun/sm4js/blob/master/test/sm2_test.js)。

### SM3 摘要

```javascript
const sjcl = require('sjcl-with-all')
const { initialize } = require('gmsm-sm4js')

initialize(sjcl)
const digestHex = sjcl.codec.hex.fromBits(sjcl.hash.sm3.hash('abc'))
console.log(digestHex)
```

输出 `66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0`。SM3 返回 SJCL bitArray；需要十六进制时使用 `sjcl.codec.hex.fromBits`。

### SM4-GCM 加解密

```javascript
const { randomBytes } = require('node:crypto')
const sjcl = require('sjcl-with-all')
const { initialize } = require('gmsm-sm4js')

initialize(sjcl)
const key = sjcl.codec.bytes.toBits(Array.from(randomBytes(16)))
const nonce = sjcl.codec.bytes.toBits(Array.from(randomBytes(12)))
const plaintext = sjcl.codec.utf8String.toBits('hello SM4')
const cipher = new sjcl.cipher.sm4(key)

const ciphertext = sjcl.mode.gcm.encrypt(
  cipher,
  plaintext,
  nonce,
  undefined,
  128
)
const decrypted = sjcl.mode.gcm.decrypt(
  cipher,
  ciphertext,
  nonce,
  undefined,
  128
)
console.log(sjcl.codec.utf8String.fromBits(decrypted))
```

SM4 是 128 位分组密码，密钥为 16 字节。GCM 密文包含认证标签；同一密钥下不得重复使用 nonce。底层 SM4 block cipher 也可配合 SJCL 支持的其他 mode 使用。CBC 不提供完整性或来源认证，不能把填充校验当作认证。更多向量见 [SM4 测试](https://github.com/emmansun/sm4js/blob/master/test/sm4_test.js)。

## API 与编码约定

`initialize(sjcl)` 会注册全部算法并返回传入的同一实例，适合一般应用。需要精简注册范围时，可单独调用表中的 `bind*`；`bindSM2` 会自动绑定所需的 SM3 和 KDF，`bindPKIX` 会绑定 SM2，`bindPKCS8` 会绑定 SM3、SM4 和 PKIX。

| 导出 | 用途 |
| --- | --- |
| `initialize(sjcl)` | 一次注册全部算法，并返回同一个 SJCL 实例 |
| `bindSM2(sjcl)` | 注册 SM2 曲线、密钥、加解密、签名和密钥交换接口 |
| `bindSM3(sjcl)` | 注册 `sjcl.hash.sm3` 和 HMAC-SM3 支持 |
| `bindKDF(sjcl)` | 注册 `sjcl.misc.kdf`，供 SM2 加解密及密钥交换使用 |
| `bindSM4(sjcl)` | 注册 `sjcl.cipher.sm4`，可配合 SJCL modes 使用 |
| `bindPKIX(sjcl)` | 注册 EC PKIX 公钥及 SEC1 私钥解析、构造 |
| `bindPKCS8(sjcl)` | 注册 PKCS#8 私钥解析、构造和加密 |
| `bindBytesCodecHex(sjcl)` | 注册 `sjcl.bytescodec.hex` 字节与十六进制转换 |
| `asn1` | ASN.1 DER `Builder` 和 `Parser` |

- `sjcl.ecc.sm2.generateKeys()` 返回 `{ pub, sec }`。传入自定义私钥时，标量必须位于 `[1, n-2]`。
- `publicKey.encrypt(message)` 接受 UTF-8 字符串或 SJCL bitArray，默认返回 ASN.1 格式十六进制密文；第三个参数可设为 `'c1c3c2'` 获取裸格式。`secretKey.decrypt(ciphertextHex)` 返回 bitArray。
- `secretKey.signHash(hash)` 返回 ASN.1 DER 签名的十六进制字符串；`publicKey.verify(message, signatureHex)` 对消息计算 SM2 摘要后验签。`hash`、`signHash`、`verifyHash` 可用于分步处理。
- `sjcl.pkix.marshalPKIXPublicKey`、`marshalECPrivateKey`、`sjcl.pkcs8.marshalPKCS8ECPrivateKey` 返回 DER 字节数组；对应的解析函数也接收 DER 字节数组。用 `sjcl.bytescodec.hex.fromBytes` 转成十六进制。
- `marshalPKCS8ECPrivateKey(key)` 生成未加密 PKCS#8；传入非空密码则加密。加密支持 PBES2/PBKDF2、HMAC-SHA1/SHA256/SHA512/SM3，以及 AES/SM4 的 CBC/GCM。空密码会报错。

## PKCS#8 参数

加密 PKCS#8 默认使用 AES-128-GCM、PBKDF2-HMAC-SHA256、600,000 次迭代和 128 位盐。可通过 `opts` 自定义，例如：

下面的密码仅作示例；实际应用应从安全配置来源读取密码。

```javascript
const sjcl = require('sjcl-with-all')
const { initialize } = require('gmsm-sm4js')

initialize(sjcl)
const keys = sjcl.ecc.sm2.generateKeys()
const plaintextDER = sjcl.pkcs8.marshalPKCS8ECPrivateKey(keys.sec)
const password = 'example-only-password'
const encryptedDER = sjcl.pkcs8.marshalPKCS8ECPrivateKey(
  keys.sec,
  true,
  password,
  {
    kdfOpts: { hash: 'sha256', iter: 600000, saltLen: 128 },
    cipherOpts: { cipher: 'aes', mode: 'gcm', keyLen: 16 }
  }
)

const plainKey = sjcl.pkcs8.parsePKCS8ECPrivateKey(plaintextDER)
const encryptedKey = sjcl.pkcs8.parsePKCS8ECPrivateKey(
  encryptedDER,
  password
)
```

省略密码（或传 `null`）表示未加密 PKCS#8；不要将明文私钥写入日志或公开位置。空字符串不会被当作“无密码”，而是明确报错。解析器接受旧 CBC 加密文件，但 CBC 不提供完整性保护。为限制恶意输入造成的计算消耗，PBKDF2 迭代次数必须在 `1..1,000,000` 之间；加密时盐长度限制为 128..4096 位。

## 运行环境

- 提供 CommonJS 和 ESM 包入口。CI 当前测试 Node.js 22、24、26；这不是对未测试 Node.js 版本的兼容承诺。
- SM2、SM3 和 SM4 由 JavaScript 实现。Node.js 后端应用可评估使用 Node.js/OpenSSL 原生 SM4；Node.js 原生接口不支持 SM4-GCM 时，可将原生 SM4 block cipher 与 SJCL GCM mode 组合使用。
- 本仓库的测试在 Node.js 中运行，不等同于浏览器兼容性验证。

## 安全与兼容性

本库不承诺 constant-time 运行。JavaScript JIT、垃圾回收和执行环境均不受本库控制；纯 JavaScript SM4 使用查表算法，SM2 也不能视为具备侧信道防护的实现。对侧信道防护有严格要求的场景，应选择经过审计、对目标算法及平台明确提供相应保证的原生密码库、系统接口或硬件实现。

SM4-CBC 和 PKCS#8 中的 CBC 加密均不提供消息认证。需要完整性保护时优先使用认证加密模式；兼容旧格式时，应在更高层协议中单独验证来源和完整性。

## 测试

```bash
npm ci
npm test
npm run build
```

测试覆盖 SM2/SM3/SM4 向量、密钥编码、签名验签、PKCS#8 加解密及无效输入。测试通过不代表密码实现获得安全认证。

## 许可证

[MIT](LICENSE)。

[npm-downloads-image]: https://badgen.net/npm/dm/gmsm-sm4js
[npm-url]: https://npmjs.org/package/gmsm-sm4js
