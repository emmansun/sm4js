# sm4js
[![SM4JS CI](https://github.com/emmansun/sm4js/actions/workflows/ci.yml/badge.svg)](https://github.com/emmansun/sm4js/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/gmsm-sm4js.svg)](https://badge.fury.io/js/gmsm-sm4js)
[![NPM Downloads][npm-downloads-image]][npm-url]

**A Simple Pure JavaScript GM-Standards SM2/SM3/SM4 Implementation based on [sjcl](https://github.com/bitwiseshiftleft/sjcl).**

## SM2
目前实现：签名结果为**r || s**的拼接；加密结果为**C1 || C3 || C2**拼接，且C1没有点格式前缀字节。为了与其它系统兼容，需要进一步处理。具体使用方法，请参考[sm2_test.js](https://github.com/emmansun/sm4js/blob/master/src/sm2_test.js "sm2_test.js")

## SM3
位于**sjcl.hash.sm3**中，使用方式和其它哈希算法相同。具体使用方法，请参考[sm3_test.js](https://github.com/emmansun/sm4js/blob/master/src/sm3_test.js "sm3_test.js")


## SM4
位于**sjcl.cipher.sm4**中，使用方式和AES相同。具体使用方法，请参考[sm4_test.js](https://github.com/emmansun/sm4js/blob/master/src/sm4_test.js "sm4_test.js")


如果是NodeJS的后端应用，请直接使用NodeJS提供的SM4实现(基于OpenSSL)。NodeJS目前尚未支持SM4-GCM模式，请参考[一种使用nodejs SM4-ECB和sjcl gcm的SM4-GCM实现](https://gist.github.com/emmansun/2eb37257cfe6ed561d1668f720f51030)。

[npm-downloads-image]: https://badgen.net/npm/dm/gmsm-sm4js
[npm-url]: https://npmjs.org/package/gmsm-sm4js
