const test = require('tape')
const sjcl = require('sjcl-with-all')
require('./sm3').bindSM3(sjcl)

test('SM3 basic', function (t) {
  const testVector = [
    {
      input: 'abc',
      hash: '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'
    },
    {
      input: 'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd',
      hash: 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732'
    },
    {
      input: 'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd',
      hash: '6888fa292df4b51341e82e3072fbdd63598439c64eda318a81756ca71a7a6c15'
    },
    { // From [GBT.32918.2-2016] A.2 Example 1
      input: sjcl.codec.hex.toBits(
        '0090414C494345313233405941484F4F2E434F4D787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E49863E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A20AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857'
      ),
      hash: 'f4a38489e32b45b6f876e3ac2168ca392362dc8f23459c1d1146fc3dbfb7bc9a'
    },
    { // From [GBT.32918.2-2016] A.2 Example 2
      input: sjcl.codec.hex.toBits(
        'F4A38489E32B45B6F876E3AC2168CA392362DC8F23459C1D1146FC3DBFB7BC9A6D65737361676520646967657374'
      ),
      hash: 'b524f552cd82b8b028476e005c377fb19a87e6fc682d48bb5d42e3d9b9effe76'
    },
    { // GB/T 32918.2-2016 A.3 Example 1
      input: sjcl.codec.hex.toBits(
        '0090414C494345313233405941484F4F2E434F4D00000000000000000000000000000000000000000000000000000000000000000000E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E0165961645281A8626607B917F657D7E9382F1EA5CD931F40F6627F357542653B201686522130D590FB8DE635D8FCA715CC6BF3D05BEF3F75DA5D543454448166612'
      ),
      hash: '26352af82ec19f207bbc6f9474e11e90ce0f7ddace03b27f801817e897a81fd5'
    },
    { // From [GBT.32918.2-2016] A.3 Example 2
      input: sjcl.codec.hex.toBits(
        '26352AF82EC19F207BBC6F9474E11E90CE0F7DDACE03B27F801817E897A81FD56D65737361676520646967657374'
      ),
      hash: 'ad673cbda311417129a9eaa5f9ab1aa1633ad47718a84dfd46c17c6fa0aa3b12'
    },
    { // GB/T 32918.4-2016 A.3 Example 1
      input: sjcl.codec.hex.toBits(
        '01C6271B31F6BE396A4166C0616CF4A8ACDA5BEF4DCBF2DD42656E6372797074696F6E207374616E646172640147AF35DFA1BFE2F161521BCF59BAB83564868D9295881735'
      ),
      hash: 'f0a41f6f48ac723cecfc4b767299a5e25c0641679fbd2d4d20e9ffd5b9f0dab8'
    },
    { // GB/T 32918.4-2016 A.3 Example 2
      input: sjcl.codec.hex.toBits(
        '0083E628CF701EE3141E8873FE55936ADF24963F5DC9C6480566C80F8A1D8CC51B656E6372797074696F6E207374616E6461726401524C647F0C0412DEFD468BDA3AE0E5A80FCC8F5C990FEE11602929232DCD9F36'
      ),
      hash: '73a48625d3758fa37b3eab80e9cfcaba665e3199ea15a1fa8189d96f579125e4'
    },
    { // GB/T 32918.4-2016 A.3 Example 2
      input: sjcl.codec.bytes.toBits(
        new Uint8Array(Buffer.from(
          '0083E628CF701EE3141E8873FE55936ADF24963F5DC9C6480566C80F8A1D8CC51B656E6372797074696F6E207374616E6461726401524C647F0C0412DEFD468BDA3AE0E5A80FCC8F5C990FEE11602929232DCD9F36'
          , 'hex')
        )),
      hash: '73a48625d3758fa37b3eab80e9cfcaba665e3199ea15a1fa8189d96f579125e4'
    }
  ]

  for (let i = 0; i < testVector.length; i++) {
    t.equal(sjcl.codec.hex.fromBits(sjcl.hash.sm3.hash(testVector[i].input)), testVector[i].hash)
  }

  t.end()
})

test('HMAC SM3 test', function (t) {
  // GM/T 0042-2015 Appendix D.3
  const testVector = [
    {
      key: sjcl.codec.hex.toBits('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'),
      data: 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
      mac: 'ca05e144ed05d1857840d1f318a4a8669e559fc8391f414485bfdf7bb408963a'
    },
    {
      key: sjcl.codec.hex.toBits('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425'),
      data: sjcl.codec.hex.toBits('cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd'),
      mac: '220bf579ded555393f0159f66c99877822a3ecf610d1552154b41d44b94db3ae'
    },
    {
      key: sjcl.codec.hex.toBits('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
      data: 'Hi There',
      mac: 'c0ba18c68b90c88bc07de794bfc7d2c8d19ec31ed8773bc2b390c9604e0be11e'
    },
    {
      key: sjcl.codec.utf8String.toBits('Jefe'),
      data: 'what do ya want for nothing?',
      mac: '2e87f1d16862e6d964b50a5200bf2b10b764faa9680a296a2405f24bec39f882'
    }
  ]
  const HMAC = sjcl.misc.hmac
  for (let i = 0; i < testVector.length; i++) {
    const mac = new HMAC(testVector[i].key, sjcl.hash.sm3)
    t.equal(sjcl.codec.hex.fromBits(mac.mac(testVector[i].data)), testVector[i].mac)

    t.equal(sjcl.codec.hex.fromBits(mac.mac(testVector[i].data)), testVector[i].mac)
  }

  t.end()
})
