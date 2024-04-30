const test = require('tape')
const sjcl = require('sjcl-with-all')
require('../src/bytescodecHex').bindBytesCodecHex(sjcl)
const { Builder, Parser } = require('../src/asn1')

test('ASN1 builder basic', function (t) {
  const builder = new Builder()
  builder.addASN1Sequence((b) => {
    b.addASN1OctetString([1, 2, 3])
    b.addASN1OctetString([4, 5, 6])
    b.addASN1IntBytes([0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    b.addASN1IntBytes([0x00, 0xf1, 0x02, 0x03, 0x04, 0x05, 0x06])
    b.addASN1BitString([7, 8, 9])
    b.addASN1Boolean(true)
    b.addASN1Boolean(false)
    b.addASN1NULL()
    b.addASN1Sequence((b1) => {
      b1.addASN1IntBytes([0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
      b1.addASN1IntBytes([0x00, 0xf1, 0x02, 0x03, 0x04, 0x05, 0x06])
    })
  })
  t.equal(
    sjcl.bytescodec.hex.fromBytes(builder.bytes()),
    '303c040301020304030405060206010203040506020700f102030405060304000708090101ff010100050030110206010203040506020700f10203040506'
  )
  t.end()
})

test('ASN1 parser basic', function (t) {
  const input = new Parser(sjcl.bytescodec.hex.toBytes('303c040301020304030405060206010203040506020700f102030405060304000708090101ff010100050030110206010203040506020700f10203040506'))
  const c1 = {}
  const c2 = {}
  const c3 = {}
  const c4 = {}
  const c5 = {}
  const c6 = {}
  const c7 = {}
  const c8 = {}
  const c9 = {}
  const inner = {}
  const input1 = {}
  const fail = !input.readASN1Sequence(inner) ||
               !input.isEmpty() ||
               !inner.out.readASN1OctetString(c1) ||
               !inner.out.readASN1OctetString(c2) ||
               !inner.out.readASN1IntBytes(c3) ||
               !inner.out.readASN1IntBytes(c4) ||
               !inner.out.readASN1BitString(c5) ||
               !inner.out.readASN1Boolean(c6) ||
               !inner.out.readASN1Boolean(c7) ||
               !inner.out.skipASN1NULL() ||
               !inner.out.readASN1Sequence(input1) ||
               !inner.out.isEmpty() ||
               !input1.out.readASN1IntBytes(c8) ||
               !input1.out.readASN1IntBytes(c9) ||
               !input1.out.isEmpty()

  t.notOk(fail)
  t.deepEqual(c1.out, [1, 2, 3])
  t.deepEqual(c2.out, [4, 5, 6])
  t.deepEqual(c3.out, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
  t.deepEqual(c4.out, [0x00, 0xf1, 0x02, 0x03, 0x04, 0x05, 0x06])
  t.deepEqual(c5.out.bytes, [7, 8, 9])
  t.equal(c5.out.bitLength, 24)
  t.ok(c6.out)
  t.notOk(c7.out)
  t.deepEqual(c8.out, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
  t.deepEqual(c9.out, [0x00, 0xf1, 0x02, 0x03, 0x04, 0x05, 0x06])
  t.end()
})

test('Bytes', function (t) {
  const b = new Builder()
  b.addBytes(['f', 'o', 'o'])
  b.addBytes(['b'])
  b.addBytes(['a', 'r', 'b', 'a', 'z'])
  const s = new Parser(b.bytes())

  let w = s.readBytes(3)
  t.ok(w.success)
  t.deepEqual(w.value, ['f', 'o', 'o'])

  w = s.readBytes(3)
  t.ok(w.success)
  t.deepEqual(w.value, ['b', 'a', 'r'])

  w = s.readBytes(3)
  t.ok(w.success)
  t.deepEqual(w.value, ['b', 'a', 'z'])

  t.ok(s.isEmpty())
  t.end()
})
