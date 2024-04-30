/** @fileOverview Low-level asn1 encoder/decoder implementation.
 * Port from golang golang.org/x/crypto/cryptobyte.
 *  @author Emman Sun
 */

const classConstructed = 0x20
const classContextSpecific = 0x80
const DERBOOLEAN = 0x01
const DERINTEGER = 0x02
const DERBITSTRING = 0x03
const DEROCTETSTRING = 0x04
const DERNULL = 0x05
const DERSequence = 0x10 | classConstructed

function constructedTag (tag) {
  return tag | classConstructed
}

function contextSpecificTag (tag) {
  return tag | classContextSpecific
}

class Builder {
  constructor (buffer) {
    this.result = buffer || []
    this.offset = 0
  }

  bytes () {
    return this.result.slice(this.offset)
  }

  addByte (byte) {
    this._add([byte & 0xff])
  }

  /**
   * addBytes appends a sequence of bytes to the byte array.
   * @param {Array} bytes byte array
   */
  addBytes (bytes) {
    this._add(bytes)
  }

  addASN1Boolean (v) {
    if (typeof v !== 'boolean') {
      throw new Error('ASN1Boolean must be a boolean')
    }
    this.addASN1(DERBOOLEAN, (builder) => {
      builder.addByte(v ? 0xff : 0x00)
    })
  }

  addASN1NULL () {
    this.addBytes([DERNULL, 0])
  }

  addASN1Sequence (builderContinuation) {
    this.addASN1(DERSequence, (builder) => {
      this.callContinuation(builderContinuation, builder)
    })
  }

  /**
   * addASN1OctetString appends a DER-encoded ASN.1 OCTET STRING.
   * @param {Array} bytes the octet string byte array
   */
  addASN1OctetString (bytes) {
    this.addASN1(DEROCTETSTRING, (builder) => {
      builder.addBytes(bytes)
    })
  }

  /**
   * addASN1BitString appends a DER-encoded ASN.1 BIT STRING. This does not
   * support BIT STRINGs that are not a whole number of bytes.
   * @param {Array} bytes
   */
  addASN1BitString (bytes) {
    this.addASN1(DERBITSTRING, (builder) => {
      builder.addByte(0)
      builder.addBytes(bytes)
    })
  }

  /**
   * addASN1IntBytes encodes in ASN.1 a positive integer represented as
   * a big-endian byte slice with zero or more leading zeroes.
   * @param {Array} bytes the byte array of integer
   */
  addASN1IntBytes (bytes) {
    for (; bytes.length > 0 && bytes[0] === 0;) {
      bytes.splice(0, 1)
    }
    if (bytes.length === 0) {
      throw new Error('invalid integer')
    }
    this.addASN1(DERINTEGER, (builder) => {
      if (bytes[0] & 0x80) {
        bytes = [0].concat(bytes)
      }
      builder.addBytes(bytes)
    })
  }

  _add (bytes) {
    if (this.child) {
      throw new Error('attempted write while child is pending')
    }
    if (this.result.length + bytes.length < bytes.length) {
      throw new Error(' length overflow')
    }
    this.result.push(...bytes)
  }

  callContinuation (builderContinuation, builder) {
    const targetRoot = this._getRoot()
    if (!targetRoot.inContinuation) {
      targetRoot.inContinuation = true
    }
    try {
      builderContinuation(builder)
    } finally {
      targetRoot.inContinuation = false
    }
  }

  flushChild () {
    if (!this.child) {
      return
    }
    this.child.flushChild()
    const child = this.child
    this.child = null

    let length = child.result.length - child.pendingLenLen - child.offset
    if (length < 0) {
      throw new Error('internal error')
    }

    if (child.pendingIsASN1) {
      if (child.pendingLenLen !== 1) {
        throw new Error('internal error')
      }
      let lenLen, lenByte
      if (length > 0x00fffffffe) {
        throw new Error('pending ASN.1 child too long')
      } else if (length >= 0x1000000) {
        lenLen = 5
        lenByte = 0x80 | 0x04
      } else if (length >= 0x10000) {
        lenLen = 4
        lenByte = 0x80 | 0x03
      } else if (length >= 0x100) {
        lenLen = 3
        lenByte = 0x80 | 0x02
      } else if (length >= 0x80) {
        lenLen = 2
        lenByte = 0x80 | 0x01
      } else {
        lenLen = 1
        lenByte = length
        length = 0
      }
      child.result[child.offset] = lenByte
      child.offset++
      child.pendingLenLen = lenLen - 1
    }

    let l = length
    for (let i = child.pendingLenLen - 1; i >= 0; i--) {
      child.result.splice(child.offset, 0, l & 0xff)
      l = l >>> 8
    }
    if (l !== 0) {
      throw new Error(
        `pending child length ${length} exceeds ${child.pendingLenLen}-byte length profix`
      )
    }
    this.result = child.result
  }

  _getRoot () {
    return this.root || this
  }

  addLengthPrefixed (lenLen, isASN1, builderContinuation) {
    const offset = this.result.length

    for (let i = 0; i < lenLen; i++) {
      this.addByte(0)
    }
    const targetRoot = this._getRoot()
    if (typeof targetRoot.inContinuation === 'undefined') {
      targetRoot.inContinuation = false
    }
    this.child = new Builder()
    this.child.root = this.root || this
    this.child.result = this.result
    this.child.offset = offset
    this.child.pendingLenLen = lenLen
    this.child.pendingIsASN1 = isASN1

    this.callContinuation(builderContinuation, this.child)
    this.flushChild()
    if (this.child) {
      throw new Error('internal error')
    }
  }

  addASN1 (tag, builderContinuation) {
    if ((tag & 0x1f) === 0x1f) {
      throw new Error(
        'high-tag number identifier octects not supported: 0x' +
          tag.toString(16)
      )
    }
    this.addByte(tag)
    this.addLengthPrefixed(1, true, builderContinuation)
  }
}

class Parser {
  constructor (bytes) {
    this.bytes = bytes
  }

  length () {
    return this.bytes ? this.bytes.length : 0
  }

  /**
   * peekASN1Tag reports whether the next ASN.1 value on the string starts with the given tag.
   * @param {uint8} tag
   * @returns true or false
   */
  peekASN1Tag (tag) {
    if (this.isEmpty()) {
      return false
    }
    return this.bytes[0] === tag
  }

  skipASN1NULL () {
    return this.skipASN1(DERNULL)
  }

  /**
   * skipOptionalASN1 advances s over an ASN.1 element with the given tag, or else leaves s unchanged.
   * @param {uint8} tag
   * @returns It reports whether the operation was successful.
   */
  skipOptionalASN1 (tag) {
    if (!this.peekASN1Tag(tag)) {
      return true
    }
    return this.readASN1({}, tag)
  }

  /**
   * skipASN1 reads and discards an ASN.1 element with the given tag.
   * @param {uint8} tag
   * @returns reports whether the operation was successful.
   */
  skipASN1 (tag) {
    return this.readASN1({}, tag)
  }

  readASN1Sequence (output) {
    return this.readASN1(output, DERSequence)
  }

  readASN1IntBytes (output) {
    return this.readASN1Bytes(output, DERINTEGER)
  }

  readASN1OctetString (output) {
    return this.readASN1Bytes(output, DEROCTETSTRING)
  }

  /**
   * readASN1BitString decodes an ASN.1 BIT STRING into output and advances.
   * @param {object} output
   * @returns {boolean} It reports whether the read was successful.
   */
  readASN1BitString (output) {
    if (!this.readASN1(output, DERBITSTRING) || output.out.isEmpty() || output.out.length() * 8 / 8 !== output.out.length()) {
      return false
    }
    const paddingBits = output.out.bytes[0]
    const bytes = output.out.bytes.slice(1)
    if (paddingBits > 7 || (bytes.length === 0 && paddingBits !== 0) ||
      (bytes.length > 0 && (bytes[bytes.length - 1] & (1 << (paddingBits - 1))) !== 0)) {
      return false
    }
    output.out = {
      bytes,
      bitLength: bytes.length * 8 - paddingBits
    }
    return true
  }

  readASN1Boolean (output) {
    if (!this.readASN1(output, DERBOOLEAN) || output.out.length() !== 1) {
      return false
    }

    output.out = output.out.bytes[0] === 0xff
    return true
  }

  readASN1Bytes (output, tag) {
    const result = this.readASN1(output, tag)
    if (!result) {
      return false
    }
    output.out = output.out.bytes
    return true
  }

  /**
   * readOptionalASN1 attempts to read the contents of a DER-encoded ASN.1 element (not including tag and length bytes)
   * tagged with the given tag into output.out. It stores whether an element with the tag was found in output.preset.
   * @param {object} output
   * @param {uint8} tag
   * @returns {boolean} It reports whether the read was successful.
   */
  readOptionalASN1 (output, tag) {
    const present = this.peekASN1Tag(tag)
    if (present) {
      const success = this.readASN1(output, tag)
      output.present = true
      return success
    }
    output.present = false
    return true
  }

  readASN1 (output, tag) {
    const result = this.readAnyASN1(output)
    if (!result || tag !== output.tag) {
      return false
    }
    return true
  }

  /**
   * readAnyASN1 reads the contents of a DER-encoded ASN.1 element (not including tag and length bytes) into output.out,
   * sets output.tag to its tag, and advances. Tags greater than 30 are not supported (i.e. low-tag-number format only).
   * @param {object} output
   * @returns {boolean} reports whether the read was successful.
   */
  readAnyASN1 (output) {
    return this._readASN1(output, true)
  }

  /**
   * readAnyASN1Element reads the contents of a DER-encoded ASN.1 element (including tag and length bytes) into output.out,
   * sets out.tag to its tag, and advances. Tags greater than 30 are not supported (i.e. low-tag-number format only).
   * @param {object} output
   * @returns {boolean} reports whether the read was successful.
   */
  readAnyASN1Element (output) {
    return this._readASN1(output, false)
  }

  _readASN1 (output, skipHeader = false) {
    if (!(output instanceof Object) || Object.keys(output).length > 0) {
      throw new Error('please provide an empty object as output')
    }
    if (!this.bytes || this.bytes.length < 2) {
      return false
    }
    const tag = this.bytes[0]
    const lenBytes = this.bytes[1]
    if ((tag & 0x1f) === 0x1f) {
    // ITU-T X.690 section 8.1.2
    //
    // An identifier octet with a tag part of 0x1f indicates a high-tag-number
    // form identifier with two or more octets. We only support tags less than
    // 31 (i.e. low-tag-number form, single octet identifier).
      return false
    }

    let length = 0
    let headerLen = 0
    // ITU-T X.690 section 8.1.3
    //
    // Bit 8 of the first length byte indicates whether the length is short- or
    // long-form.
    if ((lenBytes & 0x80) === 0) {
      // Short-form length (section 8.1.3.4), encoded in bits 1-7.
      length = lenBytes + 2
      headerLen = 2
    } else {
      // Long-form length (section 8.1.3.5). Bits 1-7 encode the number of octets
      // used to encode the length.
      const lenLen = lenBytes & 0x7f
      if (lenLen === 0 || lenLen > 4 || this.length < lenLen + 2) {
        return false
      }
      const lenBytesParser = new Parser(this.bytes.slice(2, lenLen + 2))
      const len = lenBytesParser.readUnsigned(lenLen)
      if (!len.success) {
        return false
      }
      const len32 = len.value
      // ITU-T X.690 section 10.1 (DER length forms) requires encoding the length
      // with the minimum number of octets.
      if (len32 < 128) {
        // Length should have used short-form encoding.
        return false
      }
      if (len32 >>> ((lenLen - 1) * 8) === 0) {
        // Leading octet is 0. Length should have been at least one byte shorter.
        return false
      }
      headerLen = lenLen + 2
      if (headerLen + len32 < len32) {
        // Overflow.
        return false
      }
      length = headerLen + len32
    }

    if (length < 0) {
      return false
    }
    const v = this.readBytes(length)
    if (!v.success) {
      return false
    }
    const out = new Parser(v.value)
    if (skipHeader && !out.skip(headerLen)) {
      throw new Error('internal error')
    }

    output.tag = tag
    output.out = out
    return true
  }

  readUint8 () {
    const v = this.read(1)
    if (v === undefined) {
      return { success: false }
    }
    return { success: true, value: v[0] & 0xff }
  }

  readUint6 () {
    const v = this.read(2)
    if (v === undefined) {
      return { success: false }
    }
    return { success: true, value: ((v[0] << 8) | v[1]) >>> 0 }
  }

  readUint24 () {
    const v = this.read(3)
    if (v === undefined) {
      return { success: false }
    }
    return { success: true, value: ((v[0] << 16) | (v[1] << 8) | v[2]) >>> 0 }
  }

  readUint32 () {
    const v = this.read(4)
    if (v === undefined) {
      return { success: false }
    }
    return { success: true, value: ((v[0] << 24) | (v[1] << 16) | (v[2] << 8) | v[3]) >>> 0 }
  }

  readUnsigned (length) {
    const v = this.read(length)
    if (v === undefined) {
      return { success: false }
    }
    let value = 0
    for (let i = 0; i < length; i++) {
      value = (value << 8) | v[i]
    }
    return { success: true, value: value >>> 0 }
  }

  readLengthPrefixed (lenLen) {
    let v = this.read(lenLen)
    if (v === undefined) {
      return { success: false }
    }
    let length = 0
    for (let i = 0; i < lenLen; i++) {
      length = (length << 8) | v[i]
    }
    v = this.read(length)
    if (v === undefined) {
      return { success: false }
    }
    return { success: true, value: new Parser(v) }
  }

  readBytes (n) {
    const v = this.read(n)
    if (v === undefined) {
      return { success: false }
    }
    return { success: true, value: v }
  }

  isEmpty () {
    return this.length() === 0
  }

  read (n) {
    if (this.bytes.length < n || n < 0) {
      return
    }
    const result = this.bytes.slice(0, n)
    this.bytes = this.bytes.slice(n)
    return result
  }

  skip (n) {
    return this.read(n) !== undefined
  }
}

module.exports = {
  constructedTag,
  contextSpecificTag,
  Builder,
  Parser
}
