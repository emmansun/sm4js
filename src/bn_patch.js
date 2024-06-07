export default function patchBN (sjcl) {
  /** Serialize to a byte array
   * @param {number} l The desired byte length.
   */
  sjcl.bn.prototype.toBytes = sjcl.bn.prototype.toBytes || function (l) {
    this.fullReduce()
    const result = []
    const limbs = this.limbs
    for (let i = limbs.length - 1; i >= 0; i--) {
      result.push((limbs[i] >> 16) & 0xff)
      result.push((limbs[i] >> 8) & 0xff)
      result.push(limbs[i] & 0xff)
    }
    l = l || Math.ceil(this.bitLength() / 8)
    if (l > result.length) {
      result.splice(0, 0, ...Array(l - result.length).fill(0))
    } else if (l < result.length) {
      result.splice(0, result.length - l)
    }
    return result
  }

  /** @memberOf sjcl.bn
   * @param {sjcl.BitArray} bytes The byte array to deserialize.
   */
  sjcl.bn.fromBytes = function (bytes) {
    const Class = this
    const out = new Class()
    if (!Array.isArray(bytes) || bytes.length === 0) {
      out.limbs = [0]
      return out
    }
    out.limbs = []
    const k = out.radix / 8
    const len = bytes.length
    for (let i = 0; i < len; i += k) {
      const end = len - i
      const start = Math.max(end - k, 0)
      let tmp = 0
      for (let j = start; j < end; j++) {
        tmp = tmp << 8 | (bytes[j] & 0xff)
      }
      out.limbs.push(tmp)
    }

    return out
  }
}
