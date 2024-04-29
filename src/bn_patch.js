function patchBN (sjcl) {
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
}

module.exports = {
  patchBN
}
