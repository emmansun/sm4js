/** @fileOverview some bytes codec functions.
 *  @author Emman Sun
 */

function bindBytesCodecHex (sjcl) {
  sjcl.bytescodec = sjcl.bytescodec || {}
  sjcl.bytescodec.hex = sjcl.bytescodec.hex || {
    fromBytes: function (arr) {
      let res = ''
      for (let i = 0; i < arr.length; i++) {
        let hex = (arr[i] & 0xff).toString(16)
        if (hex.length === 1) {
          hex = '0' + hex
        }
        res += hex
      }
      return res
    },
    toBytes: function (hexStr) {
      if (typeof hexStr !== 'string' || hexStr.length % 2 === 1) {
        throw new Error('Invalid hex string')
      }
      const res = []
      for (let i = 0; i < hexStr.length; i += 2) {
        res.push(parseInt(hexStr.substr(i, 2), 16))
      }
      return res
    }
  }
}

module.exports = { bindBytesCodecHex }
