import test from 'tape'
import sjcl from 'sjcl-with-all'
import bindSM3 from '../src/sm3.js'
import bindKDF from '../src/kdf.js'

bindKDF(sjcl)
bindSM3(sjcl)

test('KDF basic', function (t) {
  t.equal(
    sjcl.codec.hex.fromBits(sjcl.misc.kdf(128, 'emmansun')),
    '708993ef1388a0ae4245a19bb6c02554'
  )
  t.equal(
    sjcl.codec.hex.fromBits(sjcl.misc.kdf(256, 'emmansun')),
    '708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd4'
  )
  t.equal(
    sjcl.codec.hex.fromBits(sjcl.misc.kdf(384, 'emmansun')),
    '708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493'
  )
  t.equal(
    sjcl.codec.hex.fromBits(
      sjcl.misc.kdf(
        384,
        '708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493'
      )
    ),
    '49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f'
  )
  t.equal(
    sjcl.codec.hex.fromBits(
      sjcl.misc.kdf(
        1024,
        '708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493'
      )
    ),
    '49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f30277f3179baebd795e7853fa643fdf280d8d7b81a2ab7829f615e132ab376d32194cd315908d27090e1180ce442d9be99322523db5bfac40ac5acb03550f5c93e5b01b1d71f2630868909a6a1250edb'
  )
  t.end()
})
