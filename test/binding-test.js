'use strict';

const assert = require('assert');
const huffin = require('huffin');
const Buffer = require('buffer').Buffer;

const binding = require('../');

describe('ed25519-id-binding', () => {
  it('should generate', () => {
    const prefix = huffin.parsePrefix('wut');
    let pair = null;
    for (;;) {
      const res = binding.generate(prefix.value.toBuffer(), prefix.bitLength, 10000);
      if (res !== false) {
        pair = { secretKey: res, publicKey: res.slice(32) };
        break;
      }
    }

    assert(/@ok\//.test(huffin.stringify(pair.publicKey)));
  });
});
