/*!
 * deps/forge.js - Forge Package Customization
 *
 * Copyright (c) 2015 Cisco Systems, Inc.  See LICENSE file.
 */
"use strict";

var forge = require("node-forge");
/*{
  aes: require("node-forge/lib/aes"),
  asn1: require("node-forge/lib/asn1"),
  cipher: require("node-forge/lib/cipher"),
  hmac: require("node-forge/lib/hmac"),
  jsbn: require("node-forge/lib/jsbn"),
  md: require("node-forge/lib/md"),
  mgf: require("node-forge/lib/mgf"),
  pem: require("node-forge/lib/pem"),
  pkcs1: require("node-forge/lib/pkcs1"),
  pkcs5: require("node-forge/lib/pbkdf2"),
  pkcs7: require("node-forge/lib/pkcs7"),
  pki: require("node-forge/lib/x509"),
  prime: require("node-forge/lib/prime"),
  prng: require("node-forge/lib/prng"),
  pss: require("node-forge/lib/pss"),
  random: require("node-forge/lib/random"),
  util: require("node-forge/lib/util")
};//*/

// load hash algorithms
//require("node-forge/lib/sha1");
//require("node-forge/lib/sha256");
//require("node-forge/lib/sha512");

// load symmetric cipherModes
//require("node-forge/lib/cipherModes");

// load AES cipher suites
// TODO: move this to a separate file
//require("node-forge/lib/aesCipherSuites");

// Define AES "raw" cipher mode
function modeRaw(options) {
  options = options || {};
  this.name = "";
  this.cipher = options.cipher;
  this.blockSize = options.blockSize || 16;
  this._blocks = this.blockSize / 4;
  this._inBlock = new Array(this._blocks);
  this._outBlock = new Array(this._blocks);
}

modeRaw.prototype.start = function() {};

modeRaw.prototype.encrypt = function(input, output, finish) {
  if (input.length() < this.blockSize && !(finish && input.length() > 0)) {
    return true;
  }

  var i;

  // get next block
  for(i = 0; i < this._blocks; ++i) {
    this._inBlock[i] = input.getInt32();
  }

  // encrypt block
  this.cipher.encrypt(this._inBlock, this._outBlock);

  // write output
  for(i = 0; i < this._blocks; ++i) {
    output.putInt32(this._outBlock[i]);
  }
};

modeRaw.prototype.decrypt = function(input, output, finish) {
  if (input.length() < this.blockSize && !(finish && input.length() > 0)) {
    return true;
  }

  var i;

  // get next block
  for(i = 0; i < this._blocks; ++i) {
    this._inBlock[i] = input.getInt32();
  }

  // decrypt block
  this.cipher.decrypt(this._inBlock, this._outBlock);

  // write output
  for(i = 0; i < this._blocks; ++i) {
    output.putInt32(this._outBlock[i]);
  }
};

(function() {
  var name = "AES",
      mode = modeRaw,
      factory;
  factory = function() { return new forge.aes.Algorithm(name, mode); };
  forge.cipher.registerAlgorithm(name, factory);
})();

// Prevent nextTick from being used when possible
if ("function" === typeof setImmediate) {
  forge.util.setImmediate = forge.util.nextTick = function(callback) {
    setImmediate(callback);
  };
}

module.exports = forge;
