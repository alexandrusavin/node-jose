/*!
 * algorithms/ec-util.js - Elliptic Curve Utility Functions
 *
 * Copyright (c) 2015 Cisco Systems, Inc.  See LICENSE file.
 */
"use strict";

var clone = require("lodash.clone"),
    elliptic = require("elliptic"),
    forge = require("../deps/forge.js"),
    util = require("../util");

var CURVES = {
  "P-256": new elliptic.ec("p256"),
  "P-384": new elliptic.ec("p384"),
  "P-521": new elliptic.ec("p521")
};

function convertToElliptic(key, isPublic) {
  var retval;
  if (isPublic) {
    retval = {
      x: key.x.toString("hex"),
      y: key.y.toString("hex")
    };
    retval = CURVES[key.crv].keyFromPublic(retval);
    var check = (function() {
      var test = retval.getPublic();
      var x = test.x,
          y = test.y,
          a = test.curve.a,
          b = test.curve.b,
          p = test.curve.p;

      var x3 = x.redSqr().redMul(x),
          ax = x.redMul(a),
          y2 = y.redSqr();
      var lhs = y2;
      var rhs = x3.redAdd(ax).redAdd(b);
      return lhs.eq(rhs);
    })();
    if (!check) {
      throw new Error("invalid EC public key");
    }
  } else {
    retval = key.d.toString("hex");
    retval = CURVES[key.crv].keyFromPrivate(retval);
  }
  return retval;
}

function convertToJWK(key, isPublic) {
  var result = clone(key);
  var parts = isPublic ?
              ["x", "y"] :
              ["x", "y", "d"];
  parts.forEach(function(f) {
    result[f] = util.base64url.encode(result[f]);
  });

  // remove potentially troublesome properties
  delete result.key_ops;
  delete result.use;
  delete result.alg;

  if (isPublic) {
    delete result.d;
  }

  return result;
}

function convertToObj(key, isPublic) {
  var result = clone(key);
  var parts = isPublic ?
              ["x", "y"] :
              ["d"];
  parts.forEach(function(f) {
    // assume string if base64url-encoded
    result[f] = util.asBuffer(result[f], "base64url");
  });

  return result;
}

var UNCOMPRESSED = new Buffer([0x04]);
function convertToBuffer(key, isPublic) {
  key = convertToObj(key, isPublic);
  var result = isPublic ?
               Buffer.concat([UNCOMPRESSED, key.x, key.y]) :
               key.d;
  return result;
}

function curveSize(crv, bytes) {
  crv = CURVES[crv || ""];
  if (!crv) {
    return NaN;
  }
  return bytes ?
         crv.n.byteLength() :
         crv.n.bitLength();
}

module.exports = {
  convertToElliptic: convertToElliptic,
  convertToJWK: convertToJWK,
  convertToObj: convertToObj,
  convertToBuffer: convertToBuffer,
  curveSize: curveSize
};
