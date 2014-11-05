var asn1 = require('asn1.js');

var utils = exports;

exports.SHA1 = [ 1, 3, 14, 3, 2, 26 ];
exports.SHA1RSA = [ 1, 2, 840, 113549, 1, 1, 5 ];
exports.RSA = [ 1, 2, 840, 113549, 1, 1, 1 ];
exports.CN = [ 2, 5, 4, 3 ];
exports.DC = [ 0, 9, 2342, 19200300, 100, 1, 25 ];
exports.ALTNAME = [ 2, 5, 29, 17 ];

var GeneralName = asn1.define('GeneralName', function() {
  this.choice({
    dNSName: this.implicit(2).ia5str()
  });
});
exports.GeneralName = GeneralName;

exports.GeneralNames = asn1.define('GeneralNames', function() {
  this.seqof(GeneralName);
});

var RSAPrivateKey = asn1.define('RSAPrivateKey', function() {
  this.seq().obj(
    this.key('version').int(),
    this.key('modulus').int(),
    this.key('publicExponent').int(),
    this.key('privateExponent').int(),
    this.key('prime1').int(),
    this.key('prime2').int(),
    this.key('exponent1').int(),
    this.key('exponent2').int(),
    this.key('coefficient').int()
  );
});
exports.RSAPrivateKey = RSAPrivateKey;

var RSAPublicKey = asn1.define('RSAPublicKey', function() {
  this.seq().obj(
    this.key('modulus').int(),
    this.key('publicExponent').int()
  );
});
exports.RSAPublicKey = RSAPublicKey;

var IA5Str = asn1.define('IA5Str', function() {
  this.ia5str();
});

function genCertData(cn, altname, pubkey) {
  return {
    version: 'v3',
    serialNumber: 10001,
    signature: {
      algorithm: utils.SHA1RSA
    },
    issuer: {
      type: 'rdn',
      value: [
        [ { type: utils.CN, value: IA5Str.encode('oh.my.gosh', 'der') } ]
      ]
    },
    validity: {
      notBefore: {
        type: 'utcTime',
        value: new Date()
      },
      notAfter: {
        type: 'utcTime',
        value: new Date(+new Date + 10 * 365 * 24 * 3600 * 1000)
      }
    },
    subject: {
      type: 'rdn',
      value: [
        [ { type: utils.CN, value: IA5Str.encode(cn, 'der') } ]
      ]
    },
    subjectPublicKeyInfo: {
      algorithm: {
        algorithm: utils.RSA
      },
      subjectPublicKey: {
        unused: 0,
        data: pubkey
      }
    },
    issuerUniqueID: { unused: 0, data: '123456' },
    subjectUniqueID: { unused: 0, data: '789abc' },
    extensions: [
      {
        extnID: utils.ALTNAME,
        critical: false,
        extnValue: utils.GeneralNames.encode([
          {
            type: 'dNSName',
            value: altname
          }
        ], 'der')
      }
    ]
  };
}
exports.genCertData = genCertData;
