var tls = require('tls');
var fs = require('fs');

var options = {
  key: fs.readFileSync(__dirname + '/key.pem'),
  cert: fs.readFileSync(__dirname + '/cert.pem')
};

var server = tls.createServer(options, function(c) {
  c.once('data', function() {
    c.destroy();
    server.close();
  });
}).listen(1443, function() {
  var addr = this.address();
  console.log('Listening on %j', addr);

  var client = tls.connect({
    port: addr.port,
    host: addr.address,
    rejectUnauthorized: false
  }, function() {
    console.log(client.getPeerCertificate());
    client.write('ok');
  });
});
