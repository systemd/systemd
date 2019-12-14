var http = require('http');
var fs = require('fs');
http.createServer(function (req, res) {
  fs.readFile('img.gif', function(err, data) {
    res.writeHead(200, {'Content-Type': 'image/gif'});
    res.write(data);
    res.end();
  });
}).listen(8080); 
