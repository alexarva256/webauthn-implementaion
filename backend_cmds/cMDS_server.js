const http = require('http');
const fs   = require('fs').promises;
const path = require('path'); 

const PORT = 8080;
const MDS_DATA = path.join(__dirname, 'convenience-metadata.json');

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, If-None-Match');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS, POST');

  try {
    const rawData = await fs.readFile(MDS_DATA, 'utf8');
    
    const parsedData = JSON.parse(rawData);
    const currentSequenceNumber = `"${parsedData.no}"`;
    
    if (req.headers['if-none-match'] === currentSequenceNumber) {
      res.writeHead(304);
      return res.end();
    }

    res.setHeader('ETag', currentSequenceNumber);
    res.setHeader('Cache-Control', 'public, max-age=1209600'); 
    
    res.writeHead(200, {
      'Content-Type': 'application/json' 
    });
    
    res.end(rawData);
      
  } catch (err) {
    res.writeHead(404, {'Content-Type': 'text/plain'});
    res.end('File not found');
  }
});

server.listen(PORT, 'localhost', () => {
  console.log(`Mock MDS Server running at http://localhost:${PORT}/`);
});