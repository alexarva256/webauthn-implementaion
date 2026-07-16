const http = require('http');
const fs   = require('fs').promises;
const path = require('path'); 

const PORT = 8080;
const MDS_DATA = path.join(__dirname, 'blob.jwt');

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, If-None-Match');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS, POST');

  // Ignore favicon requests to prevent double-execution
  if (req.url === '/favicon.ico') {
    res.writeHead(204);
    return res.end();
  }

  try {
    const rawData = await fs.readFile(MDS_DATA, 'utf8');
    
    // 1. Split the JWT into its 3 parts (Header, Payload, Signature)
    const parts = rawData.trim().split('.');
    if (parts.length !== 3) {
        throw new Error("blob.jwt is not a valid 3-part JWT string.");
    }

    // 2. Decode the Payload (the middle part)
    const payloadBuffer = Buffer.from(parts[1], 'base64url');
    const parsedData = JSON.parse(payloadBuffer.toString('utf8'));
    
    // 3. Extract the sequence number
    const currentSequenceNumber = `"${parsedData.no}"`;
    
    if (req.headers['if-none-match'] === currentSequenceNumber) {
      res.writeHead(304);
      return res.end();
    }

    res.setHeader('ETag', currentSequenceNumber);
    res.setHeader('Cache-Control', 'public, max-age=1209600'); 
    
    // Note: If the client expects a raw JWT string, 'application/jwt' or 'text/plain' 
    // might be more accurate than 'application/json', but keeping your original header here.
    res.writeHead(200, {
      'Content-Type': 'application/json' 
    });
    
    // Serve the raw JWT string to the client
    res.end(rawData);
      
  } catch (err) {
    // Log the actual error to your terminal so you know exactly why it failed!
    console.error("Server Error:", err.message); 
    
    res.writeHead(404, {'Content-Type': 'text/plain'});
    res.end('File not found or internal server error');
  }
});

server.listen(PORT, 'localhost', () => {
  console.log(`Mock MDS Server running at http://localhost:${PORT}/`);
});