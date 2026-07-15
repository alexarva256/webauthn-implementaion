const http   = require('http');
const fs     = require('fs').promises;
const path   = require('path');
const crypto = require('crypto'); 

// Cache will hold the mapped AAGUIDs and the next required update time
let memoryCache = { data: null, nextUpdate: 0 };

const BLOB_LOCAL_PATH = path.join(__dirname, 'blob.jwt');
//const FIDO_MDS_URL = 'https://mds.fidoalliance.org/'; 
const FIDO_MDS_URL_LOCAL = 'http://localhost:8080/';


// ==========================================
//  X.509 VALIDATION FUNCTION
// ==========================================
function validateFidoMdsChain(x5cArray, rootDerBuffer) {
  if (!x5cArray || x5cArray.length === 0) throw new Error("x5c chain is empty.");

  const chain = x5cArray.map(certStr => {
      const derBuffer = Buffer.from(certStr, 'base64');
      return new crypto.X509Certificate(derBuffer);
  });

  // Load the authenticator's specific Root CA from the MDS cache
  const trustedRoot = new crypto.X509Certificate(rootDerBuffer);
  chain.push(trustedRoot);

  for (let i = 0; i < chain.length - 1; i++) {
      const currentCert = chain[i];
      const issuerCert = chain[i + 1];

      const now = Date.now();
      const validFrom = new Date(currentCert.validFrom).getTime();
      const validTo = new Date(currentCert.validTo).getTime();

      // WebAuthn Quirk: Ignore expiration dates on the hardware's leaf certificate (i === 0)
      if (i > 0) {
          if (now < validFrom || now > validTo) {
              throw new Error(`Certificate expired or not yet valid: ${currentCert.subject}`);
          }
      }

      if (!currentCert.verify(issuerCert.publicKey)) {
          throw new Error(`Signature validation failed: ${currentCert.subject}`);
      }

      // If it's an intermediate, ensure it's a CA
      if (i > 0 && !currentCert.ca) {
          throw new Error(`Intermediate certificate is not a valid CA: ${currentCert.subject}`);
      }
  }

  if (chain[chain.length - 1].fingerprint256 !== trustedRoot.fingerprint256) {
      throw new Error("Chain does not terminate at the expected Authenticator Root CA.");
  }

  return chain[0]; 
}

// ==========================================
//  FIDO MDS BLOB LOGIC
// ==========================================
function decodeFidoBlob(rawBlob) {
  const parts = rawBlob.trim().split('.');
  if (parts.length !== 3) throw new Error("Invalid JWT BLOB format.");
  const payloadBuffer = Buffer.from(parts[1], 'base64url');
  return JSON.parse(payloadBuffer.toString('utf8'));
}

function processMdsPayload(payload) {
  const map = {};
  if (payload.entries && Array.isArray(payload.entries)) {
    payload.entries.forEach(entry => {
      if (entry.aaguid) {
        // Map the AAGUID directly to its full metadata statement
        map[entry.aaguid] = entry.metadataStatement;
      }
    });
  }
  return map;
}

async function refreshFidoMdsCache() {
  console.log("Fetching latest FIDO MDS Blob...");
  try {
    //const response = await fetch(FIDO_MDS_URL); // Use the real FIDO MDS URL in production
    const response = await fetch(FIDO_MDS_URL_LOCAL); // Use the local mock server for testing
    if (!response.ok) throw new Error(`MDS responded with HTTP ${response.status}`);

    const rawBlob = await response.text(); 
    const payload = decodeFidoBlob(rawBlob);
    
    memoryCache.data = processMdsPayload(payload);
    memoryCache.nextUpdate = new Date(payload.nextUpdate).getTime(); 

    await fs.writeFile(BLOB_LOCAL_PATH, rawBlob, 'utf8');
    console.log(`MDS Cache updated. Next update due: ${payload.nextUpdate}`);
  } catch (error) {
      console.error("Fetch failed:", error.message); 
      if (!memoryCache.data) await tryLoadingFromDiskBackup();
  }
}

async function tryLoadingFromDiskBackup() {
  try {
    const rawBlob = await fs.readFile(BLOB_LOCAL_PATH, 'utf8');
    const payload = decodeFidoBlob(rawBlob);
    
    memoryCache.data = processMdsPayload(payload);
    memoryCache.nextUpdate = new Date(payload.nextUpdate).getTime();
    console.log("Loaded MDS blob from local disk.");
  } catch (err) {
    console.log("No local blob.jwt found. First initialization run required.");
  }
}

async function initializeFidoBackendStore() {
  await tryLoadingFromDiskBackup();
  if (!memoryCache.data || Date.now() >= memoryCache.nextUpdate) {
    await refreshFidoMdsCache();
  }
}

initializeFidoBackendStore();

// ==========================================
//  SERVER ROUTING
// ==========================================
const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, POST');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    return res.end();
  }

  if (req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    
    req.on('end', () => {
      let parsedBody;
      try {
        parsedBody = JSON.parse(body);
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        return res.end('Invalid JSON payload');
      }

      // --- ROUTE: AAGUID LOOKUP ---
      if (req.url === '/api/lookup-aaguid') {
        const { aaguid } = parsedBody;

        if (!memoryCache.data) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Store uninitialized' }));
        }

        const matchedDevice = memoryCache.data[aaguid];
        const description = matchedDevice?.description || "Unknown Authenticator";

        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ description }));
      }
      
      // --- ROUTE: REGISTRATION VALIDATION ---
      else if (req.url === '/api/register') {
        const { username, credentialId, x5c, aaguid } = parsedBody;

        if (!x5c || !Array.isArray(x5c) || x5c.length === 0) {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            return res.end("Missing x5c certificate chain.");
        }

        if (!aaguid) {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            return res.end("Missing aaguid in payload.");
        }

        // 1. Look up the device in the MDS Cache
        const deviceMetadata = memoryCache.data[aaguid];
        if (!deviceMetadata) {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            return res.end(`Unknown AAGUID (${aaguid}). Device not found in FIDO registry.`);
        }

        // 2. Extract the device's specific Root CA from the metadata
        const rootCerts = deviceMetadata.attestationRootCertificates;
        if (!rootCerts || rootCerts.length === 0) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            return res.end("MDS missing Root CA for this device.");
        }

        try {
            // 3. FIDO MDS stores roots as Base64 strings. Convert to binary buffer.
            const authenticatorRootDer = Buffer.from(rootCerts[0], 'base64');

            // 4. Validate the browser's chain against the device's true Root CA!
            const leafCert = validateFidoMdsChain(x5c, authenticatorRootDer);
            console.log(`[Success] Validated attestation chain for: ${leafCert.subject}`);
            console.log(`[Device Name] ${deviceMetadata.description}`);
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ message: "Registration & Cryptographic Validation successful!" }));
        } catch (error) {
            console.error("[Security] Certificate Validation Error:", error.message);
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            return res.end(`Security Check Failed: ${error.message}`);
        }
      } 
      else {
        res.writeHead(404);
        return res.end();
      }
    });
  } else {
    res.writeHead(404);
    res.end();
  }
});

server.listen(4000, () => console.log('Backend listening on http://localhost:4000'));