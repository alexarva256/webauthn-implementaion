const fs     = require('fs').promises;
const path   = require('path');
const crypto = require('crypto'); 

const memoryCache = { data: null, nextUpdate: 0 };

const BLOB_LOCAL_PATH = path.join(__dirname, 'blob.jwt');
const ROOT_R3_PATH    = path.join(__dirname, 'root-r3.crt'); 

const FIDO_MDS_URL_LOCAL = 'https://mds.fidoalliance.org/'; 
//const FIDO_MDS_URL_LOCAL = 'http://localhost:8080/';

// ==========================================
//  X.509 VALIDATION FUNCTION
// ==========================================
function validateFidoMdsChain(x5cArray, rootDerBuffer) {
  if (!x5cArray || x5cArray.length === 0) throw new Error("x5c chain is empty.");

  const chain = x5cArray.map(certStr => {
      const derBuffer = Buffer.from(certStr, 'base64');
      return new crypto.X509Certificate(derBuffer);
  });

  const trustedRoot = new crypto.X509Certificate(rootDerBuffer);
  chain.push(trustedRoot);

  for (let i = 0; i < chain.length - 1; i++) {
      const currentCert = chain[i];
      const issuerCert = chain[i + 1];

      const now = Date.now();
      const validFrom = new Date(currentCert.validFrom).getTime();
      const validTo = new Date(currentCert.validTo).getTime();

      if (i > 0) {
          if (now < validFrom || now > validTo) {
              throw new Error(`Certificate expired or not yet valid: ${currentCert.subject}`);
          }
      }

      if (!currentCert.verify(issuerCert.publicKey)) {
          throw new Error(`Signature validation failed: ${currentCert.subject}`);
      }

      if (i > 0 && !currentCert.ca) {
          throw new Error(`Intermediate certificate is not a valid CA: ${currentCert.subject}`);
      }
  }

  if (chain[chain.length - 1].fingerprint256 !== trustedRoot.fingerprint256) {
      throw new Error("Chain does not terminate at the expected Root CA.");
  }

  return chain[0]; 
}

// ==========================================
//  FIDO MDS BLOB LOGIC
// ==========================================
async function validateBlobAuthenticity(rawBlob) {
    const parts = rawBlob.trim().split('.');
    if (parts.length !== 3) throw new Error("Invalid JWT BLOB format.");

    const headerBuffer = Buffer.from(parts[0], 'base64url');
    const header = JSON.parse(headerBuffer.toString('utf8'));

    if (!header.x5c || !Array.isArray(header.x5c) || header.x5c.length === 0) {
        throw new Error("MDS Blob header is missing the x5c certificate chain.");
    }

    let rootPem;
    try {
        rootPem = await fs.readFile(ROOT_R3_PATH);
    } catch (err) {
        throw new Error(`Could not read root-r3.crt. Details: ${err.message}`);
    }
    const trustedRoot = new crypto.X509Certificate(rootPem);

    console.log("Validating MDS Blob x5c chain against root-r3.crt...");
    
    const leafCert = validateFidoMdsChain(header.x5c, trustedRoot.raw);

    const dataToVerify = Buffer.from(`${parts[0]}.${parts[1]}`);
    const signature = Buffer.from(parts[2], 'base64url');
    
    const isValidSignature = crypto.verify(
        'RSA-SHA256', 
        dataToVerify,
        leafCert.publicKey,
        signature
    );
    
    if (!isValidSignature) {
        const altVerify = crypto.createVerify('SHA256').update(dataToVerify).verify(leafCert.publicKey, signature);
        if (!altVerify) throw new Error("MDS Blob JWT signature verification failed! File may be tampered with.");
    }
    
    console.log("MDS Blob cryptographic signature verified successfully!");
}

function decodeFidoBlob(rawBlob) {
  const parts = rawBlob.trim().split('.');
  const payloadBuffer = Buffer.from(parts[1], 'base64url');
  return JSON.parse(payloadBuffer.toString('utf8'));
}

function processMdsPayload(payload) {
  const map = {};
  if (payload.entries && Array.isArray(payload.entries)) {
    payload.entries.forEach(entry => {
      if (entry.aaguid) {
        map[entry.aaguid] = entry.metadataStatement;
      }
    });
  }
  return map;
}

async function refreshFidoMdsCache() {
  console.log("Fetching latest FIDO MDS Blob...");
  try {
    const response = await fetch(FIDO_MDS_URL_LOCAL); 
    if (!response.ok) throw new Error(`MDS responded with HTTP ${response.status}`);

    const rawBlob = await response.text(); 
    
    await validateBlobAuthenticity(rawBlob);

    const payload = decodeFidoBlob(rawBlob);
    
    memoryCache.data = processMdsPayload(payload);
    const memoryCache = JSON.stringify(memoryCache.data, null, 2);
    await fs.writeFile(path.join(__dirname, 'cache.json'), cache_data, 'utf8');
    memoryCache.nextUpdate = new Date(payload.nextUpdate).getTime(); 

    await fs.writeFile(BLOB_LOCAL_PATH, rawBlob, 'utf8');
    console.log(`MDS Cache updated. Next update due: ${payload.nextUpdate}`);
  } catch (error) {
      console.error("Fetch/Validation failed:", error.message); 
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
  //try {
  //  const rootCert = await fs.readFile(TRUSTED_ROOT_PATH, 'utf8');
  //  const trustedRoot = new crypto.X509Certificate(rootCert);
  //  const validfrom = new Date(trustedRoot.validFrom).getTime();
  //  const validto = new Date(trustedRoot.validTo).getTime();
  //  const now = Date.now();
  //  if (now < validfrom || now > validto) {
  //    throw new Error("Local trusted root certificate is expired or not yet valid. Need to fetch a new one.");
  //    
  //  }
  //  console.log("Loaded trusted root certificate from local disk.");
  //} catch (err) {
  //  console.log("No local trusted root certificate found another initialization run required.");
  //}


}

async function executeFidoSync() {
  console.log("Starting FIDO MDS Sync...");
  await tryLoadingFromDiskBackup();
  
  if (!memoryCache.data || Date.now() >= memoryCache.nextUpdate) {
    await refreshFidoMdsCache();
  } else {
    console.log("Local MDS blob is still fresh. No download required.");
  }
}

executeFidoSync()
    .then(() => {
        console.log("Sync complete. Exiting.");
        process.exit(0);
    })
    .catch(err => {
        console.error("Fatal Error during sync:", err);
        process.exit(1);
    });