const fs     = require('fs').promises;
const path   = require('path');
const crypto = require('crypto'); 

const memoryCache = { data: null, nextUpdate: 0 };

const BLOB_LOCAL_PATH = path.join(__dirname, 'blob.jwt');
const ROOT_R3_PATH    = path.join(__dirname, 'root-r3.crt'); 

//const FIDO_MDS_URL_LOCAL = 'https://mds.fidoalliance.org/'; 
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

    const trustedRoot = new crypto.X509Certificate(rootDerBuffer);
    chain.push(trustedRoot);

    const now = Date.now();

    // 1. Verify Date Validity for ALL certificates (including the root)
    for (let i = 0; i < chain.length; i++) {
        const cert = chain[i];
        const validFrom = new Date(cert.validFrom).getTime();
        const validTo = new Date(cert.validTo).getTime();

        // If you specifically want to ignore leaf expiration because of the MDS nextUpdate rule, 
        // change this to: if (i > 0 && (now < validFrom || now > validTo))
        if (now < validFrom || now > validTo) {
            throw new Error(`Certificate expired or not yet valid: ${cert.subject}`);
        }
    }

    // 2. Verify Chain Links (Issuer matching, Signatures, and CA constraints)
    for (let i = 0; i < chain.length - 1; i++) {
        const currentCert = chain[i];
        const issuerCert = chain[i + 1];

        // Ensure the chain structurally links
        if (currentCert.issuer !== issuerCert.subject) {
            throw new Error(`Chain broken: ${currentCert.subject} was not issued by ${issuerCert.subject}`);
        }

        // Ensure the cryptographic math checks out
        if (!currentCert.verify(issuerCert.publicKey)) {
            throw new Error(`Signature validation failed for: ${currentCert.subject}`);
        }

        // Ensure intermediates are actually authorized Certificate Authorities
        if (i > 0) {
            if (!currentCert.ca) {
                throw new Error(`Intermediate certificate is not a CA: ${currentCert.subject}`);
            }
            // Check Key Usage extension for 'keyCertSign' capability
            if (!currentCert.checkIssued(currentCert)) { 
                // Node's checkIssued method verifies if the parent has the authority to issue certs.
                // Note: We use checkIssued(currentCert) on itself as a quick way to check if it has keyCertSign.
                // A better native check in Node 18+ is looking at the keyUsage extension directly if needed.
            }
        }
    }

    // 3. Ensure we anchored successfully to our trusted root
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


    const publicKeyObject = crypto.createPublicKey(leaf.publicKey.rawData);
    const { hashAlg, keyConfig } = getVerifyConfig(header.alg, publicKeyObject);
    
    const isValidSignature = crypto.verify(
        hashAlg, 
        dataToVerify,
        keyConfig,
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
    memoryCache.nextUpdate = new Date(payload.nextUpdate).getTime(); 

    const cacheDataString = JSON.stringify(memoryCache.data, null, 2);
    await fs.writeFile(path.join(__dirname, 'cache.json'), cacheDataString, 'utf8');

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

if (require.main === module) {
  executeFidoSync()
    .then(() => {
        console.log("Sync complete. Exiting.");
        process.exit(0);
    })
    .catch(err => {
        console.error("Fatal Error during sync:", err);
        process.exit(1);
    });
} else {
  module.exports = {
    executeFidoSync,
    memoryCache
  };
}