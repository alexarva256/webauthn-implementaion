const express = require('express');
const router = express.Router();
const cbor = require('cbor'); // <-- Add this
const cache = require('../fido-mds/cache');
const { validateAuthenticatorTrust } = require('../utils/fido-trust');

router.post('/register', async (req, res) => {
  try {
    const { username, attestationObject } = req.body;

    console.log(`\n--- Incoming Registration for: ${username} ---`);

    const attObjBuffer = Buffer.from(attestationObject, 'base64url');
    const decodedAttObj = cbor.decodeFirstSync(attObjBuffer);

    const authData = decodedAttObj.authData;
    const aaguidBytes = authData.slice(37, 53);
    const aaguidHex = aaguidBytes.toString('hex');
    
    const aaguid = `${aaguidHex.slice(0,8)}-${aaguidHex.slice(8,12)}-${aaguidHex.slice(12,16)}-${aaguidHex.slice(16,20)}-${aaguidHex.slice(20,32)}`;
    
    console.log(`Extracted AAGUID: ${aaguid}`);

    let x5c = [];
    if (decodedAttObj.attStmt && decodedAttObj.attStmt.x5c) {
        x5c = decodedAttObj.attStmt.x5c.map(certBuffer => certBuffer.toString('base64'));
    }

    const mdsData = cache.memoryCache.data;
    if (!mdsData) {
      return res.status(503).json({ error: "FIDO MDS cache is temporarily unavailable." });
    }

    const metadataStatement = mdsData[aaguid];
    if (!metadataStatement) {
      return res.status(403).json({ error: "Unrecognized Authenticator (AAGUID not found in MDS)." });
    }

    console.log(`Device Identified: ${metadataStatement.description}`);

    if (x5c.length > 0) {
      const isTrusted = await validateAuthenticatorTrust(metadataStatement, x5c);
      
      if (!isTrusted) {
        return res.status(403).json({ error: "Authenticator failed FIDO trust verification." });
      }
      console.log("X.509 Trust Chain Validated Successfully!");
    } else {
      console.log("No x5c chain provided (Self-Attested). Skipping MDS trust check.");
    }

    res.json({ 
      success: true, 
      message: `Successfully validated ${metadataStatement.description} against FIDO MDS!` 
    });

  } catch (error) {
    console.error("Registration endpoint error:", error);
    res.status(500).json({ error: error.message || "Internal server error" });
  }
});

module.exports = router;