const crypto = require('crypto');

/**
 * Format raw Base64 in standard PEM formatting
 */
function formatAsPEM(base64String) {
    
    const cleanBase64 = base64String.replace(/\s+/g, '');
    
    const lines = cleanBase64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

// The Root Certificate from FIDO Alliance MDS
const rawRootBase64 = "MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC"; 

// The Leaf Certificate (CBOR decoded attStmt.x5c[0])
const rawLeafBase64 = string("MIICWjCCAcKgAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKjEoMCYGA1UEAxMfWXViaWNvIFUyRiBDZXJ0aWZpY2F0ZSBTZXJpYWwgNDU3MjAwNjMxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs");

try {
    const rootPem = formatAsPEM(rawRootBase64);
    const leafPem = formatAsPEM(rawLeafBase64);

    const rootCert = new crypto.X509Certificate(rootPem);
    const leafCert = new crypto.X509Certificate(leafPem);

    console.log(`Checking Leaf issued by: ${leafCert.issuer}`);
    console.log(`Against Root Subject: ${rootCert.subject}`);

    const isGenuine = leafCert.verify(rootCert.publicKey);

    if (isGenuine) {
        console.log("\n SUCCESS: Chain of Trust verified!");
        console.log("This is a mathematically proven, genuine YubiKey.");
    } else {
        console.log("\n FAILED: Signature mismatch.");
        console.log("This device was NOT manufactured by the owner of the Root CA.");
    }

} catch (err) {
    console.error("\n Certificate Parsing Error:");
    console.error(err.message);
}