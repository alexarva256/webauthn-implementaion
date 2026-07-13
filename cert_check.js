const crypto = require('crypto');

/**
 * Helper to wrap raw Base64 in standard PEM formatting
 */
function formatAsPEM(base64String) {
    // Remove any existing whitespace/newlines just in case
    const cleanBase64 = base64String.replace(/\s+/g, '');
    // Chunk into 64-character lines
    const lines = cleanBase64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

// 1. The Root Certificate (From FIDO MDS or your paste)
const rawRootBase64 = "MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC..."; // (paste the rest of your string here)

// 2. The Leaf Certificate (From the YubiKey's x5c[0] array)
// In your real app, this comes from the CBOR decoded `attStmt.x5c[0]` buffer sent from the frontend.
// For this script, convert that buffer to base64 on the frontend and paste it here to test.
const rawLeafBase64 = "MIICqTCCAZGgAwIBAgIJANHfO139O7yUMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNV
BAMMC2F0dGVzdCB0ZXN0MB4XDTI0MDQxNjEzMzkyMFoXDTI1MDQxNjEzMzkyMFow
bzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0
aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBT
ZXJpYWwgMTU2NDIwNTAwOTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABH/cldCj
LmUlqHq/b9J/3UmjzlVbeFlt+QrQEHlQeKmtmD7ZHkhn9fxKHaTL1GX7d1JY+sT3
m3HkJxIMdYELvOSjbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIu
MS4yMBMGCysGAQQBguUcAgEBBAQDAgQwMCEGCysGAQQBguUcAQEEBBIEEPigEfOM
Ck0VgAYXER+e3H0wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAaYuC
KXLfv6d0fxlgqWvVkudeMKzZeT/08MLPO7jkJyBHKv5mEAr/UMNjVyrhmgIDurup
aTsGN9VBkw5sNa1BAgCPoYF8Uh+u+BBODmYOC7NcbqDr+WBHolJ2TX2ule70fszS
9X1wj06fv0VhJqNdNYBfzSnUFy79b/wEcsjYFCLKmnx/am8By7sE4z3q7HCxwV67
mKuRxRzLWDPvhW3DRyD80jqN4b2PEE3ua1Ih3h7x7E6/4EqpwUbdiNkZ0uYBbYkf
DtYosddoTV6IyFZu3bRFopgi5CmYY5yuGeC16+mlMTaT7oK+EVSUFGdZ+NeCB2Ex
8PkI5L1P5TKkYh9oLA=="

try {
    // Format both to PEM
    const rootPem = formatAsPEM(rawRootBase64);
    const leafPem = formatAsPEM(rawLeafBase64);

    // Parse them using Node's native X509 class
    const rootCert = new crypto.X509Certificate(rootPem);
    const leafCert = new crypto.X509Certificate(leafPem);

    console.log(`Checking Leaf issued by: ${leafCert.issuer}`);
    console.log(`Against Root Subject: ${rootCert.subject}`);

    // THE CRITICAL MATH: 
    // Did the Root Certificate's public key sign this Leaf Certificate?
    const isGenuine = leafCert.verify(rootCert.publicKey);

    if (isGenuine) {
        console.log("\n✅ SUCCESS: Chain of Trust verified!");
        console.log("This is a mathematically proven, genuine YubiKey.");
    } else {
        console.log("\n❌ FAILED: Signature mismatch.");
        console.log("This device was NOT manufactured by the owner of the Root CA.");
    }

} catch (err) {
    console.error("\n⚠️ Certificate Parsing Error:");
    console.error(err.message);
}