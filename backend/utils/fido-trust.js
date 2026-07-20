const { X509Certificate, X509ChainBuilder, cryptoProvider } = require('@peculiar/x509');
const { webcrypto } = require('crypto');

cryptoProvider.set(webcrypto);

/**
 * Validates a WebAuthn attestation chain against the FIDO MDS.
 * 
 * @param {Object} mdsEntry 
 * @param {string[]} attestationX5c 
 * @returns {Promise<boolean>} 
 */
async function validateAuthenticatorTrust(mdsEntry, attestationX5c) {
  if (!mdsEntry) {
    console.warn("AAGUID not found in MDS cache.");
    return false; 
  }

  if (mdsEntry.statusReports && mdsEntry.statusReports.length > 0) {
    const latestStatus = mdsEntry.statusReports[0].status;
    const dangerousStatuses = ['REVOKED', 'USER_VERIFICATION_BYPASS', 'ATTESTATION_KEY_COMPROMISE'];
    
    if (dangerousStatuses.includes(latestStatus)) {
      throw new Error(`Authenticator rejected. FIDO Status: ${latestStatus}`);
    }
  }

  if (!mdsEntry.attestationRootCertificates || mdsEntry.attestationRootCertificates.length === 0) {
    throw new Error("MDS entry is missing trusted root certificates.");
  }
  const trustedRoots = mdsEntry.attestationRootCertificates.map(certStr => new X509Certificate(certStr));

  if (!attestationX5c || attestationX5c.length === 0) {
    throw new Error("Attestation statement is missing the x5c chain.");
  }
  const leafCert = new X509Certificate(attestationX5c[0]);
  const intermediates = attestationX5c.slice(1).map(certStr => new X509Certificate(certStr));

  const chainBuilder = new X509ChainBuilder({
    certificates: [...trustedRoots, ...intermediates]
  });

  try {
    const builtChain = await chainBuilder.build(leafCert);
    
    const builtRootThumbprint = builtChain[builtChain.length - 1].thumbprint;
    const isTrustedAnchor = trustedRoots.some(root => root.thumbprint === builtRootThumbprint);

    if (!isTrustedAnchor) {
      throw new Error("Attestation chain does not anchor to a trusted FIDO root.");
    }

    return true;
  } catch (error) {
    console.error("Attestation trust chain validation failed:", error.message);
    return false;
  }
}

module.exports = { validateAuthenticatorTrust };