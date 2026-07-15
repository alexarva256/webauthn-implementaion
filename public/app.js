// app.js

// ==========================================
//  HELPER FUNCTIONS
// ==========================================

function formatAsPEM(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64 = window.btoa(binary);
    
    // Break the base64 string into lines of 64 characters
    const formattedB64 = base64.match(/.{1,64}/g).join('\n');
    
    return `-----BEGIN CERTIFICATE-----\n${formattedB64}\n-----END CERTIFICATE-----`;
}

function bufferToBase64url(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64URLStringToBuffer(base64URLString) {
    const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - (base64.length % 4)) % 4;
    const padded = base64.padEnd(base64.length + padLen, '=');
    const binary = atob(padded);
    const buffer = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        buffer[i] = binary.charCodeAt(i);
    }
    return buffer;
}

function generateRandomChallenge() {
    return window.crypto.getRandomValues(new Uint8Array(32));
}

function logToScreen(id, text, clear = false) {
    const output = document.getElementById(id);
    if (!output) return; 
    if (clear) output.innerText = "";
    output.innerText += text + "\n";
}

// ==========================================
//  INDEXED DB SETUP
// ==========================================
const dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open('WebAuthnLocalDB', 3);
    
    request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains('users')) {
            db.createObjectStore('users', { keyPath: 'username' });
        }
    };
    
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
});

async function dbSaveUser(userData) {
    const db = await dbPromise;
    return new Promise((resolve, reject) => {
        const transaction = db.transaction('users', 'readwrite');
        const store = transaction.objectStore('users');
        store.put(userData);
        transaction.oncomplete = resolve;
        transaction.onerror = reject;
    });
}

async function dbGetUser(username) {
    const db = await dbPromise;
    return new Promise((resolve, reject) => {
        const transaction = db.transaction('users', 'readonly');
        const store = transaction.objectStore('users');
        const request = store.get(username);
        request.onsuccess = () => resolve(request.result);
        request.onerror = reject;
    });
}

// ==========================================
//  REGISTRATION LOGIC
// ==========================================
document.getElementById('registerBtn').addEventListener('click', async () => {
    const username = document.getElementById('reg-username').value;
    if (!username) return alert("Enter a username to register.");

    logToScreen('reg-output', "Checking database for existing keys...", true);

    const existingUser = await dbGetUser(username);
    const excludeCredentials = [];

    if (existingUser && existingUser.credentialId) {
        excludeCredentials.push({
            type: "public-key",
            id: base64URLStringToBuffer(existingUser.credentialId)
        });
    }

    const encryptionSalt = generateRandomChallenge();

    const publicKey = {
        rp: { name: "Local DB Lab", id: window.location.hostname },
        user: {
            id: new TextEncoder().encode(username), 
            name: username,
            displayName: username,
        },
        challenge: generateRandomChallenge(),
        pubKeyCredParams: [
            { type: "public-key", alg: -7 },   
            { type: "public-key", alg: -257 }  
        ],
        excludeCredentials: excludeCredentials,
        authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
        timeout: 60000,
        attestation: "direct",
        extensions: { prf: { eval: {first: encryptionSalt} } }
    };

    try {
        logToScreen('reg-output', "Tap your YubiKey...");
        const credential = await navigator.credentials.create({ publicKey });
        
        const prfResults = credential.getClientExtensionResults();
        let symmetricKey; 

        if (prfResults.prf && prfResults.prf.results) {
            symmetricKey = prfResults.prf.results.first; 
        } else {
            throw new Error('PRF is not supported or was not enabled on this device.');
        }

        const newUserData = {
            username: username,
            credentialId: credential.id, 
            publicKey: bufferToBase64url(credential.response.getPublicKey()) 
        };

        await dbSaveUser(newUserData);

        // Extracting AAGUID
        const authDataBuffer = credential.response.getAuthenticatorData();
        const authData = new Uint8Array(authDataBuffer);
        const aaguidBytes = authData.slice(37, 53);
        const aaguidHex = Array.from(aaguidBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        const aaguid = `${aaguidHex.slice(0,8)}-${aaguidHex.slice(8,12)}-${aaguidHex.slice(12,16)}-${aaguidHex.slice(16,20)}-${aaguidHex.slice(20)}`;
            
        logToScreen('reg-output', "\nAuthenticator AAGUID: " + aaguid);

        logToScreen('reg-output', "Sending AAGUID to backend...");
        
        try {
            const apiResponse = await fetch('http://localhost:4000/api/lookup-aaguid', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ aaguid: aaguid })
            });

            if (!apiResponse.ok) {
                const errorData = await apiResponse.text();
                throw new Error(`Backend refused (HTTP ${apiResponse.status}): ${errorData}`);
            }

            const resultData = await apiResponse.json();
            logToScreen('reg-output', "Device Model: " + resultData.description);

        } catch (apiErr) {
            console.error("Full Error Details:", apiErr);
            logToScreen('reg-output', `Lookup failed: ${apiErr.message}`);
        }
        
        logToScreen('reg-output', "\nSaved to IndexedDB!");
        logToScreen('reg-output', "Deriving AES-GCM Vault Key..."); 

        const masterKey = await crypto.subtle.importKey(
            'raw', symmetricKey, 'HKDF', false, ['deriveKey']
        );

        const attObj = CBOR.decode(credential.response.attestationObject);
        console.log("Full Attestation Object:", attObj);

    
        if (attObj.attStmt && attObj.attStmt.x5c) {
            logToScreen('reg-output', "\nExtracting X.509 chain...");

            // 1. Convert the ArrayBuffers to standard Base64 strings
            // Note: X.509 uses standard Base64, not URL-safe Base64!
            const x5cBase64Strings = attObj.attStmt.x5c.map(certBuffer => {
                let binary = '';
                const bytes = new Uint8Array(certBuffer);
                for (let i = 0; i < bytes.byteLength; i++) {
                    binary += String.fromCharCode(bytes[i]);
                }
                return window.btoa(binary); // Standard browser base64 encoder
            });
        
            logToScreen('reg-output', "Sending chain to backend for secure validation...");
        
            // 2. Send the extracted strings to your Node.js backend
            const verifyResponse = await fetch('http://localhost:4000/api/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: username,
                    credentialId: credential.id,
                    x5c: x5cBase64Strings,
                    aaguid: aaguid 
                })
            });
        
            if (!verifyResponse.ok) {
                const errorText = await verifyResponse.text();
                throw new Error(`Backend validation failed: ${errorText}`);
            }
        
            const result = await verifyResponse.json();
            logToScreen('reg-output', `\n✅ ${result.message}`);
        } else {
            logToScreen('reg-output', "\nNo certificate chain (x5c) found in this attestation statement.");
        }


                // -----------------------------------------------------

                const aesKey = await crypto.subtle.deriveKey(
                    { name: 'HKDF', salt: new Uint8Array(), hash: 'SHA-256', info: new TextEncoder().encode('AES-GCM Vault Encryption Key V1') },
                    masterKey,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['encrypt', 'decrypt']
                );

                console.log("Success! Your AES Key Object:", aesKey);
                logToScreen('reg-output', "Registration Complete!");

            } catch (err) {
                logToScreen('reg-output', "\n Error: " + err.message);
            }
        });

// ==========================================
//  AUTHENTICATION LOGIC
// ==========================================
document.getElementById('loginBtn').addEventListener('click', async () => {
    const logId = 'login-output';
    logToScreen(logId, "Setting up challenge...", true);

    const encryptionSalt = generateRandomChallenge(); 

    try {
        const publicKeyRequest = {
            challenge: generateRandomChallenge(),
            timeout: 60000,
            rpId: window.location.hostname,
            userVerification: "preferred",
            extensions: { prf: { eval: { first: encryptionSalt } } }
        };

        logToScreen(logId, "Tap your YubiKey...");
        const assertion = await navigator.credentials.get({ publicKey: publicKeyRequest });

        const userHandle = assertion.response.userHandle;
        if (!userHandle) throw new Error("No user handle found.");
        
        const identifiedUsername = new TextDecoder().decode(userHandle);
        logToScreen(logId, `Key identifies as: "${identifiedUsername}"`);

        const dbUser = await dbGetUser(identifiedUsername);
        const credID = assertion.id;
        
        if (!dbUser) {
            logToScreen(logId, `User "${identifiedUsername}" not found in DB. Signaling browser...`);
            if (window.PublicKeyCredential && PublicKeyCredential.signalUnknownCredential) {
                try {
                    await PublicKeyCredential.signalUnknownCredential({ rpId: window.location.hostname, credentialId: credID });
                } catch (signalErr) { console.error("Signal API failed:", signalErr); }
            }
            throw new Error(`SECURITY ALERT: User "${identifiedUsername}" DELETED. Access Denied.`);
        }

        const extensionResults = assertion.getClientExtensionResults();
        const prfResults = extensionResults?.prf?.results?.first;
        if (!prfResults) throw new Error("PRF not supported/enabled.");

        logToScreen(logId, "Deriving AES-GCM Vault Key...");

        const masterKey = await crypto.subtle.importKey(
            'raw', prfResults, 'HKDF', false, ['deriveKey']
        );

        const aesKey = await crypto.subtle.deriveKey(
            { name: 'HKDF', salt: new Uint8Array(), hash: 'SHA-256', info: new TextEncoder().encode('AES-GCM Vault Encryption Key V1') },
            masterKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );

        logToScreen(logId, "\n LOGIN SUCCESSFUL!");
        logToScreen(logId, "Welcome back, " + identifiedUsername);
        
    } catch (err) {
        logToScreen(logId, "\n " + err.message);
    }
});