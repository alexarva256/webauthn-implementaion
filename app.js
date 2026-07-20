/**
 * UTILITIES & FORMATTING
*/
const Utils = {
	bufferToBase64url(buffer) {
		return btoa(String.fromCharCode(...new Uint8Array(buffer)))
			.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
	},

	base64URLStringToBuffer(base64URLString) {
		const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
		const padLen = (4 - (base64.length % 4)) % 4;
		const padded = base64.padEnd(base64.length + padLen, '=');
		const binary = atob(padded);
		return Uint8Array.from(binary, c => c.charCodeAt(0)).buffer;
	},

	generateChallenge() {
		return window.crypto.getRandomValues(new Uint8Array(32));
	},

	log(id, text, clear = false) {
		const output = document.getElementById(id);
		if (!output) return;
		if (clear) output.innerText = "";
		output.innerText += text + "\n";
	}
};

/**
*  STORAGE (INDEXED DB)
*/
const Database = {
	async getDB() {
		return new Promise((resolve, reject) => {
			const request = indexedDB.open('WebAuthnLocalDB', 3);
			request.onupgradeneeded = (e) => {
				const db = e.target.result;
				if (!db.objectStoreNames.contains('users')) {
					db.createObjectStore('users', { keyPath: 'username' });
				}
			};
			request.onsuccess = () => resolve(request.result);
			request.onerror = () => reject(request.error);
		});
	},

	async saveUser(userData) {
		const db = await this.getDB();
		return new Promise((resolve, reject) => {
			const transaction = db.transaction('users', 'readwrite');
			transaction.objectStore('users').put(userData);
			transaction.oncomplete = resolve;
			transaction.onerror = reject;
		});
	},

	async getUser(username) {
		const db = await this.getDB();
		return new Promise((resolve, reject) => {
			const transaction = db.transaction('users', 'readonly');
			const request = transaction.objectStore('users').get(username);
			request.onsuccess = () => resolve(request.result);
			request.onerror = reject;
		});
	}
};

/**
*  CRYPTOGRAPHY
*/

const CryptoManager = {
	/**
	 * Derives an AES-GCM encryption key from the WebAuthn PRF output.
	 * @param {ArrayBuffer} prfOutput - The symmetric key material from the authenticator.
	 */
	async deriveVaultKey(prfOutput) {
		if (!prfOutput) throw new Error("PRF is not supported or was not enabled on this device.");

		const masterKey = await crypto.subtle.importKey(
			'raw', prfOutput, 'HKDF', false, ['deriveKey']
		);

		const aesKey = await crypto.subtle.deriveKey(
			{
				name: 'HKDF',
				salt: new Uint8Array(),
				hash: 'SHA-256',
				info: new TextEncoder().encode('AES-GCM Vault Encryption Key V1')
			},
			masterKey,
			{ name: 'AES-GCM', length: 256 },
			false,
			['encrypt', 'decrypt']
		);

		return aesKey;
	}
};

/**
*  BACKEND API CALLS
*/

const BackendAPI = {
	/**
	 * Sends the authenticator payload to the server for MDS verification.
	 */

	async verifyRegistration(payload) {
		const response = await fetch('http://localhost:4000/api/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(payload)
		});

		if (!response.ok) {
			const errorText = await response.text();
			throw new Error(`Backend validation failed: ${errorText}`);
		}
		return await response.json();
	}
};

/**
*  WEBAUTHN ORCHESTRATION
*/

async function handleRegistration(username) {
	const logId = 'reg-output';
	//Utils.log(logId, "Checking database for existing keys...", true);

	const existingUser = await Database.getUser(username);
	//const excludeCredentials = existingUser?.credentialId
	//    ? [{ type: "public-key", id: Utils.base64URLStringToBuffer(existingUser.credentialId) }]
	//    : [];
	//
	const encryptionSalt = Utils.generateChallenge();

	const publicKey = {
		rp: { name: "Local DB Lab", id: window.location.hostname },
		user: {
			id: new TextEncoder().encode(username),
			name: username,
			displayName: username,
		},
		challenge: Utils.generateChallenge(),
		pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
		//excludeCredentials,
		authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
		timeout: 60000,
		attestation: "direct",
		extensions: { prf: { eval: { first: encryptionSalt } } }
	};

	Utils.log(logId, "Tap your YubiKey...");
	const credential = await navigator.credentials.create({ publicKey });

await Database.saveUser({
        username: username,
        credentialId: credential.id,
        publicKey: Utils.bufferToBase64url(credential.response.getPublicKey())
    });
    Utils.log(logId, "\nSaved to IndexedDB!");

    Utils.log(logId, "Sending raw attestation data to backend for secure decoding and validation...");
    
    const backendResponse = await BackendAPI.verifyRegistration({
        username,
        credentialId: credential.id,
        clientDataJSON: Utils.bufferToBase64url(credential.response.clientDataJSON),
        attestationObject: Utils.bufferToBase64url(credential.response.attestationObject)
    });
    
    Utils.log(logId, `Backend: ${backendResponse.message}`);

	Utils.log(logId, "Deriving AES-GCM Vault Key from PRF...");
	const prfResults = credential.getClientExtensionResults()?.prf?.results?.first;
	const aesKey = await CryptoManager.deriveVaultKey(prfResults);

	console.log("Success! Your AES Key Object:", aesKey);
	Utils.log(logId, "Registration Complete!");
}

async function handleLogin() {
	const logId = 'login-output';
	Utils.log(logId, "Setting up challenge...", true);

	const encryptionSalt = Utils.generateChallenge();

	const publicKeyRequest = {
		challenge: Utils.generateChallenge(),
		timeout: 60000,
		rpId: window.location.hostname,
		userVerification: "preferred",
		extensions: { prf: { eval: { first: encryptionSalt } } }
	};

	Utils.log(logId, "Tap your YubiKey...");
	const assertion = await navigator.credentials.get({ publicKey: publicKeyRequest });

	const userHandle = assertion.response.userHandle;
	if (!userHandle) throw new Error("No user handle found on this credential.");
	const identifiedUsername = new TextDecoder().decode(userHandle);
	Utils.log(logId, `Key identifies as: "${identifiedUsername}"`);

	//const dbUser = await Database.getUser(identifiedUsername);
	//if (!dbUser) {
	//	if (window.PublicKeyCredential?.signalUnknownCredential) {
	//		await PublicKeyCredential.signalUnknownCredential({ rpId: window.location.hostname, credentialId: assertion.id })
	//			.catch(err => console.error("Signal API failed:", err));
	//	}
	//	throw new Error(`SECURITY ALERT: User "${identifiedUsername}" not found. Access Denied.`);
	//}

	Utils.log(logId, "Deriving AES-GCM Vault Key...");
	const prfResults = assertion.getClientExtensionResults()?.prf?.results?.first;
	const aesKey = await CryptoManager.deriveVaultKey(prfResults);

	console.log("Recovered AES Key Object:", aesKey);
	Utils.log(logId, "\nLOGIN SUCCESSFUL!");
	Utils.log(logId, `Welcome back, ${identifiedUsername}`);
}

/**
 *  UI EVENT LISTENERS
*/

document.getElementById('registerBtn').addEventListener('click', async () => {
	const username = document.getElementById('reg-username').value.trim();
	if (!username) return alert("Enter a username to register.");

	try {
		await handleRegistration(username);
	} catch (err) {
		Utils.log('reg-output', `\nError: ${err.message}`);
		console.error(err);
	}
});

document.getElementById('loginBtn').addEventListener('click', async () => {
	try {
		await handleLogin();
	} catch (err) {
		Utils.log('login-output', `\nError: ${err.message}`);
		console.error(err);
	}
});