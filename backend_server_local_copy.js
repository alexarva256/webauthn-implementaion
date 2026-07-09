const http = require('http');

const fs = require('fs').promises;

const path = require('path');

let memoryCache = { data: null, serialNumber: null };


const BLOB_LOCAL_PATH = path.join(__dirname, 'fido-blob-cache.txt');

const CONFIG_LOCAL_PATH = path.join(__dirname, 'cache-config.json');

const FIDO_MDS_URL = 'https://c-mds.fidoalliance.org/';

const TWO_WEEKS_MS = 14 * 24 * 60 * 60 * 1000;


// (Helper decoding/fetching functions remain exactly as before...)

function decodeFidoBlob(rawBlob) {

const parts = rawBlob.trim().split('.');

if (parts.length !== 3) throw new Error("Invalid BLOB format.");

return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));

}


async function refreshFidoMdsCache() {

const fetchOptions = { method: 'GET', headers: {} };

if (memoryCache.serialNumber) fetchOptions.headers['If-None-Match'] = memoryCache.serialNumber;

try {

const response = await fetch(FIDO_MDS_URL, fetchOptions);

if (response.status === 304) return;

if (!response.ok) throw new Error(`MDS responded with HTTP ${response.status}`);

const rawBlob = await response.text();

const etag = response.headers.get('ETag');

const parsedJwt = decodeFidoBlob(rawBlob);


memoryCache.data = parsedJwt.entries;

memoryCache.serialNumber = etag ? etag.replace(/"/g, '') : null;


await fs.writeFile(BLOB_LOCAL_PATH, rawBlob, 'utf8');

await fs.writeFile(CONFIG_LOCAL_PATH, JSON.stringify({

serialNumber: memoryCache.serialNumber, nextFetchDue: Date.now() + TWO_WEEKS_MS

}), 'utf8');

} catch (error) {

if (!memoryCache.data) await tryLoadingFromDiskBackup();

}

}


async function tryLoadingFromDiskBackup() {

try {

const rawBlob = await fs.readFile(BLOB_LOCAL_PATH, 'utf8');

const rawConfig = await fs.readFile(CONFIG_LOCAL_PATH, 'utf8');

memoryCache.data = decodeFidoBlob(rawBlob).entries;

memoryCache.serialNumber = JSON.parse(rawConfig).serialNumber;

} catch (err) { console.log("First initialization run required."); }

}


async function initializeFidoBackendStore() {

let nextFetchDue = 0;

try { nextFetchDue = JSON.parse(await fs.readFile(CONFIG_LOCAL_PATH, 'utf8')).nextFetchDue || 0; } catch (e) {}

await tryLoadingFromDiskBackup();

if (Date.now() >= nextFetchDue || !memoryCache.data) {

await refreshFidoMdsCache();

}

}


// Initialize the FIDO Memory store on server boot

initializeFidoBackendStore();


// 2. HTTP SERVER TO SERVE THE FRONTEND LOGIC

const server = http.createServer(async (req, res) => {

// Enable CORS so your frontend can communicate safely with it

res.setHeader('Access-Control-Allow-Origin', '*');

res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, POST'); // Explicitly allow these methods


// THE FIX: Intercept the CORS preflight OPTIONS request and say "OK!"

if (req.method === 'OPTIONS') {

res.writeHead(200);

return res.end();

}


// Endpoint for matching the AAGUID

if (req.method === 'POST' && req.url === '/api/lookup-aaguid') {

let body = '';

req.on('data', chunk => { body += chunk; });

req.on('end', () => {

try {

const { aaguid } = JSON.parse(body);

// High speed memory lookup straight from Node's RAM!

if (!memoryCache.data) {

res.writeHead(500, { 'Content-Type': 'application/json' });

return res.end(JSON.stringify({ error: 'Store uninitialized' }));

}


const matchedDevice = memoryCache.data.find(entry => entry.aaguid === aaguid);

const description = matchedDevice?.metadataStatement?.description || "Unknown Authenticator";


res.writeHead(200, { 'Content-Type': 'application/json' });

res.end(JSON.stringify({ description }));

} catch (err) {

res.writeHead(400, { 'Content-Type': 'text/plain' });

res.end('Bad Request');

}

});

} else {

res.writeHead(404);

res.end();

}

});


server.listen(4000, () => console.log('Backend listening on http://localhost:4000')); 