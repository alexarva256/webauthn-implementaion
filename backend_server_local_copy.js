const http = require('http');
const fs   = require('fs').promises;
const path = require('path');

let memoryCache = { data: null, serialNumber: null };

const DATA_LOCAL_PATH   = path.join(__dirname, 'fido-metatadata-local.json');
const CONFIG_LOCAL_PATH = path.join(__dirname, 'fido-metadata-config.json');

//we will use the following but for testing we will use the local server!
//const FIDO_MDS_URL = 'https://c-mds.fidoalliance.org/';
const FIDO_MDS_URL      = 'http://localhost:8080/';
const TWO_WEEKS_MS      = 14 * 24 * 60 * 60 * 1000;

//the convenience MDS metadata are currently sent in .json format so no need to decode the jwt blob.
//function decodeFidoBlob(rawBlob) {
//  const parts = rawBlob.trim().split('.');
//  if (parts.length !== 3) throw new Error("Invalid BLOB format.");
//  return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
//}

async function refreshFidoMdsCache() {
  const fetchOptions = { method: 'GET', headers: {} };
  if (memoryCache.serialNumber) {
    fetchOptions.headers['If-None-Match'] = memoryCache.serialNumber;
  }

  try {
    const response = await fetch(FIDO_MDS_URL, fetchOptions);
    if (response.status === 304) return;
    if (!response.ok) throw new Error(`MDS responded with HTTP ${response.status}`);

    const data = await response.json();
    const etag = response.headers.get('ETag');
    //no need to decode the jwt blob since we are using the convenience MDS metadata in .json format.
    //const parsedJwt = decodeFidoBlob(rawBlob);
    //memoryCache.data = parsedJwt.entries;
    memoryCache.data = data;
    memoryCache.serialNumber = etag ? etag.replace(/"/g, '') : null;

    await fs.writeFile(DATA_LOCAL_PATH, JSON.stringify(data), 'utf8');
    await fs.writeFile(CONFIG_LOCAL_PATH, JSON.stringify({
      serialNumber: memoryCache.serialNumber,
      nextFetchDue: Date.now() + TWO_WEEKS_MS
    }), 'utf8');
  }catch (error) {
    	console.error("Fetch failed with error:", error); 
	
    	if (!memoryCache.data) await tryLoadingFromDiskBackup();
  }
}

async function tryLoadingFromDiskBackup() {
  try {
    //we will use the following but for now we only have a .json file so no need to decode the jwt blob.
    //const rawBlob = await fs.readFile(BLOB_LOCAL_PATH, 'utf8');
    //const rawConfig = await fs.readFile(CONFIG_LOCAL_PATH, 'utf8');
    //memoryCache.data = decodeFidoBlob(rawBlob).entries;
    //memoryCache.serialNumber = JSON.parse(rawConfig).serialNumber;

    const data = await fs.readFile(DATA_LOCAL_PATH, 'utf8');
    const config = await fs.readFile(CONFIG_LOCAL_PATH, 'utf8');
    memoryCache.data = JSON.parse(data);
    memoryCache.serialNumber = JSON.parse(config).serialNumber;

  } catch (err) {
    console.log("First initialization run required.");

  }
}

async function initializeFidoBackendStore() {
  let nextFetchDue = 0;
  try {
    nextFetchDue = JSON.parse(await fs.readFile(CONFIG_LOCAL_PATH, 'utf8')).nextFetchDue || 0;
  } catch (e) {}

  await tryLoadingFromDiskBackup();
  if (Date.now() >= nextFetchDue || !memoryCache.data) {
    await refreshFidoMdsCache();
  }
}

initializeFidoBackendStore();

const server = http.createServer(async (req, res) => {

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, POST');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    return res.end();
  }

  if (req.method === 'POST' && req.url === '/api/lookup-aaguid') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const { aaguid } = JSON.parse(body);

        if (!memoryCache.data) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Store uninitialized' }));
        }

        const matchedDevice = memoryCache.data[aaguid];
        const description = matchedDevice?.friendlyNames?.['en-US'] || "Unknown Authenticator";

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