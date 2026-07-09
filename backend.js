const http = require('http');

let memoryCache = { 
    data: null, 
    serialNumber: null,
    nextFetchDue: 0 
};

const FIDO_MDS_URL = 'https://c-mds.fidoalliance.org/';
const TWO_WEEKS_MS = 14 * 24 * 60 * 60 * 1000;

function decodeFidoBlob(rawBlob) {
    const parts = rawBlob.trim().split('.');
    if (parts.length !== 3) throw new Error("Invalid BLOB format.");
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
}

async function refreshFidoMdsCache() {
    const fetchOptions = { method: 'GET', headers: {} };
    if (memoryCache.serialNumber) fetchOptions.headers['If-None-Match'] = memoryCache.serialNumber;
    
    try {
        console.log("Fetching FIDO metadata...");
        const response = await fetch(FIDO_MDS_URL, fetchOptions);
        
        if (response.status === 304) {
            console.log("FIDO metadata up to date (304). Updating next fetch time.");
            
            memoryCache.nextFetchDue = Date.now() + TWO_WEEKS_MS;
            return;
        }
        
        if (!response.ok) throw new Error(`MDS responded with HTTP ${response.status}`);
        
        const rawBlob = await response.text();
        const etag = response.headers.get('ETag');
        const parsedJwt = decodeFidoBlob(rawBlob);

        memoryCache.data = parsedJwt.entries; 
        memoryCache.serialNumber = etag ? etag.replace(/"/g, '') : null;
        memoryCache.nextFetchDue = Date.now() + TWO_WEEKS_MS;
        
        console.log("Successfully loaded FIDO metadata into RAM.");
    } catch (error) {
        console.error("Failed to fetch FIDO metadata:", error.message);
    }
}

async function initializeFidoBackendStore() {
    await refreshFidoMdsCache();
}

initializeFidoBackendStore();

setInterval(async () => {
    if (Date.now() >= memoryCache.nextFetchDue) {
        console.log("Scheduled metadata refresh triggered...");
        await refreshFidoMdsCache();
    }
}, 24 * 60 * 60 * 1000);


//HTTP SERVER
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
                    res.writeHead(503, { 'Content-Type': 'application/json' });
                    return res.end(JSON.stringify({ error: 'FIDO Store initializing or unavailable. Please try again.' }));
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