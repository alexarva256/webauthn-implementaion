// 1. Our cache state now tracks the serial number (ETag) instead of time
let memoryCache = {
    data: null,
    serialNumber: null 
};

// The FIDO MDS endpoint
const FIDO_MDS_URL = 'https://mds.fidoalliance.org/'; 

/**
 * Fetches the FIDO Metadata BLOB, using Conditional GETs to check for updates.
 */
async function getFidoMetadata() {
    
    // 2. Prepare our request headers
    const fetchOptions = {
        method: 'GET',
        headers: {}
    };

    // If we already have a serial number cached, add it to the 'If-None-Match' header
    if (memoryCache.serialNumber) {
        fetchOptions.headers['If-None-Match'] = memoryCache.serialNumber;
        console.log(`Checking FIDO for updates. My version: ${memoryCache.serialNumber}`);
    } else {
        console.log("No cache found. Fetching initial FIDO BLOB...");
    }

    try {
        // 3. Make the request
        const response = await fetch(FIDO_MDS_URL, fetchOptions);

        // 4. Handle the 304 Not Modified (Cache Hit)
        if (response.status === 304) {
            console.log("Server returned 304 Not Modified. Cache is up to date!");
            return memoryCache.data;
        }

        // 5. Handle standard errors
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        // 6. Handle the 200 OK (Cache Miss / New Data Available)
        console.log("New data received! Updating cache...");
        
        // FIDO MDS blobs are usually raw text (a signed JWT string), not plain JSON
        const rawBlob = await response.text(); 
        
        // Extract the new serial number from the ETag header
        // Note: fetch API headers.get() is case-insensitive
        const newSerialNumber = response.headers.get('ETag'); 

        // 7. Save to memory
        memoryCache.data = rawBlob;
        
        // Sometimes APIs wrap ETags in quotes (e.g., "77"). We clean them up just in case.
        if (newSerialNumber) {
            memoryCache.serialNumber = newSerialNumber.replace(/"/g, ''); 
        }

        return memoryCache.data;

    } catch (error) {
        console.error("Failed to reach FIDO MDS:", error);
        
        // Fallback: If FIDO is down, serve what we have in memory
        if (memoryCache.data) {
            console.log("Serving stale FIDO data as a fallback.");
            return memoryCache.data;
        } else {
            throw new Error("FIDO MDS is unreachable and no local cache exists.");
        }
    }
}