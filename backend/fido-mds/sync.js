const fs = require('fs').promises;
const config = require('./config');
const cache = require('./cache');
const mds = require('./mds');

async function triggerStaleMdsAlert(daysStale) {
  const msg = `CRITICAL: FIDO MDS Blob is ${daysStale} days past its update deadline.`;
  console.error(msg);
  await fs.appendFile(config.paths.errorLog, `[${new Date().toISOString()}] ${msg}\n`, 'utf8');
}

async function fetchAndProcessBlob() {
  console.log("Fetching FIDO MDS Blob...");
  const response = await fetch(config.urls.fidoMds);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);

  const rawBlob = await response.text();
  await mds.validateBlobAuthenticity(rawBlob);
  
  const { payloadMap, nextUpdate } = mds.parseAndFormatBlob(rawBlob);
  await cache.saveToDisk(rawBlob, payloadMap, nextUpdate);
  console.log(`MDS Cache updated. Next update: ${nextUpdate}`);
}

async function executeFidoSync() {
  console.log("Starting Sync...");

  if (!cache.memoryCache.data) {
    const localBlob = await cache.loadFromDisk();
    if (localBlob) {
      const { payloadMap, nextUpdate } = mds.parseAndFormatBlob(localBlob);
      cache.memoryCache.data = payloadMap;
      cache.memoryCache.nextUpdate = new Date(nextUpdate).getTime();
      console.log("Loaded from local disk.");
    }
  }

  const now = Date.now();
  if (!cache.memoryCache.data || now >= cache.memoryCache.nextUpdate) {
    try {
      await fetchAndProcessBlob();
    } catch (error) {
      console.error("Fetch/Validation failed:", error.message);
    }
  } else {
    console.log("Local MDS blob is still fresh.");
  }

  if (cache.memoryCache.nextUpdate) {
    const staleTime = now - cache.memoryCache.nextUpdate;
    if (staleTime > config.thresholds.staleMs) {
      const daysStale = (staleTime / (1000 * 60 * 60 * 24)).toFixed(1);
      await triggerStaleMdsAlert(daysStale);
    }
  } else {
    await triggerStaleMdsAlert("unknown (cache empty)");
  }
}

if (require.main === module) {
  executeFidoSync()
    .then(() => process.exit(0))
    .catch(err => {
      console.error("Fatal:", err);
      process.exit(1);
    });
}

module.exports = { executeFidoSync };