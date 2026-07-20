const fs = require('fs').promises;
const config = require('./config');

const memoryCache = { data: null, nextUpdate: 0 };

async function saveToDisk(rawBlob, payloadMap, nextUpdate) {
  memoryCache.data = payloadMap;
  memoryCache.nextUpdate = new Date(nextUpdate).getTime();

  const cacheDataString = JSON.stringify(memoryCache.data, null, 2);
  await fs.writeFile(config.paths.cacheJson, cacheDataString, 'utf8');
  await fs.writeFile(config.paths.blob, rawBlob, 'utf8');
}

async function loadFromDisk() {
  try {
    const rawBlob = await fs.readFile(config.paths.blob, 'utf8');
    return rawBlob;
  } catch (err) {
    return null;
  }
}

module.exports = {
  memoryCache,
  saveToDisk,
  loadFromDisk
};