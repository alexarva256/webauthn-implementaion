const fs = require('fs').promises;
const path = require('path');

const parseJwt = (token) => {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString('utf8'));
  } catch (e) {
    return null;
  }
};

(async () => {
  try {
    const rawBlob = await fs.readFile(path.join(__dirname, 'blob.jwt'), 'utf8');
    const decoded = parseJwt(rawBlob);
    await fs.writeFile(
      path.join(__dirname, 'readable.json'),
      JSON.stringify(decoded, null, 2)
    );
  } catch (err) {
    console.error(err);
  }
})();