require('reflect-metadata');

const express = require('express');
const cors = require('cors');
const { executeFidoSync } = require('./fido-mds/sync');
const registerRoute = require('./routes/register');

const app = express();

app.use(cors());
app.use(express.json());

app.use('/api', registerRoute);

async function startServer() {
  try {
    console.log("Initializing FIDO MDS Cache...");

    await executeFidoSync();
    
    const PORT = 4000;
    app.listen(PORT, () => {
      console.log(`\n🚀 Server is running on http://localhost:${PORT}`);
      console.log(`Waiting for WebAuthn registrations...\n`);
    });

  } catch (error) {
    console.error("Failed to start server. MDS sync critically failed:", error);
    process.exit(1);
  }
}

startServer();