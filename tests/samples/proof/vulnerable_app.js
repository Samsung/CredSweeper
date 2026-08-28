// ===== DEMO / TEST DATA (Should be filtered) =====

// Docker demo passwords - should NOT be flagged
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: 'whalehello'  // <- Should be filtered by ValueDemoPlaceholderCheck
};

const grafanaConfig = {
  adminPassword: 'grafana'  // <- Should be filtered by ValueDemoPlaceholderCheck
};

// FTP convention - should NOT be flagged
const ftpConfig = {
  username: 'anonymous',  // <- Should be filtered by ValueProtocolPlaceholderCheck
  password: 'anonymous'   // <- Should be filtered by ValueProtocolPlaceholderCheck
};

// Test fixture - should NOT be flagged
const testPassword = 'P4ssw0rd'; // NOT OK  // <- Should be filtered by ValueTestFixtureCheck

// UUIDs - should NOT be flagged
const appId = 'D77B7E06-80BA-4137-BCF4-654B95CCEBC5';  // <- Should be filtered by UUID detection

// ===== REAL SECRETS (Should be flagged) =====

// AWS credentials - should be flagged
const awsConfig = {
  accessKeyId: 'AKIAQXJ7ZR4K3M9P2LNT',  // <- Should be detected
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEZZZ'  // <- Should be detected
};

// Database credentials - should be flagged
const dbConfig2 = {
  password: 'Xk9$mPq2vR8nL4wZ'  // <- Should be detected
};

// API Keys - should be flagged
const apiKeys = {
  sendgrid: 'SG.a1B2c3D4e5F6g7H8i9J0.kL1mN2oP3qR4sT5uV6wX7yZ8aB9cD0eF1gH2iJ3kL',  // <- Should be detected
  stripe: 'sk_live_51Hg7YqLkJ3nR8mQwErT6yUiOpAsD9fGhJkL2zXcVbN',  // <- Should be detected
  twilio: '9f8e7d6c5b4a39281706f5e4d3c2b1a0'  // <- Should be detected (THIS WAS BROKEN!)
};
