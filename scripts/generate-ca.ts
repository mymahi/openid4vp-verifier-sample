#!/usr/bin/env node

/**
 * Generate Certificate Authority (CA) for OpenID4VP Verifier
 * 
 * This script generates a CA certificate and private key that will be used
 * to sign verifier certificates. Run this once to set up the CA.
 * 
 * The CA certificate and key will be saved to the certs/ directory and
 * can be committed to the repository for development/testing purposes.
 * 
 * This CA needs to be pregistered with the wallet applications to trust
 * certificates issued by it. If you regenerate the CA, you won't be able to
 * test against the testing version of the MyMahi Wallet unless you contact
 * the developers to update the wallet with the new CA certificate.
 * 
 * WARNING: In production, the CA should be managed securely and never
 * committed to version control.
 * 
 * Usage: node scripts/generate-ca.js
 *        or: npm run generate-ca
 */

import * as x509 from '@peculiar/x509';
import { Crypto } from '@peculiar/webcrypto';
import * as fs from 'fs';
import * as path from 'path';

// Initialize the crypto provider
const webcrypto = new Crypto();
x509.cryptoProvider.set(webcrypto);

// Certificate paths
const CERTS_DIR = path.join(process.cwd(), 'certs');
const CA_CERT_PATH = path.join(CERTS_DIR, 'ca.crt');
const CA_KEY_PATH = path.join(CERTS_DIR, 'ca.key');

/**
 * Ensure the certs directory exists
 */
function ensureCertsDirectory() {
    if (!fs.existsSync(CERTS_DIR)) {
        fs.mkdirSync(CERTS_DIR, { recursive: true });
        console.log(`✓ Created certificates directory: ${CERTS_DIR}`);
    }
}

/**
 * Save a key to disk in JWK format
 */
async function saveKeyToFile(key: CryptoKey, filePath: string) {
    const jwk = await webcrypto.subtle.exportKey('jwk', key);
    fs.writeFileSync(filePath, JSON.stringify(jwk, null, 2), 'utf-8');
}

/**
 * Generate Certificate Authority
 */
async function generateCA() {
    ensureCertsDirectory();

    // Check if CA already exists
    if (fs.existsSync(CA_CERT_PATH) && fs.existsSync(CA_KEY_PATH)) {
        console.log('\n⚠️  Certificate Authority already exists!');
        console.log(`   CA Certificate: ${CA_CERT_PATH}`);
        console.log(`   CA Private Key: ${CA_KEY_PATH}`);
        console.log('\n   To regenerate the CA, delete these files first.');
        console.log('   WARNING: Regenerating will invalidate all issued certificates!\n');
        process.exit(1);
    }

    console.log('\n🔐 Generating Certificate Authority (CA)...\n');

    // Generate Ed25519 key pair for CA
    console.log('   → Generating Ed25519 key pair...');
    const keys = await webcrypto.subtle.generateKey(
        {
            name: 'Ed25519',
        },
        true,
        ['sign', 'verify']
    );

    // Create CA certificate with proper CA extensions
    console.log('   → Creating CA certificate...');
    const caCert = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: '01',
        name: 'CN=OpenID4VP Sample CA,O=MyMahi,C=NZ',
        notBefore: new Date(),
        notAfter: new Date(Date.now() + 10 * 365 * 24 * 60 * 60 * 1000), // 10 years validity
        signingAlgorithm: { name: 'Ed25519' },
        keys,
        extensions: [
            new x509.KeyUsagesExtension(
                x509.KeyUsageFlags.keyCertSign | 
                x509.KeyUsageFlags.cRLSign | 
                x509.KeyUsageFlags.digitalSignature,
                true // critical
            ),
            new x509.BasicConstraintsExtension(true, 2, true), // CA=true, pathlen=2, critical=true
            await x509.SubjectKeyIdentifierExtension.create(keys.publicKey, false),
        ],
    });

    // Save CA certificate and private key
    console.log('   → Saving CA certificate and private key...');
    fs.writeFileSync(CA_CERT_PATH, caCert.toString('pem'), 'utf-8');
    await saveKeyToFile(keys.privateKey, CA_KEY_PATH);

    console.log('\n✓ Certificate Authority generated successfully!\n');
    console.log('   CA Certificate: ' + CA_CERT_PATH);
    console.log('   CA Private Key: ' + CA_KEY_PATH);
    console.log('\n   Certificate Details:');
    console.log(`   - Subject: ${caCert.subject}`);
    console.log(`   - Valid From: ${caCert.notBefore.toISOString()}`);
    console.log(`   - Valid Until: ${caCert.notAfter.toISOString()}`);
    console.log(`   - Algorithm: Ed25519`);
    console.log(`   - Serial Number: ${caCert.serialNumber}`);
    console.log('\n📝 Note: For development/testing, these files can be committed to git.');
    console.log('   For production, manage the CA securely and never commit to version control.\n');
}

// Run the script
generateCA().catch((error) => {
    console.error('\n❌ Error generating CA:', error.message);
    process.exit(1);
});
