import * as x509 from '@peculiar/x509';
import { SignJWT, jwtDecrypt, importJWK, exportJWK } from 'jose';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import {
    LogotypeExtn,
    LogotypeInfo,
    LogotypeData,
    LogotypeDetails,
    LogotypeImage,
    HashAlgAndValue,
} from '@peculiar/asn1-x509-logotype';
import { AlgorithmIdentifier } from '@peculiar/asn1-x509';

// Directory for storing CA and certificates
const CERTS_DIR = path.join(process.cwd(), 'certs');
const CA_CERT_PATH = path.join(CERTS_DIR, 'ca.crt');
const CA_KEY_PATH = path.join(CERTS_DIR, 'ca.key');
const VERIFIER_CERT_PATH = path.join(CERTS_DIR, 'verifier.crt');
const VERIFIER_KEY_PATH = path.join(CERTS_DIR, 'verifier.key');
const LOGO_PATH = path.join(CERTS_DIR, 'logo.png');

/**
 * Ensure the certs directory exists
 */
function ensureCertsDirectory() {
    if (!fs.existsSync(CERTS_DIR)) {
        fs.mkdirSync(CERTS_DIR, { recursive: true });
        console.log(`Created certificates directory: ${CERTS_DIR}`);
    }
}

/**
 * Save a key to disk in JWK format
 */
async function saveKeyToFile(key: CryptoKey, filePath: string) {
    const jwk = await crypto.subtle.exportKey('jwk', key);
    fs.writeFileSync(filePath, JSON.stringify(jwk, null, 2), 'utf-8');
}

/**
 * Load a key from disk (JWK format)
 */
async function loadKeyFromFile(filePath: string, algorithm: any, usages: KeyUsage[]): Promise<CryptoKey> {
    const jwkData = fs.readFileSync(filePath, 'utf-8');
    const jwk = JSON.parse(jwkData);
    return await crypto.subtle.importKey('jwk', jwk, algorithm, true, usages);
}

/**
 * Load existing CA certificate and keys from disk
 * CA must be generated first using: npm run generate-ca
 */
export async function loadCA() {
    if (!fs.existsSync(CA_CERT_PATH) || !fs.existsSync(CA_KEY_PATH)) {
        throw new Error('Certificate Authority not found! Please generate it first using: npm run generate-ca');
    }

    console.log('Loading Certificate Authority (CA)...');

    const certPem = fs.readFileSync(CA_CERT_PATH, 'utf-8');
    const caCert = new x509.X509Certificate(certPem);

    const caPrivateKey = await loadKeyFromFile(CA_KEY_PATH, { name: 'Ed25519' }, ['sign']);

    // Derive public key from certificate
    const caPublicKey = await caCert.publicKey.export();

    console.log('✓ CA loaded successfully');

    return {
        certificate: caCert,
        privateKey: caPrivateKey,
        publicKey: caPublicKey,
    };
}

/**
 * Create a Logotype extension for including a logo in the certificate
 */
function createLogotypeExtension(logoPath: string): x509.Extension {
    // Read the logo file
    const logoData = fs.readFileSync(logoPath);

    // Calculate SHA-256 hash of the logo
    const logoHash = crypto.createHash('sha256').update(logoData).digest();

    // Create the logotype structure according to RFC 3709
    const logotype = new LogotypeExtn({
        subjectLogo: new LogotypeInfo({
            direct: new LogotypeData({
                image: [
                    new LogotypeImage({
                        imageDetails: new LogotypeDetails({
                            mediaType: 'image/png',
                            logotypeHash: [
                                new HashAlgAndValue({
                                    hashAlg: new AlgorithmIdentifier({
                                        algorithm: '2.16.840.1.101.3.4.2.1', // SHA-256 OID
                                    }),
                                    hashValue: new OctetString(logoHash),
                                }),
                            ],
                            logotypeURI: ['data:image/png;base64,' + logoData.toString('base64')],
                        }),
                    }),
                ],
            }),
        }),
    });

    // Convert to ASN.1 and create extension
    const logotypeAsn = AsnConvert.serialize(logotype);

    return new x509.Extension(
        '1.3.6.1.5.5.7.1.12', // id-pe-logotype OID
        false, // not critical
        new Uint8Array(logotypeAsn)
    );
}

/**
 * Generate a verifier certificate signed by the CA
 * In production, this should be replaced with proper certificate management
 * Note: HAIP Section 7 requires ES256 as minimum, but also supports Ed25519
 */
export async function generateVerifierCertificate(caCert: x509.X509Certificate, caPrivateKey: CryptoKey) {
    ensureCertsDirectory();

    console.log('Generating verifier certificate signed by CA...');

    // Generate Ed25519 key pair for verifier
    const keys = (await crypto.subtle.generateKey(
        {
            name: 'Ed25519',
        },
        true,
        ['sign', 'verify']
    )) as CryptoKeyPair;

    // Generate a unique serial number
    const serialNumber = crypto.randomBytes(16).toString('hex');

    // Create verifier certificate signed by CA
    const cert = await x509.X509CertificateGenerator.create({
        serialNumber,
        subject: 'CN=OpenID4VP Sample Verifier,O=MyMahi,C=NZ',
        issuer: caCert.subject,
        notBefore: new Date(),
        notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year validity
        signingAlgorithm: { name: 'Ed25519' },
        publicKey: keys.publicKey,
        signingKey: caPrivateKey,
        extensions: [
            new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment),
            new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.clientAuth, x509.ExtendedKeyUsage.serverAuth]),
            await x509.SubjectKeyIdentifierExtension.create(keys.publicKey, false),
            await x509.AuthorityKeyIdentifierExtension.create(caCert, false),
            // Add logotype extension if logo file exists
            ...(fs.existsSync(LOGO_PATH) ? [createLogotypeExtension(LOGO_PATH)] : []),
        ],
    });

    // Save verifier certificate and private key
    fs.writeFileSync(VERIFIER_CERT_PATH, cert.toString('pem'), 'utf-8');
    await saveKeyToFile(keys.privateKey, VERIFIER_KEY_PATH);

    console.log(`Verifier certificate saved to: ${VERIFIER_CERT_PATH}`);
    console.log(`Verifier private key saved to: ${VERIFIER_KEY_PATH}`);

    return {
        certificate: cert,
        privateKey: keys.privateKey,
        publicKey: keys.publicKey,
    };
}

/**
 * Calculate x509_hash for HAIP client identifier
 * HAIP Section 5: Client Identifier Prefix x509_hash
 */
export function calculateX509Hash(certificate: x509.X509Certificate): string {
    const certDer = certificate.rawData;
    const hash = crypto.createHash('sha256').update(Buffer.from(certDer)).digest();
    const base64url = hash.toString('base64url');
    return `x509_hash:${base64url}`;
}

/**
 * Convert X.509 certificate to PEM format
 */
export function certificateToPem(certificate: x509.X509Certificate): string {
    return certificate.toString('pem');
}

/**
 * Get certificate chain as array of base64-encoded DER certificates for x5c header
 * HAIP: Trust anchor (root CA) must NOT be included in x5c
 * Since our CA is the root/trust anchor, only include the verifier certificate
 * In a production environment with intermediate CAs, include intermediates but not the root
 */
export function getCertificateChain(certificate: x509.X509Certificate, caCertificate?: x509.X509Certificate): string[] {
    const certDer = certificate.rawData;
    const base64Cert = Buffer.from(certDer).toString('base64');

    // Only include the end-entity certificate (verifier cert)
    // Do NOT include the CA certificate as it is the root/trust anchor
    const chain = [base64Cert];

    return chain;
}

/**
 * Sign a JWT using X.509 certificate (JAR - JWT-Secured Authorization Request)
 * HAIP Section 5.1: Signed Authorization Requests MUST be used
 * Using Ed25519 algorithm (EdDSA with Ed25519 curve for JOSE)
 */
export async function signJwtWithCertificate(
    payload: Record<string, any>,
    privateKey: CryptoKey,
    certificate: x509.X509Certificate,
    caCertificate?: x509.X509Certificate
): Promise<string> {
    // Export the private key to JWK format for jose
    const jwk = await crypto.subtle.exportKey('jwk', privateKey);

    // Import to jose format with Ed25519 algorithm
    const key = await importJWK(jwk, 'Ed25519');

    // Get x5c certificate chain (excluding trust anchor, but including CA)
    const x5c = getCertificateChain(certificate, caCertificate);

    // Sign JWT with x5c header using Ed25519
    const jwt = await new SignJWT(payload)
        .setProtectedHeader({
            alg: 'Ed25519',
            typ: 'oauth-authz-req+jwt',
            x5c: x5c,
        })
        .setIssuedAt()
        .sign(key);

    return jwt;
}

/**
 * Generate ephemeral ECDH-ES P-256 key pair for response encryption
 * HAIP Section 5: Ephemeral encryption public keys specific to each Authorization Request
 */
export async function generateEphemeralEncryptionKey() {
    // Generate ECDH P-256 key pair
    const keyPair = await crypto.subtle.generateKey(
        {
            name: 'ECDH',
            namedCurve: 'P-256',
        },
        true,
        ['deriveKey', 'deriveBits']
    );

    // Export public key to JWK for client_metadata
    const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

    // Add kid (key ID) to the JWK - use thumbprint of the public key
    const thumbprint = crypto.createHash('sha256').update(JSON.stringify(publicKeyJwk)).digest('base64url');

    return {
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        publicKeyJwk: {
            ...publicKeyJwk,
            kid: thumbprint,
            use: 'enc',
            alg: 'ECDH-ES',
        },
    };
}

/**
 * Decrypt JWE response
 * HAIP Section 5: Response encryption with ECDH-ES + A256GCM
 */
export async function decryptResponse(jwe: string, privateKey: CryptoKey): Promise<any> {
    // Decrypt JWE
    const { payload } = await jwtDecrypt(jwe, privateKey);

    return payload;
}

/**
 * Load or create CA and verifier certificate, cache them
 * In production, load from secure storage
 */
let cachedCA: {
    certificate: x509.X509Certificate;
    privateKey: CryptoKey;
    publicKey: CryptoKey;
} | null = null;

let cachedVerifierCert: {
    certificate: x509.X509Certificate;
    privateKey: CryptoKey;
    publicKey: CryptoKey;
} | null = null;

/**
 * Get Certificate Authority (must already exist)
 * CA must be generated first using: npm run generate-ca
 */
export async function getCA() {
    if (!cachedCA) {
        // Load existing CA (will throw error if not found)
        cachedCA = await loadCA();
    }
    return cachedCA;
}

/**
 * Get verifier certificate signed by CA
 * Generates the certificate if it doesn't exist (should happen at server startup)
 */
export async function getVerifierCertificate() {
    if (!cachedVerifierCert) {
        // Ensure we have a CA first
        const ca = await getCA();

        // Try to load existing verifier certificate
        if (fs.existsSync(VERIFIER_CERT_PATH) && fs.existsSync(VERIFIER_KEY_PATH)) {
            console.log('Loading existing verifier certificate...');
            const certPem = fs.readFileSync(VERIFIER_CERT_PATH, 'utf-8');
            const cert = new x509.X509Certificate(certPem);

            const privateKey = await loadKeyFromFile(VERIFIER_KEY_PATH, { name: 'Ed25519' }, ['sign']);

            const publicKey = await cert.publicKey.export();

            cachedVerifierCert = {
                certificate: cert,
                privateKey,
                publicKey,
            };
            console.log('✓ Verifier certificate loaded successfully');
        } else {
            // Generate new verifier certificate signed by CA
            console.log('Generating new verifier certificate...');
            cachedVerifierCert = await generateVerifierCertificate(ca.certificate, ca.privateKey);
            console.log('✓ Verifier certificate generated successfully');
        }
    }
    return cachedVerifierCert;
}

/**
 * Get both CA and verifier certificate
 * Must be called at server startup to ensure certificates are ready
 */
export async function getCertificates() {
    const verifier = await getVerifierCertificate();
    const ca = await getCA();
    return {
        verifier,
        ca,
    };
}
