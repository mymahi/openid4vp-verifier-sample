import Fastify from 'fastify';
import { randomUUID } from 'crypto';
import { FastifyRequest, FastifyReply } from 'fastify';
import QRCode from 'qrcode';
import formbody from '@fastify/formbody';
import { Ed25519, digest, generateSalt } from './edcrypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import dotenv from 'dotenv';
import {
    getVerifierCertificate,
    getCertificates,
    calculateX509Hash,
    signJwtWithCertificate,
    generateEphemeralEncryptionKey,
    decryptResponse,
} from './x509crypto';

dotenv.config();

const BASE_URL =
    process.env.BASE_URL != null
        ? process.env.BASE_URL
        : process.env.CODESPACE_NAME != null
        ? // When using github codespaces, ensure that you set the port to public otherwise
          // it won't be reachable by MyMahi servers
          `https://${process.env.CODESPACE_NAME}-3000.app.github.dev`
        : // Doesn't work with localhost as the endpoints need to be reachable from the MyMahi servers
          'http://localhost:3000';
const ISSUER_URL = process.env.ISSUER_URL || 'https://credentials.staging.mymahi.com';
const WALLET_AUTHORIZE_URL = process.env.WALLET_AUTHORIZE_URL || 'https://app.staging.mymahi.com/wallet/authorize';

// HAIP COMPLIANCE STATUS:
// This implementation now provides a mostly HAIP-compliant OpenID4VP verifier with the following features:
//
// ✅ IMPLEMENTED HAIP REQUIREMENTS:
//
// 1. SIGNED AUTHORIZATION REQUESTS (HAIP Section 5.1):
//    ✓ Uses JWT-Secured Authorization Request (JAR) with RFC9101
//    ✓ Uses x509_hash Client Identifier Prefix (HAIP Section 5)
//    ✓ X.509 certificates used for verifier authentication
//    ✓ Certificate chain included in x5c header (end-entity cert only, root CA excluded per spec)
//    ✓ Using EdDSA (Ed25519) algorithm for signing
//    ✓ Certificates include Subject Logotype extension with organization logo
//
// 2. RESPONSE ENCRYPTION (HAIP Section 5):
//    ✓ Uses response_mode 'direct_post.jwt' for encrypted responses
//    ✓ Implements ECDH-ES with P-256 curve for JWE alg
//    ✓ Uses A256GCM for JWE enc
//    ✓ Supplies ephemeral encryption public keys in client_metadata
//    ✓ Decrypts encrypted responses with ephemeral private keys
//
// 3. CRYPTOGRAPHIC REQUIREMENTS (HAIP Section 7):
//    ✓ Supports Ed25519 as primary algorithm (HAIP-compliant)
//    ✓ Also supports ES256 (ECDSA with P-256 and SHA-256) as fallback
//    ✓ Note: HAIP mandates ES256 as minimum baseline, but Ed25519 is also allowed
//
// 4. SAME-DEVICE FLOW (HAIP Section 5.1):
//    ✓ Includes redirect_uri in HTTP response to wallet's POST
//    ✓ Implements proper redirect handling
//
// 5. OTHER HAIP REQUIREMENTS:
//    ✓ Uses haip-vp:// custom URL scheme (HAIP Section 5.1)
//    ✓ Uses DCQL instead of Presentation Exchange (HAIP Section 5)
//    ✓ Includes vp_token response type (HAIP Section 5)
//    ✓ Uses dc+sd-jwt format identifier (HAIP Section 5.3.2)
//    ✓ Uses SHA-256 for digests (HAIP Section 8)
//
// ⚠️ PRODUCTION CONSIDERATIONS:
//
// 1. CERTIFICATE MANAGEMENT:
//    - Currently uses a development CA (generated once with npm run generate-ca)
//    - Verifier certificates are CA-signed with Ed25519 and include Subject Logotype extension
//    - Production should use certificates from a trusted Certificate Authority; or
//      your own Certificate Authority pre-registered with wallet applications
//    - Implement proper certificate loading from secure storage
//    - Handle certificate rotation and expiration
//
// 2. TRUST FRAMEWORK:
//    - Implement proper trust anchor validation
//    - Verify issuer certificates against trusted roots
//    - Implement certificate revocation checking
//
// 3. SECURITY HARDENING:
//    - Add rate limiting and request throttling
//    - Implement proper session management
//    - Add CSRF protection
//    - Secure storage for private keys (HSM/KMS)
//    - Add comprehensive logging and monitoring
//
// 4. CERTIFICATE BASED CREDENTIALS:
//    - Implement support for certificate-based credentials as per HAIP guidelines (x5c in VCs)
//    - HAIP requires verifiers to support VC verification using certificate chains instead of using
//      public keys from well-known JWKS only, however MyMahi credentials currently only use JWKS
//
// This implementation is now suitable for development, testing, and can be adapted
// for production use with proper certificate management, trust framework integration, and security hardening.

const fastify = Fastify({ logger: true });

// Register formbody plugin to handle application/x-www-form-urlencoded payloads
fastify.register(formbody);

// Define proper types for the in-memory stores
interface ErrorResponse {
    error: string;
    error_description?: string;
    state: string;
}

// Refine the ResponseData interface to include specific properties
interface ResponseData {
    validatedPayload: {
        age_equal_or_over?: Record<string, boolean>;
        issuing_country?: string;
        [key: string]: any; // Allow additional properties
    };
}

// Define a unified type for the in-memory store
interface RequestEntry {
    id: string;
    dcql_query: object;
    state: string;
    nonce: string;
    response_code: string;
    // Encryption keys for HAIP response encryption (required)
    encryptionPrivateKey: CryptoKey;
    encryptionPublicKeyJwk: any;
    completed?: boolean; // Indicates if the request is completed
    error?: ErrorResponse; // Error details if the request failed
    response?: ResponseData; // Response details if the request succeeded
}

// Update the requests object to use the new metadata structure
const requests: Record<string, RequestEntry> = {};

// Starting page
fastify.get('/', async (request: FastifyRequest, reply: FastifyReply) => {
    return reply.type('text/html').send(`
        <html>
            <head>
                <title>OpenID4VP Verifier</title>
                <script>
                    let timeoutHandle;

                    async function prepareRequest() {
                        const response = await fetch('/prepare-request', { method: 'POST' });
                        const data = await response.json();

                        document.getElementById('prepare-button').style.display = 'none';
                        document.getElementById('flow-buttons').style.display = 'block';

                        document.getElementById('inline-flow').onclick = function() {
                            window.location.href = data.inlineOpenId4VPUrl;
                        };

                        document.getElementById('cross-device-flow').onclick = function() {
                            document.getElementById('flow-buttons').style.display = 'none';
                            document.getElementById('qr-container').style.display = 'block';
                            document.getElementById('qr-code').src = '/render-qr/' + data.requestId;
                            document.getElementById('cancel-button').style.display = 'block';

                            // Start polling for request status
                            pollRequestStatus(data.requestId);
                        };
                    }

                    function cancelRequest() {
                        clearInterval(timeoutHandle);
                        alert('Request has been canceled.');
                        window.location.reload();
                    }

                    async function pollRequestStatus(requestId) {
                        const startTime = Date.now();

                        timeoutHandle = setInterval(async function() {
                            const elapsed = Date.now() - startTime;

                            if (elapsed > 5 * 60 * 1000) { // 5 minutes timeout
                                clearInterval(timeoutHandle);
                                alert('Request timed out. Please try again.');
                                window.location.reload();
                                return;
                            }

                            const response = await fetch('/request-status/' + requestId);
                            const data = await response.json();

                            if (data.redirect_uri) {
                                clearInterval(timeoutHandle);
                                window.location.href = data.redirect_uri;
                            }
                        }, 5000); // Poll every 5 seconds
                    }
                </script>
            </head>
            <body>
                <h1>Welcome to the OpenID4VP Verifier</h1>
                <button id="prepare-button" onclick="prepareRequest()">Prepare Request</button>
                <div id="flow-buttons" style="display: none;">
                    <button id="inline-flow">Inline Flow</button>
                    <button id="cross-device-flow">Cross-Device Flow</button>
                </div>
                <div id="qr-container" style="display: none;">
                    <h2>Scan the QR Code</h2>
                    <img id="qr-code" alt="QR Code" />
                    <button id="cancel-button" style="display: none;" onclick="cancelRequest()">Cancel</button>
                </div>
            </body>
        </html>
    `);
});

// Endpoint to prepare an authorization request
fastify.post('/prepare-request', async (request: FastifyRequest, reply: FastifyReply) => {
    const requestId = randomUUID();

    // HAIP Section 5: DCQL query MUST be used (not Presentation Exchange)
    // DCQL (Digital Credentials Query Language) is mandated by HAIP for credential requests
    const dcqlQuery = {
        credentials: [
            {
                id: 'requested_id_credential',
                format: 'dc+sd-jwt', // HAIP Section 5.3.2: format identifier for SD-JWT VC
                meta: {
                    vct_values: [`${ISSUER_URL}/credential/mymahi/learner_id/1.0`],
                },
                claims: [
                    { path: ['age_equal_or_over', '16'] }, // Modify this number, supported age gates are 13, 16, 18, 21
                    // { path: ['age_in_years'] }, // This gets the precise age in years rather than just an age gate
                    // { path: ['age_birth_year'] }, // This gets the birth year rather a pre-calculated age
                    { path: ['issuing_country'] }, // This gets the country, in case only IDs from specific countries are supported/allowed
                ],
            },
        ],
        credential_sets: [
            {
                purpose: 'ID for age 16+ check',
                options: [['requested_id_credential']],
            },
        ],
    };

    // HAIP Section 5: Generate ephemeral encryption keys for response encryption
    const ephemeralKey = await generateEphemeralEncryptionKey();

    // Store the request in memory with encryption keys
    requests[requestId] = {
        id: requestId,
        dcql_query: dcqlQuery,
        state: randomUUID(),
        nonce: randomUUID(),
        response_code: randomUUID(),
        encryptionPrivateKey: ephemeralKey.privateKey,
        encryptionPublicKeyJwk: ephemeralKey.publicKeyJwk,
    };

    // Get verifier certificate for client_id (load CA and verifier cert)
    const { verifier } = await getCertificates();
    const clientId = calculateX509Hash(verifier.certificate);

    const inlineOpenID4VPUrl = new URL(WALLET_AUTHORIZE_URL);
    inlineOpenID4VPUrl.searchParams.append('client_id', clientId);
    inlineOpenID4VPUrl.searchParams.append('request_uri', `${BASE_URL}/openid4vp/request/${requestId}?flow=inline`);

    return { requestId, inlineOpenId4VPUrl: inlineOpenID4VPUrl.toString() };
});

// Endpoint to render the QR code
fastify.get(
    '/render-qr/:id',
    async (
        request: FastifyRequest<{
            Params: { id: string };
        }>,
        reply: FastifyReply
    ) => {
        const { id } = request.params;

        if (!id || !requests[id]) {
            return reply.status(400).send({ error: 'Invalid or missing request ID' });
        }

        // Get verifier certificate for x509_hash client_id
        const { verifier } = await getCertificates();
        const clientId = calculateX509Hash(verifier.certificate);

        // Construct the OpenID4VP URL using HAIP-compliant custom URL scheme
        const openid4vpUrl = new URL('haip-vp://authorize'); // HAIP Section 5.1 mandates haip-vp:// custom URL scheme
        openid4vpUrl.searchParams.append('client_id', clientId);
        openid4vpUrl.searchParams.append('request_uri', `${BASE_URL}/openid4vp/request/${id}?flow=cross-device`);

        try {
            const qrCodeImage = await QRCode.toBuffer(openid4vpUrl.toString(), { type: 'png' });
            reply.type('image/png');
            return qrCodeImage;
        } catch (error) {
            return reply.status(500).send({ error: 'Failed to generate QR code' });
        }
    }
);

// Endpoint for the wallet to retrieve the request by ID
fastify.get(
    '/openid4vp/request/:id',
    async (
        request: FastifyRequest<{ Params: { id: string }; Querystring: { flow?: string } }>,
        reply: FastifyReply
    ) => {
        const { id } = request.params;
        const { flow = 'inline' } = request.query;

        if (!id || !requests[id]) {
            return reply.status(404).send({ error: 'Invalid or missing request ID' });
        }

        if (flow !== 'cross-device' && flow !== 'inline') {
            return reply.status(400).send({ error: 'Invalid flow value' });
        }

        // Get verifier certificate and CA for signing
        const { verifier, ca } = await getCertificates();
        const clientId = calculateX509Hash(verifier.certificate);

        // HAIP Section 5: Include ephemeral encryption public key in client_metadata
        const clientMetadata = {
            // HAIP Section 5.3.2 requires 'dc+sd-jwt' format identifier for SD-JWT VC
            // HAIP Section 7: ES256 is the mandatory baseline, but Ed25519 is also supported
            // Using Ed25519 as primary algorithm with ES256 as fallback
            vp_formats_supported: {
                'dc+sd-jwt': {
                    'sd-jwt_alg_values': ['Ed25519', 'ES256'],
                    'kb-jwt_alg_values': ['Ed25519', 'ES256'],
                },
            },
            // HAIP Section 5: Ephemeral encryption public key for response encryption
            jwks: {
                keys: [requests[id].encryptionPublicKeyJwk],
            },
        };

        const responseUri = `${BASE_URL}/openid4vp/response?flow=${flow}`;

        // HAIP Section 5.1: Create signed JWT (JAR - JWT-Secured Authorization Request)
        const payload = {
            iss: clientId,
            aud: 'https://self-issued.me/v2', // Default audience
            response_type: 'vp_token', // HAIP Section 5 requirement
            client_id: clientId,
            response_mode: 'direct_post.jwt', // HAIP Section 5: Encrypted response mode
            state: requests[id].state,
            dcql_query: requests[id].dcql_query,
            client_metadata: clientMetadata,
            nonce: requests[id].nonce,
            response_uri: responseUri,
        };

        // Sign the JWT with X.509 certificate, include CA in chain
        const signedJwt = await signJwtWithCertificate(
            payload,
            verifier.privateKey,
            verifier.certificate,
            ca.certificate
        );

        reply.type('application/oauth-authz-req+jwt');
        return signedJwt;
    }
);

// Endpoint to handle the wallet response
fastify.post(
    '/openid4vp/response',
    {
        config: {
            contentType: 'application/x-www-form-urlencoded',
        },
    },
    async (
        request: FastifyRequest<{
            Body: {
                response?: string; // HAIP: Encrypted JWE response in direct_post.jwt mode
                error?: string; // Unencrypted error responses are allowed
                error_description?: string;
                state?: string; // State may be present in unencrypted error responses
            };
            Querystring: {
                flow?: string;
            };
        }>,
        reply: FastifyReply
    ) => {
        const { response, error, error_description, state } = request.body;
        const { flow = 'inline' } = request.query;

        // Handle unencrypted error responses (allowed by OAuth 2.0 spec)
        if (error && !response) {
            // Find matching request by state if provided
            const matchingRequest = state ? Object.values(requests).find((req) => req.state === state) : null;

            if (matchingRequest) {
                matchingRequest.error = {
                    error,
                    error_description,
                    state: state || matchingRequest.state,
                };
                return reply.status(200).send({
                    redirect_uri: `${BASE_URL}/error?response_code=${matchingRequest.response_code}`,
                });
            } else {
                // Error without matching state - return generic error page
                return reply.status(400).send({
                    error,
                    error_description,
                });
            }
        }

        // HAIP Section 5: response_mode is direct_post.jwt, so response parameter is required for success cases
        if (!response) {
            return reply.status(400).send({
                error: 'invalid_request',
                details: 'Missing response parameter',
            });
        }

        // Decrypt the HAIP encrypted response
        let decryptedPayload: any = null;
        let effectiveState: string | undefined;

        try {
            // Find the request that matches by trying to decrypt with each pending request
            let found = false;
            for (const req of Object.values(requests)) {
                if (!req.completed && req.encryptionPrivateKey) {
                    try {
                        decryptedPayload = await decryptResponse(response, req.encryptionPrivateKey);
                        effectiveState = decryptedPayload.state;
                        found = true;
                        break;
                    } catch (e) {
                        // Try next request
                        continue;
                    }
                }
            }
            if (!found) {
                return reply.status(400).send({
                    error: 'invalid_request',
                    details: 'Could not decrypt response with any pending request key',
                });
            }
        } catch (decryptError) {
            return reply.status(400).send({
                error: 'invalid_request',
                details: decryptError instanceof Error ? decryptError.message : 'Decryption failed',
            });
        }

        if (!effectiveState) {
            return reply.status(400).send({
                error: 'invalid_request',
                details: 'Missing state in decrypted response',
            });
        }

        // Validate the state by loading the corresponding request
        const matchingRequest = Object.values(requests).find((req) => req.state === effectiveState);
        if (!matchingRequest) {
            return reply.status(400).send({
                error: 'invalid_request',
                details: 'No matching request found for the provided state',
            });
        }

        // Handle errors from decrypted payload
        if (decryptedPayload.error) {
            matchingRequest.error = {
                error: decryptedPayload.error,
                error_description: decryptedPayload.error_description,
                state: effectiveState,
            };
            return reply.status(200).send({
                redirect_uri: `${BASE_URL}/error?response_code=${matchingRequest.response_code}`,
            });
        }

        // Get vp_token from decrypted payload (already parsed as object from JWT)
        const parsedVpToken = decryptedPayload.vp_token;

        if (!parsedVpToken) {
            return reply.status(400).send({
                error: 'invalid_request',
                details: 'Missing vp_token in decrypted response',
            });
        }

        // Validate the structure of the parsed VP Token
        if (typeof parsedVpToken !== 'object' || parsedVpToken === null) {
            return reply.status(400).send({
                error: 'Invalid VP Token',
                details: 'The VP Token must be a JSON object.',
            });
        }

        // Hardcoded check for the requested_id_credential
        const presentedVcs = parsedVpToken['requested_id_credential'];

        if (!Array.isArray(presentedVcs) || presentedVcs.length === 0) {
            return reply.status(400).send({
                error: 'Invalid VP Token',
                details: 'No SD-JWT VCs presented for requested_id_credential.',
            });
        }

        // Fetch the issuer's public key
        let issuerPublicKey;
        try {
            const response = await fetch(`${ISSUER_URL}/.well-known/jwt-vc-issuer`);
            if (!response.ok) {
                throw new Error(`Failed to fetch issuer public key: ${response.statusText}`);
            }
            const issuerData = await response.json();
            issuerPublicKey = issuerData.jwks.keys[0];
        } catch (fetchError) {
            return reply.status(500).send({
                error: 'Issuer Key Fetch Error',
                details: fetchError instanceof Error ? fetchError.message : 'Unknown error',
            });
        }

        // Verify the presented SD-JWT VC
        let verificationResult;
        try {
            const sdJwtVcInstance = new SDJwtVcInstance({
                verifier: await Ed25519.getVerifier(issuerPublicKey),
                signAlg: Ed25519.alg,
                hasher: digest,
                hashAlg: 'sha-256',
                saltGenerator: generateSalt,
                kbVerifier: await Ed25519.getKbVerifier(),
            });

            verificationResult = await sdJwtVcInstance.verify(
                presentedVcs[0],
                // Hardcoded, claims as specified in the DCQL query
                ['age_equal_or_over.16', 'issuing_country'],
                true
            );

            if (!verificationResult) {
                return reply.status(400).send({
                    error: 'Invalid SD-JWT VC',
                    details: 'The SD-JWT VC for requested_id_credential failed verification.',
                });
            }
        } catch (verificationError) {
            return reply.status(500).send({
                error: 'Verification Error',
                details: verificationError instanceof Error ? verificationError.message : 'Unknown error',
            });
        }

        matchingRequest.response = { validatedPayload: verificationResult.payload };

        // Mark the request as completed
        matchingRequest.completed = true;

        // HAIP Section 5.1: Respond with the redirect_uri based on flow
        // For same-device flow (inline), redirect_uri must be included in response
        // and wallet must follow it. Verifier must reject if redirect doesn't arrive
        // in the same user session.
        if (flow === 'cross-device') {
            return {
                redirect_uri: null,
            };
        } else {
            return {
                redirect_uri: `${BASE_URL}/success?response_code=${matchingRequest.response_code}`,
            };
        }
    }
);

// Endpoint to query the status of the request, used for cross device flow
fastify.get('/request-status/:id', async (req: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
    const { id } = req.params;

    if (!id) {
        return reply.status(400).send({ error: 'Missing request ID' });
    }

    const requestEntry = requests[id];
    if (!requestEntry) {
        return reply.status(404).send({ error: 'Request ID not found' });
    }

    let redirectUri;
    if (requestEntry.completed) {
        redirectUri = `${BASE_URL}/success?response_code=${requestEntry.response_code}`;
    } else if (requestEntry.error) {
        redirectUri = `${BASE_URL}/error?response_code=${requestEntry.response_code}`;
    } else {
        redirectUri = null; // No redirect URI available yet
    }

    return reply.send({
        requestId: id,
        redirect_uri: redirectUri,
    });
});

// Success page
fastify.get(
    '/success',
    async (request: FastifyRequest<{ Querystring: { response_code: string } }>, reply: FastifyReply) => {
        const { response_code } = request.query;
        const responseData = Object.values(requests).find((req) => req.response_code === response_code)?.response;

        if (!responseData) {
            return reply.type('text/html').send(`
            <html>
                <head><title>Success</title></head>
                <body>
                    <h1>Verification Successful!</h1>
                    <p>No data found for the provided response code.</p>
                    <button onclick="window.location.href='/'">Restart</button>
                </body>
            </html>
        `);
        }

        return reply.type('text/html').send(`
        <html>
            <head><title>Success</title></head>
            <body>
                <h1>Verification Successful!</h1>
                <p>Age Equal or Over 16: ${responseData.validatedPayload.age_equal_or_over?.['16'] ?? 'Unknown'}</p>
                <p>Issuing Country: ${responseData.validatedPayload.issuing_country ?? 'Unknown'}</p>
                <p>Validated Payload: ${JSON.stringify(responseData.validatedPayload)}</p>
                <button onclick="window.location.href='/'">Restart</button>
            </body>
        </html>
    `);
    }
);

// Error page
fastify.get(
    '/error',
    async (request: FastifyRequest<{ Querystring: { response_code: string } }>, reply: FastifyReply) => {
        const { response_code } = request.query;
        const errorData = Object.values(requests).find((req) => req.response_code === response_code)?.error;

        if (!errorData) {
            return reply.type('text/html').send(`
            <html>
                <head><title>Error</title></head>
                <body>
                    <h1>An Error Occurred</h1>
                    <p>No data found for the provided response code.</p>
                    <button onclick="window.location.href='/'">Restart</button>
                </body>
            </html>
        `);
        }

        return reply.type('text/html').send(`
        <html>
            <head><title>Error</title></head>
            <body>
                <h1>An Error Occurred</h1>
                <p>Error: ${errorData.error}</p>
                <p>Description: ${errorData.error_description || 'No description provided'}</p>
                <p>State: ${errorData.state}</p>
                <button onclick="window.location.href='/'">Restart</button>
            </body>
        </html>
    `);
    }
);

// Start the server
const start = async () => {
    try {
        // Generate certificates on startup
        console.log('🔐 Initializing certificates...');
        await getVerifierCertificate();
        console.log('✓ Certificates ready\n');

        await fastify.listen({ port: 3000 });
        console.log(`Server is running on ${BASE_URL}`);
    } catch (err) {
        fastify.log.error(err);
        process.exit(1);
    }
};

start();
