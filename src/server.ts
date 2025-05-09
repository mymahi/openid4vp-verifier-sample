import Fastify from 'fastify';
import { randomUUID } from 'crypto';
import { FastifyRequest, FastifyReply } from 'fastify';
import QRCode from 'qrcode';
import { UnsecuredJWT } from 'jose';
import formbody from '@fastify/formbody';
import { Ed25519, digest, generateSalt } from './edcrypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import dotenv from 'dotenv';

dotenv.config();

const BASE_URL =
    process.env.BASE_URL != null
        ? process.env.BASE_URL
        : process.env.CODESPACE_NAME != null
        ? `https://${process.env.CODESPACE_NAME}-3000.app.github.dev`
        : 'http://localhost:3000'; // Doesn't work with localhost as the endpoints need to be reachable from the MyMahi servers
const ISSUER_URL = process.env.ISSUER_URL || 'https://credentials.staging.mymahi.com';
const WALLET_AUTHORIZE_URL = process.env.WALLET_AUTHORIZE_URL || 'https://app.staging.mymahi.com/wallet/authorize';

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

    // DCQL query
    const dcqlQuery = {
        credentials: [
            {
                id: 'requested_id_credential',
                format: 'dc+sd-jwt',
                meta: {
                    vct_values: [`${ISSUER_URL}/credential/mymahi/learner_id/1.0`],
                },
                claims: [
                    { path: ['age_equal_or_over', '16'] }, // Modify this number, supported age gates are 13, 16, 18, 21
                    // { path: ['age_in_years'] }, // This gets the precise age in years rather than just an age gate
                    // { path: ['age_birth_year'] }, // This gets the birth year rather a pre-calculated age
                    { path: ['issuing_country'] } // This gets the country, in case only IDs from specific countries are supported/allowed
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

    // Store the request in memory
    requests[requestId] = {
        id: requestId,
        dcql_query: dcqlQuery,
        state: randomUUID(),
        nonce: randomUUID(),
        response_code: randomUUID(),
    };

    const inlineOpenID4VPUrl = new URL(WALLET_AUTHORIZE_URL);
    inlineOpenID4VPUrl.searchParams.append('client_id', `redirect_uri:${BASE_URL}/openid4vp/response?flow=inline`);
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

        // Construct the OpenID4VP URL
        const openid4vpUrl = new URL('openid4vp://authorize'); // Can also use the WALLET_AUTHORIZE_URL for deep linking from the Camera app
        openid4vpUrl.searchParams.append('client_id', `redirect_uri:${BASE_URL}/openid4vp/response?flow=cross-device`);
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

        const clientMetadata = {
            vp_formats: { 'dc+sd-jwt': { 'sd-jwt_alg_values': ['Ed25519'], 'kb-jwt_alg_values': ['Ed25519'] } },
        };

        const responseUri = `${BASE_URL}/openid4vp/response?flow=${flow}`;

        const unsignedJwt = new UnsecuredJWT({
            iss: `redirect_uri:${BASE_URL}/openid4vp/response?flow=${flow}`,
            aud: 'https://self-issued.me/v2', // Default audience
            response_type: 'vp_token',
            client_id: `redirect_uri:${BASE_URL}/openid4vp/response?flow=${flow}`,
            response_mode: 'direct_post',
            state: requests[id].state,
            dcql_query: requests[id].dcql_query,
            client_metadata: clientMetadata,
            nonce: requests[id].nonce,
            response_uri: responseUri,
        }).encode();

        reply.type('application/oauth-authz-req+jwt');
        return unsignedJwt;
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
                state: string;
                vp_token?: string;
                error?: string;
                error_description?: string;
            };
            Querystring: {
                flow?: string;
            };
        }>,
        reply: FastifyReply
    ) => {
        const { state, vp_token, error, error_description } = request.body;
        const { flow = 'inline' } = request.query;

        if (!state) {
            return reply.status(400).send({
                error: 'Invalid response',
                details: 'Missing or invalid state',
            });
        }

        // Validate the state by loading the corresponding request
        const matchingRequest = Object.values(requests).find((req) => req.state === state);
        if (!matchingRequest) {
            return reply.status(400).send({
                error: 'Invalid state',
                details: 'No matching request found for the provided state',
            });
        }

        if (error) {
            matchingRequest.error = { error, error_description, state };
            return reply.status(200).send({
                redirect_uri: `${BASE_URL}/error?response_code=${matchingRequest.response_code}`,
            });
        }

        if (!vp_token) {
            return reply.status(400).send({
                error: 'Invalid response',
                details: 'Missing vp_token',
            });
        }

        // Parse the vp_token as a JSON object
        let parsedVpToken;
        try {
            parsedVpToken = JSON.parse(vp_token);
        } catch (parseError) {
            return reply.status(400).send({
                error: 'Invalid VP Token',
                details: 'The VP Token is not a valid JSON string.',
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

        // Respond with the redirect_uri based on flow
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
        await fastify.listen({ port: 3000 });
        console.log(`Server is running on ${BASE_URL}`);
    } catch (err) {
        fastify.log.error(err);
        process.exit(1);
    }
};

start();
