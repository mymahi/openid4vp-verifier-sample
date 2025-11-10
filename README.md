# openid4vp-verifier-sample

A sample OpenID4VP (OpenID for Verifiable Presentations) verifier implementation demonstrating credential verification using SD-JWT VCs.

## Overview

This verifier demonstrates the core concepts of OpenID4VP with support for:

-   Same-device (inline) and cross-device presentation flows
-   DCQL (Digital Credentials Query Language) for credential requests
-   SD-JWT VC verification with cryptographic holder binding
-   Age verification and issuing country validation

## HAIP Compliance Status

This implementation is now mostly **HAIP-compliant** for development and testing, implementing most major HAIP 1.0 requirements.

### ✅ Fully Implemented HAIP Requirements

1. **Signed Authorization Requests (HAIP Section 5.1)**

    - ✅ JWT-Secured Authorization Request (JAR) per RFC9101
    - ✅ X.509 certificate-based signing with Ed25519 algorithm
    - ✅ `x509_hash` Client Identifier Prefix
    - ✅ Certificate chain in x5c header (end-entity cert only, root CA excluded per spec)
    - ✅ Certificates include Subject Logotype extension with organization logo

2. **Response Encryption (HAIP Section 5)**

    - ✅ `direct_post.jwt` response mode with encrypted responses
    - ✅ ECDH-ES with P-256 curve for JWE alg
    - ✅ A256GCM for JWE enc
    - ✅ Ephemeral encryption public keys in client_metadata
    - ✅ Response decryption with ephemeral private keys

3. **Cryptographic Algorithm Support (HAIP Section 7)**

    - ✅ Ed25519 as primary algorithm (HAIP-compliant)
    - ✅ ES256 (ECDSA with P-256 and SHA-256) as fallback
    - ✅ SHA-256 for digests (HAIP Section 8)
    - ✅ Note: HAIP mandates ES256 as minimum baseline, but Ed25519 is also supported

4. **DCQL and Protocol Requirements**
    - ✅ Custom URL Scheme: `haip-vp://` (HAIP Section 5.1)
    - ✅ DCQL Query Language instead of Presentation Exchange (HAIP Section 5)
    - ✅ `vp_token` response type (HAIP Section 5)
    - ✅ `dc+sd-jwt` format identifier (HAIP Section 5.3.2)
    - ✅ Same-Device Flow with redirect_uri handling (HAIP Section 5.1)

### ⚠️ Production Deployment Considerations

While this implementation is mostly HAIP-compliant, the following should be addressed for production:

1. **Certificate Management**

    - Currently uses a development CA (generated once with `npm run generate-ca`)
    - Verifier certificates are CA-signed with Ed25519 and include Subject Logotype extension
    - Production should use certificates from a trusted Certificate Authority; or your own Certificate Authority pre-registered with wallet applications
    - Implement proper certificate loading from secure storage
    - Handle certificate rotation and expiration

2. **Trust Framework**

    - Implement proper trust anchor validation
    - Verify issuer certificates against trusted roots
    - Implement certificate revocation checking

3. **Security Hardening**

    - Add rate limiting and request throttling
    - Implement proper session management
    - Add CSRF protection
    - Secure storage for private keys (HSM/KMS)
    - Add comprehensive logging and monitoring

4. **Certificate Based Credentials**
    - Implement support for certificate-based credentials as per HAIP guidelines (x5c in VCs)
    - HAIP requires verifiers to support VC verification using certificate chains instead of using public keys from well-known JWKS only, however MyMahi credentials currently only use JWKS

### Development vs Production

**This implementation is suitable for:**

-   ✅ Development and testing with HAIP compliance
-   ✅ Integration testing with HAIP-compliant wallets
-   ✅ Understanding HAIP requirements and implementation patterns
-   ✅ Prototyping production verifier systems

**For production deployment, ensure:**

-   Proper X.509 certificate management with CA-issued certs
-   Secure key storage (HSM/KMS)
-   Trust framework integration
-   Security hardening and monitoring

## Features

-   **HAIP 1.0 Compliant**: Full implementation of OpenID4VC High Assurance Interoperability Profile

    -   Signed authorization requests with X.509 certificates (JAR)
    -   Encrypted responses with ECDH-ES + A256GCM
    -   x509_hash client identifier prefix
    -   Ed25519 cryptographic algorithm (with ES256 fallback)

-   **Two Presentation Flows**:

    -   Same-device (inline): User interacts on same device
    -   Cross-device: User scans QR code with wallet on different device

-   **DCQL-based Credential Requests**:

    -   Request specific claims (age gates, issuing country)
    -   Support for selective disclosure with SD-JWT VC

-   **Secure Credential Verification**:

    -   Validates issuer signatures using X.509 certificates
    -   Verifies key binding (KB-JWT)
    -   Checks presented claims match requested claims
    -   Decrypts encrypted presentations

-   **X.509 Certificate Management**:
    -   Automatic certificate generation for development
    -   Support for EdDSA (Ed25519) signing
    -   Certificate chain handling (x5c)
    -   x509_hash calculation for client identification

## Setup

1. Install dependencies:

```bash
npm install
```

2. Configure environment variables (optional):
   Create a `.env` file:

```env
BASE_URL=http://localhost:3000
ISSUER_URL=https://credentials.staging.mymahi.com
WALLET_AUTHORIZE_URL=https://app.staging.mymahi.com/wallet/authorize
```

3. Start the server:

```bash
npm start
```

The server will automatically generate the verifier certificate on startup using the pre-existing CA included in the repository.

**Note**: The CA files are included in the repository for development/testing purposes. For production, use certificates from a trusted Certificate Authority.

## Usage

1. Navigate to `http://localhost:3000`
2. Click "Prepare Request"
3. Choose flow:
    - **Inline Flow**: Opens wallet directly (same device)
    - **Cross-Device Flow**: Shows QR code for scanning

## Architecture

### Key Components

-   **`/prepare-request`**: Creates authorization request with DCQL query and ephemeral encryption keys
-   **`/openid4vp/request/:id`**: Returns signed JWT (JAR) with X.509 certificate
-   **`/openid4vp/response`**: Receives and decrypts encrypted VP token, verifies credentials
-   **`/render-qr/:id`**: Generates QR code for cross-device flow with haip-vp:// scheme
-   **`/request-status/:id`**: Polls request status (cross-device)
-   **`/success`**: Displays verified credential data
-   **`/error`**: Displays error information

### Cryptographic Operations

-   **X.509 Certificate Generation**: CA-signed certificates with Ed25519 and Subject Logotype extension (`src/x509crypto.ts`)
-   **JWT Signing**: JAR with x5c certificate chain (end-entity only) using Ed25519 algorithm
-   **Response Encryption**: ECDH-ES with ephemeral P-256 keys per request
-   **Response Decryption**: JWE decryption with A256GCM
-   **Client Identification**: x509_hash calculation from certificate

### DCQL Query Structure

```typescript
{
  credentials: [{
    id: 'requested_id_credential',
    format: 'dc+sd-jwt',
    meta: {
      vct_values: ['<credential-type>']
    },
    claims: [
      { path: ['age_equal_or_over', '16'] },
      { path: ['issuing_country'] }
    ]
  }],
  credential_sets: [{
    purpose: 'ID for age 16+ check',
    options: [['requested_id_credential']]
  }]
}
```

## Configuration

Modify the DCQL query in `/prepare-request` endpoint to request different claims:

```typescript
// Age verification options
{
    path: ['age_equal_or_over', '13'];
} // Age 13+
{
    path: ['age_equal_or_over', '16'];
} // Age 16+
{
    path: ['age_equal_or_over', '18'];
} // Age 18+
{
    path: ['age_equal_or_over', '21'];
} // Age 21+
{
    path: ['age_in_years'];
} // Exact age
{
    path: ['age_birth_year'];
} // Birth year

// Other claims
{
    path: ['issuing_country'];
} // Country code
```

## Security Considerations

✅ **This implementation now includes:**

1. Signed authorization requests with X.509 certificates (JAR) using Ed25519
2. Response encryption with ECDH-ES and A256GCM (direct_post.jwt)
3. Ed25519 cryptographic support with ES256 fallback (HAIP-compliant)
4. x509_hash client identifier prefix
5. Ephemeral encryption keys per request
6. Proper certificate chain handling (end-entity cert only, root CA excluded)
7. Subject Logotype extension in certificates with organization logo
8. CA-signed verifier certificates (development CA)

⚠️ **For production deployment, additionally implement:**

1. Certificates from a trusted Certificate Authority (currently uses development CA)
2. Secure key storage (HSM/KMS) for private keys
3. Certificate revocation checking
4. Proper trust anchor validation
5. Trust framework integration
6. Session management and CSRF protection
7. Rate limiting and request throttling
8. Comprehensive logging and monitoring
9. Certificate rotation and lifecycle management

## Dependencies

-   `fastify`: Web framework
-   `@fastify/formbody`: Form data parsing
-   `jose`: JWT/JWS/JWE operations
-   `@sd-jwt/sd-jwt-vc`: SD-JWT VC verification
-   `@peculiar/x509`: X.509 certificate generation and management
-   `@peculiar/webcrypto`: Web Crypto API implementation
-   `qrcode`: QR code generation
-   `dotenv`: Environment configuration

## References

-   [OpenID4VC HAIP 1.0](https://openid.github.io/OpenID4VC-HAIP/openid4vc-high-assurance-interoperability-profile-wg-draft.html)
-   [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
-   [SD-JWT VC Specification](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc)
-   [DCQL Specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-dcql-query-language)

## License

MIT
