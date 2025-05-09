import { calculateJwkThumbprint, exportJWK, generateKeyPair, JWK } from 'jose';

export const generateSalt = (length: number): string => {
    if (length <= 0) {
        return '';
    }
    // a hex is represented by 2 characters, so we split the length by 2
    const array = new Uint8Array(length / 2);
    crypto.getRandomValues(array);

    const salt = Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join('');

    return salt;
};

export const digest = async (data: string | ArrayBuffer, algorithm = 'sha-256'): Promise<Uint8Array> => {
    const ec = new TextEncoder();
    const digest = await crypto.subtle.digest(algorithm, typeof data === 'string' ? ec.encode(data) : data);
    return new Uint8Array(digest);
};

export const Ed25519 = Object.freeze({
    alg: 'Ed25519',

    generateKeyPair: async () => {
        const keyPair = await generateKeyPair('EdDSA', {
            crv: 'Ed25519',
            extractable: true
        });

        // Export the public and private keys in JWK format
        const privateKeyJWK = await exportJWK(keyPair.privateKey);
        const publicKeyJWK = await exportJWK(keyPair.publicKey);
        privateKeyJWK.kid = await calculateJwkThumbprint(privateKeyJWK, 'sha256');
        publicKeyJWK.kid = await calculateJwkThumbprint(publicKeyJWK, 'sha256');

        return { publicKey: publicKeyJWK, privateKey: privateKeyJWK };
    },

    getPublicKeyFromPrivateKey: async (privateKeyJWK: JWK): Promise<JWK> => {
        if (privateKeyJWK.kty !== 'OKP' || privateKeyJWK.crv !== 'Ed25519') {
            throw new Error('Invalid private key');
        }
        // eslint-disable-next-line @typescript-eslint/naming-convention
        const { key_ops: _key_ops, use: _use, d: _d, ...publicKeyJWK } = privateKeyJWK;
        return publicKeyJWK;
    },

    getSigner: async (privateKeyJWK: JWK) => {
        const privateKey = await crypto.subtle.importKey(
            'jwk',
            privateKeyJWK,
            {
                name: 'Ed25519'
            },
            true, // whether the key is extractable (i.e., can be used in exportKey)
            ['sign']
        );

        return async (data: string) => {
            const encoder = new TextEncoder();
            const signature = await crypto.subtle.sign(
                {
                    name: 'Ed25519'
                },
                privateKey,
                encoder.encode(data)
            );

            return btoa(String.fromCharCode(...new Uint8Array(signature)))
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=+$/, ''); // Convert to base64url format
        };
    },

    getVerifier: async (publicKeyJWK: JWK) => {
        const publicKey = await crypto.subtle.importKey(
            'jwk',
            publicKeyJWK,
            {
                name: 'Ed25519'
            },
            true, // whether the key is extractable (i.e., can be used in exportKey)
            ['verify']
        );

        return async (data: string, signatureBase64url: string) => {
            const encoder = new TextEncoder();
            const signature = Uint8Array.from(atob(signatureBase64url.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
            const isValid = await crypto.subtle.verify(
                {
                    name: 'Ed25519'
                },
                publicKey,
                signature,
                encoder.encode(data)
            );

            return isValid;
        };
    },

    getKbVerifier: async () => {
        return async (data: string, signatureBase64url: string, payload: { cnf?: { jwk: object } }) => {
            let publicKeyJWK: JWK;
            if (payload.cnf && payload.cnf.jwk) {
                // use the jwk from the cnf
                publicKeyJWK = payload.cnf.jwk as JWK;
            } else {
                return false;
            }

            const publicKey = await crypto.subtle.importKey(
                'jwk',
                publicKeyJWK,
                {
                    name: 'Ed25519'
                },
                true, // whether the key is extractable (i.e., can be used in exportKey)
                ['verify']
            );

            const encoder = new TextEncoder();
            const signature = Uint8Array.from(atob(signatureBase64url.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
            const isValid = await crypto.subtle.verify(
                {
                    name: 'Ed25519'
                },
                publicKey,
                signature,
                encoder.encode(data)
            );

            return isValid;
        };
    }
});
