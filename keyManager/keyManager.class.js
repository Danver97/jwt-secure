const base64url = require('base64url');

class KeyManager {
    /**
     * 
     * @param {Object} options 
     * @param {number} [options.rsabit] RSA key bits
     * @param {string} [options.algo] Algorithm used for computing the JWT signature
     * @param {number} [options.rotationInterval] Time after which the key is rotated in seconds
     * @param {number} [options.keyExpirationInterval] Time after which the previous key expires and can't be no longer used for signature verification
     */
    constructor(options = {}) {
        let { rsabit, algo, rotationInterval = 60, keyExpirationInterval = 0 } = options;
        if (algo)
            algo = algo.toUpperCase();
        this.supportedBits = {
            2048: '2048',
            3072: '3072',
            4096: '4096',
        };
        this.supportedAlgos = {
            RS256: 'RS256',
            RS384: 'RS384',
            RS512: 'RS512',
        };
        if (rsabit && !this._isSupportedBits(rsabit))
            throw new Error(`RSA bits not supported. Supported RSA bits: ${Object.keys(this.supportedBits).toString()}`);
        if (algo && !this._isSupportedAlgo(algo))
            throw new Error(`Algorithm not supported. Supported algorithms: ${Object.keys(this.supportedAlgos).toString()}`);
        this.rsabit = rsabit || 2048;
        this.algorithm = algo || this.supportedAlgos.RS256;
        this.rotationInterval = rotationInterval;
        this.keyExpirationInterval = keyExpirationInterval;
        this.intervalRef = setInterval(() => this.rotate(), rotationInterval*1000);
    }

    async init() {
        await this.rotate();
    }

    finalize() {
        clearInterval(this.intervalRef);
    }

    _isSupportedBits(rsabit) {
        return !!this.supportedBits[rsabit];
    }

    _isSupportedAlgo(algo) {
        return !!this.supportedAlgos[algo];
    }

    _base64urlEncoding(data) {
        data = JSON.stringify(data);
        return base64url(data);
    }

    _base64urlDecoding(data) {
        return base64url.decode(data);
    }

    rotate() {
        throw new Error('Not implemented!');
    }

    sign() {
        throw new Error('Not implemented!');
    }

    verify() {
        throw new Error('Not implemented!');
    }
}

module.exports = KeyManager;
