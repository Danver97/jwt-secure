const KeyManager = require('./keyManager.class');
const NodeRSA = require('node-rsa');
const uuid = require('uuid').v4;
const jwt = require('jsonwebtoken');

class TestKeyManager extends KeyManager {
    /**
     * 
     * @param {Object} options 
     * @param {number} [options.rsabit] RSA key bits
     * @param {string} [options.algo] Algorithm used for computing the JWT signature
     * @param {number} [options.rotationInterval] Time after which the key is rotated in seconds
     * @param {number} [options.keyExpirationInterval] Time after which the previous key expires and can't be no longer used for signature verification in seconds
     */
    constructor(options = {}) {
        super(options);
        this.keyStore = {};
    }
    
    async rotate() {
        const oldKid = this.kid
        setTimeout(() => {
            delete this.keyStore[oldKid];
        }, this.keyExpirationInterval*1000);
        this.kid = uuid();
        const rsa = new NodeRSA({ b: this.rsabit });
        const privateKey = rsa.exportKey('pkcs1-private-pem');
        const publicKey = rsa.exportKey('pkcs1-public-pem');
        rsa.generateKeyPair();
        this.keyStore[this.kid] = { rsa, privateKey, publicKey };
    }

    sign(jwtPayload, options = {}) {
        const privateKey = this.keyStore[this.kid].privateKey;
        jwtPayload.kid = this.kid;
        options = Object.assign(options, { algorithm: this.algorithm });
        const promise = new Promise((resolve, reject) => {
            jwt.sign(jwtPayload, privateKey, options, (err, token) => {
                if (err) {
                    reject(err);
                    return;
                }
                resolve(token);
            });
        });
        return promise;
    }

    verify(token, options = {}) {
        const kid = jwt.decode(token).kid;
        const publicKey = this.keyStore[kid || this.kid].publicKey;
        const promise = new Promise((resolve, reject) => {
            jwt.verify(token, publicKey, options, (err, token) => {
                if (err) {
                    reject(err);
                    return;
                }
                resolve(token);
            });
        });
        return promise;
    }
}

module.exports = TestKeyManager;
