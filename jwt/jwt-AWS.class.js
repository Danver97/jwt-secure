const JWTSecure = require('./jwt-secure.class');
const jwt = require('jsonwebtoken');
const AWS = require('aws-sdk');
const base64url = require('base64url');

const region = process.env.AWS_DEFAULT_REGION;
const credentials = new AWS.Credentials({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});
AWS.config = new AWS.Config({ region, credentials });
const kms = new AWS.KMS({ apiVersion: '2014-11-01' });

class JWTAWS extends JWTSecure {
    /**
     * 
     * @param {Object} options 
     * @param {number} [options.rsabit] RSA key bits
     * @param {string} [options.algo] Algorithm used for computing the JWT signature
     * @param {number} [options.rotationInterval] Time after which the key is rotated in seconds
     * @param {number} [options.keyExpirationInterval] Time after which the previous key expires and can't be no longer used for signature verification in days
     */
    constructor(options = {}) {
        super(options);
        this.awsAlgos = {
            RS256: 'RSASSA_PKCS1_V1_5_SHA_256',
            RS384: 'RSASSA_PKCS1_V1_5_SHA_384',
            RS512: 'RSASSA_PKCS1_V1_5_SHA_512',
        };
    }

    _getAWSAlgorithm(algo) {
        return this.awsAlgos[algo];
    }

    async rotate() {
        const oldKid = this.kid;
        const response = await kms.createKey({
            CustomerMasterKeySpec: `RSA_${this.rsabit}`,
            Description: 'Key used to sign JWT tokens',
            KeyUsage: 'SIGN_VERIFY',
        }).promise();
        this.kid = response.KeyMetadata.KeyId;
        await kms.createAlias({
            AliasName: `alias/JWTSecure_${this.kid}`,
            TargetKeyId: this.kid,
        }).promise();
        
        if (oldKid) {
            await kms.scheduleKeyDeletion({
                KeyId: oldKid,
                PendingWindowInDays: this.keyExpirationInterval < 7 ? 7 : this.keyExpirationInterval,
            }).promise();
        }
    }

    async sign(jwtPayload) {
        jwtPayload.kid = this.kid;
        jwtPayload.iat = Math.floor((new Date()).getTime()/1000);
        const header64url = this._base64urlEncoding({ alg: this.algorithm, typ: 'JWT' });
        const payload64url = this._base64urlEncoding(jwtPayload);

        const response = await kms.sign({
            KeyId: this.kid,
            Message: `${header64url}.${payload64url}`,
            SigningAlgorithm: this._getAWSAlgorithm(this.algorithm),
        }).promise();

        const signature64url = base64url.fromBase64(response.Signature.toString('base64'));

        return `${header64url}.${payload64url}.${signature64url}`;
    }

    async verify(token) {
        const chunks = token.split('.');
        const header64url = chunks[0];
        const payload64url = chunks[1];
        const signature64url = chunks[2];
        const signature64 = base64url.toBase64(signature64url);
        
        const decoded = jwt.decode(token);
        const kid = decoded.kid;
        const response = await kms.verify({
            KeyId: kid || this.kid,
            Message: `${header64url}.${payload64url}`,
            Signature: Buffer.from(signature64, 'base64'),
            SigningAlgorithm: this._getAWSAlgorithm(this.algorithm),
        }).promise();
        
        return decoded;
    }
}

module.exports = JWTAWS;
