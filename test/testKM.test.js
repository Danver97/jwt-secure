const assert = require('assert');
const jwt = require('jsonwebtoken');
const JWTTest = require('..')('test');

const waitAsync = ms => new Promise(resolve => setTimeout(resolve, ms));

describe('JWTTest unit test', function () {
    const testKM = new JWTTest({ rsabit: 2048, algo: 'rs256', rotationInterval: 10, keyExpirationInterval: 2 });
    let jwtPayload;

    before(async function () {
        this.timeout(10000);
        await testKM.init()
    });

    this.beforeEach(() => {
        jwtPayload = {
            field1: 'value1'
        };
    });

    it('check rotate() works', async function () {
        this.timeout(30000);
        this.slow(20000);
        let oldKid = testKM.kid;
        let oldPrivateKey = testKM.keyStore[testKM.kid].privateKey;
        let oldPublicKey = testKM.keyStore[testKM.kid].publicKey;

        await testKM.rotate();
        assert.notStrictEqual(testKM.kid, oldKid);
        assert.notStrictEqual(testKM.keyStore[testKM.kid].privateKey, oldPrivateKey);
        assert.notStrictEqual(testKM.keyStore[testKM.kid].publicKey, oldPublicKey);

        oldKid = testKM.kid;
        oldPrivateKey = testKM.keyStore[testKM.kid].privateKey;
        oldPublicKey = testKM.keyStore[testKM.kid].publicKey;

        await waitAsync(10100);
        assert.notStrictEqual(testKM.kid, oldKid);
        assert.notStrictEqual(testKM.keyStore[testKM.kid].privateKey, oldPrivateKey);
        assert.notStrictEqual(testKM.keyStore[testKM.kid].publicKey, oldPublicKey);

        waitAsync(2100);
        assert.strictEqual(testKM.keyStore[oldKid], undefined);
    });

    it('check sign() works', async function () {
        this.timeout(3000);
        const privateKey = testKM.keyStore[testKM.kid].privateKey;
        jwtPayload.kid = testKM.kid;

        const expected = jwt.sign(jwtPayload, privateKey, { algorithm: 'RS256' });
        const actual = await testKM.sign(jwtPayload);
        assert.strictEqual(actual, expected);
    });

    it('check verify() works', async function () {
        this.timeout(3000);
        const privateKey = testKM.keyStore[testKM.kid].privateKey;
        const publicKey = testKM.keyStore[testKM.kid].publicKey;
        jwtPayload.kid = testKM.kid;

        const token = jwt.sign(jwtPayload, privateKey, { algorithm: 'RS256' });

        const expected = jwt.verify(token, publicKey, { algorithm: 'RS256' });
        const actual = await testKM.verify(token);
        assert.deepStrictEqual(actual, expected);
    });

    after(() => testKM.finalize())
})