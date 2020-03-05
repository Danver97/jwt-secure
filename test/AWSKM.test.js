const assert = require('assert');
const jwt = require('jsonwebtoken');
const JWTAWS = require('..')('aws');
const AWS = require('aws-sdk');

const kms = new AWS.KMS({ apiVersion: '2014-11-01' });

const waitAsync = ms => new Promise(resolve => setTimeout(resolve, ms));

describe('JWTAWS unit test', function () {
    const awsKM = new JWTAWS({ rsabit: 2048, algo: 'rs256', rotationInterval: 8, keyExpirationInterval: 7 });
    let jwtPayload;

    before(async function () {
        this.timeout(10000);
        await awsKM.init();
    });

    this.beforeEach(() => {
        jwtPayload = {
            field1: 'value1'
        };
    });

    it('check rotate() works', async function () {
        this.timeout(30000);
        this.slow(20000);
        let oldKid = awsKM.kid;

        await awsKM.rotate();
        assert.notStrictEqual(awsKM.kid, oldKid);

        oldKid = awsKM.kid;

        await waitAsync(12100);
        assert.notStrictEqual(awsKM.kid, oldKid);

        const response = await kms.describeKey({ KeyId: oldKid }).promise();
        assert.strictEqual(response.KeyMetadata.KeyState, 'PendingDeletion');
    });

    it('check sign() works', async function () {
        this.timeout(3000);
        jwtPayload.kid = awsKM.kid;

        const token1 = jwt.sign(jwtPayload, 'secret');
        const chunks1 = token1.split('.');
        const header = JSON.parse(Buffer.from(chunks1[0], 'base64').toString());
        header.alg = 'RS256';
        chunks1[0] = Buffer.from(JSON.stringify(header)).toString('base64');
        const expected = `${chunks1[0]}.${chunks1[1]}`;

        const token2 = await awsKM.sign(jwtPayload);
        const chunks2 = token2.split('.');
        const actual = `${chunks2[0]}.${chunks2[1]}`;

        assert.strictEqual(typeof chunks2[2], 'string');
        assert.ok(chunks2[2].length > 0);
        assert.strictEqual(actual, expected);
    });

    it('check verify() works', async function () {
        this.timeout(3000);
        jwtPayload.kid = awsKM.kid;

        const token1 = jwt.sign(jwtPayload, 'secret');
        const expected = jwt.verify(token1, 'secret');

        const token2 = await awsKM.sign(jwtPayload);
        const actual = await awsKM.verify(token2);
        assert.deepStrictEqual(actual, expected);
    });

    after(() => awsKM.finalize());
})