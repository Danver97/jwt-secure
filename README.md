# jwt-secure

This package helps you create signed jwt tokens, creating managing RSA keys for you.  
It automatically creates and rotates at a given interval RSA keys.

Currently only supports AWS, but if needed you can issue a PR or open an issue to expand the supported cloud providers.
The interface can be easily implemented.

## Usage
```js
const JWTSecure = require('jwt-secure')('aws');
const jwts = new JWTSecure({ rsabit: 2048, algo: 'rs256', rotationInterval: 60, keyExpirationInterval: 7 });
await jwts.init();

const payload = {
    userId: 'u01974',
    name: 'John',
};
const token = await jwts.sign(payload);
const jwtPayload = await jwts.verify(token);
```

## Classes

### JWTSecure
It's an "abstract" class. It can be instantiated, but it's method are not implemented and are throwing an error. It defines the "interface" for each class.

### JWTAWS
Creates and manages RSA using KMS on AWS on your behalf
```js
const JWTSecure = require('jwt-secure')('aws');
const jwts = new JWTSecure(options);
```
`options` are the following:
- `rsabits - string`: number of bits for your keys. Supported values `2048` `3072` `4096`.
- `algo - string`: algorithm used for signing your token. Supported values `RS256` `RS384` `RS512`.
- `rotationInterval - int`: number of **seconds** after which the current key used is changed in seconds.
- `keyExpirationInterval - int`: number of **days** after which each key that has been changed is expired and can no longer be used to verify old tokens.

```js
jwts.init();
```
Creates the first pair of RSA keys. Now the module is readyto work.

Returns: `Promise<void>`.


```js
const token = await jwts.sign(payload);
```
- `payload - object`: your jwt payload. Any additional field such as `exp`, `sub`, `iss`, `nbf`, `aud`, must be already added into the payload. Only `iat` and `kid` will be automatically added.

Returns: `Promise<string>`.


```js
const decodedPayload = await jwts.verify(token);
```
- `token - string`: your signed jwt token.

Returns: `Promise<object>`.


### JWTTest - **NOT FOR PRODUCTION USE**
Useful for unit tests. Creates and manages RSA keys locally.
```js
const JWTSecure = require('jwt-secure')('test');
const jwts = new JWTSecure(options);
```
`options` are the following:
- `rsabits - string`: number of bits for your keys. Supported values `2048` `3072` `4096`.
- `algo - string`: algorithm used for signing your token. Supported values `RS256` `RS384` `RS512`.
- `rotationInterval - int`: number of **seconds** after which the current key used is changed in seconds.
- `keyExpirationInterval - int`: number of **seconds** after which each key that has been changed is expired and can no longer be used to verify old tokens.

```js
jwts.init();
```
Creates the first pair of RSA keys. Now the module is readyto work.

Returns: `Promise<void>`.

```js
const token = jwts.sign(payload, options);
```
- `payload - object`: your jwt payload.
- `options - object`: the same options of [`jsonwebtoken`](https://www.npmjs.com/package/jsonwebtoken).

Returns: `Promise<string>`.


```js
const decodedPayload = jwts.verify(token, options);
```
- `token - string`: your signed jwt token.
- `options - object`: the same options of [`jsonwebtoken`](https://www.npmjs.com/package/jsonwebtoken).

Returns: `Promise<object>`.

