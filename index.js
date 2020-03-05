const jwtTest = require('./jwt/jwt-test.class');
const jwtAWS = require('./jwt/jwt-AWS.class');

module.exports = function(kmType) {
    switch (kmType) {
        case 'test':
            return jwtTest;
        case 'aws':
            return jwtAWS;
        default:
            return jwtTest;
    }
}
