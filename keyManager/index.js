const testKM = require('./testKM.class');
const AWSKM = require('./AWSKM.class');

module.exports = function(kmType) {
    switch (kmType) {
        case 'test':
            return testKM;
        case 'aws':
            return AWSKM;
        default:
            return testKM;
    }
}
