var clean = require('warden-test-clean');
console.log(clean.pad('hello', 10)); // uses only the clean package

var evil = require('warden-test-evil');
console.log('evil module loaded:', evil.name);
