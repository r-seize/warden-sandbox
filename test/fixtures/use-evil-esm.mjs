// ESM script that dynamically imports the evil ESM package
// (dynamic import so the ESM hook can intercept it from node_modules)
const evil = await import('warden-test-evil/esm-index.mjs');
console.log('loaded:', evil.default);
