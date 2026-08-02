// Simulates token theft: reads env vars and would exfiltrate them.
const token    = process.env.NPM_TOKEN;
const home     = process.env.HOME;
console.log('Would exfiltrate:', { token, home });
