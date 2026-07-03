// File: worker/deploy/deploy-worker.js
// Runs in the panel's backend (on user's local machine)

async function deployWorker(config) {
    // 1. Generate encrypted payload
    const payload = generateEncryptedPayload(config);
    
    // 2. Read the worker template
    const workerScript = readFile('worker/proxy/proxy-worker.js');
    
    // 3. Inject configuration
    const deployedScript = workerScript.replace(
        '__CONFIG_JSON__', 
        JSON.stringify(config)
    );
    
    // 4. Read sup.html and inject encrypted payload
    const supHtml = readFile('worker/templates/sup.html')
        .replace('__ENCRYPTED_PAYLOAD__', payload.encrypted)
        .replace('__PAYLOAD_KEY__', payload.key);
    
    // 5. Deploy to Cloudflare
    await cloudflare.deploy({
        script: deployedScript,
        html: supHtml,
        name: config.workerName
    });
}