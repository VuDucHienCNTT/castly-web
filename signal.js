/*
 * Castly web helpers, shared by index.html (send files to the TV) and poc.html (network test).
 *
 *  - base64url, random ids
 *  - AES-256-GCM "c1." envelopes for signaling (the key only ever lives in the QR's #fragment)
 *  - ntfy.sh publish (POST) / subscribe (WebSocket) with automatic reconnect
 *  - incremental SHA-256, so a 100 MB file can be hashed in 2 MB slices without loading it into RAM
 *
 * Wire format must match app/src/main/kotlin/dev/castly/receiver/files/internet/SignalCrypto.kt.
 * No dependencies; ES5-style so older Safari versions parse it.
 */
(function (g) {
  'use strict';
  var C = {};

  C.NTFY = 'https://ntfy.sh';
  // STUN only. No TURN relay on purpose: file bytes must never go through a third-party server.
  C.ICE_SERVERS = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] }];
  C.ENVELOPE_PREFIX = 'c1';

  var enc = new TextEncoder(), dec = new TextDecoder();

  C.b64u = function (bytes) {
    var a = new Uint8Array(bytes), s = '';
    for (var i = 0; i < a.length; i += 0x8000) s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  C.unb64u = function (s) {
    s = String(s).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var b = atob(s), a = new Uint8Array(b.length);
    for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
    return a;
  };

  /** n random characters from a 32-letter alphabet (no modulo bias: 256 is a multiple of 32). */
  C.randomId = function (n) {
    var abc = 'abcdefghijkmnpqrstuvwxyz23456789', r = new Uint8Array(n), s = '';
    crypto.getRandomValues(r);
    for (var i = 0; i < n; i++) s += abc.charAt(r[i] & 31);
    return s;
  };

  // ─── AES-GCM envelopes ────────────────────────────────────────────────────
  function aad(topic) { return enc.encode('castly1|' + topic); }

  C.importKey = function (raw) {
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  };
  C.newRawKey = function () { return crypto.getRandomValues(new Uint8Array(32)); };

  /** Encrypts obj for the given destination topic (bound as AAD, so a message can't be replayed to the other topic). */
  C.seal = function (key, topic, obj) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: aad(topic), tagLength: 128 }, key,
      enc.encode(JSON.stringify(obj))).then(function (ct) {
      return C.ENVELOPE_PREFIX + '.' + C.b64u(iv) + '.' + C.b64u(ct);
    });
  };
  C.open = function (key, topic, text) {
    var p = String(text).split('.');
    if (p.length !== 3 || p[0] !== C.ENVELOPE_PREFIX) return Promise.reject(new Error('format'));
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: C.unb64u(p[1]), additionalData: aad(topic), tagLength: 128 }, key,
      C.unb64u(p[2])).then(function (pt) { return JSON.parse(dec.decode(pt)); });
  };

  // ─── ntfy pub/sub ─────────────────────────────────────────────────────────
  C.publish = function (topic, text) {
    return fetch(C.NTFY + '/' + topic, { method: 'POST', body: text, cache: 'no-store' }).then(function (r) {
      if (!r.ok) throw new Error('ntfy ' + r.status);
      return r;
    });
  };

  /**
   * Subscribes to topic over WebSocket, delivering each message's text to onText once. Reconnects with
   * backoff and resumes after the last seen message id. sinceUnix: deliver cached messages newer than this.
   */
  C.subscribe = function (topic, sinceUnix, onText, onState) {
    var ws = null, closed = false, last = null, seen = {}, delay = 1000;
    function connect() {
      if (closed) return;
      var since = last || String(Math.max(0, Math.floor(sinceUnix)));
      ws = new WebSocket(C.NTFY.replace(/^http/, 'ws') + '/' + topic + '/ws?since=' + encodeURIComponent(since));
      ws.onopen = function () { delay = 1000; if (onState) onState('open'); };
      ws.onmessage = function (e) {
        var m; try { m = JSON.parse(e.data); } catch (x) { return; }
        if (m.event !== 'message' || !m.id || seen[m.id]) return;
        seen[m.id] = 1; last = m.id;
        onText(m.message || '');
      };
      ws.onclose = function () {
        if (closed) return;
        if (onState) onState('retry');
        setTimeout(connect, delay); delay = Math.min(delay * 2, 15000);
      };
      ws.onerror = function () { try { ws.close(); } catch (x) {} };
    }
    connect();
    return { close: function () { closed = true; try { ws && ws.close(); } catch (x) {} } };
  };

  // ─── SHA-256 (incremental) ────────────────────────────────────────────────
  var K = new Int32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);

  function Sha256() {
    this.h = new Int32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    this.buf = new Uint8Array(64); this.n = 0; this.len = 0; this.w = new Int32Array(64);
  }
  Sha256.prototype.block = function (b, o) {
    var w = this.w, h = this.h, i, x, y;
    for (i = 0; i < 16; i++) w[i] = (b[o + 4 * i] << 24) | (b[o + 4 * i + 1] << 16) | (b[o + 4 * i + 2] << 8) | b[o + 4 * i + 3];
    for (i = 16; i < 64; i++) {
      x = w[i - 15]; y = w[i - 2];
      w[i] = (w[i - 16] + (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) + w[i - 7] +
        (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10))) | 0;
    }
    var a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5], gg = h[6], hh = h[7];
    for (i = 0; i < 64; i++) {
      var t1 = (hh + (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) +
        ((e & f) ^ (~e & gg)) + K[i] + w[i]) | 0;
      var t2 = ((((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) +
        ((a & bb) ^ (a & c) ^ (bb & c))) | 0;
      hh = gg; gg = f; f = e; e = (d + t1) | 0; d = c; c = bb; bb = a; a = (t1 + t2) | 0;
    }
    h[0] = (h[0] + a) | 0; h[1] = (h[1] + bb) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
    h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + gg) | 0; h[7] = (h[7] + hh) | 0;
  };
  Sha256.prototype.update = function (data) {
    var d = data instanceof Uint8Array ? data : new Uint8Array(data), i = 0, n = d.length;
    this.len += n;
    if (this.n) {
      while (this.n < 64 && i < n) this.buf[this.n++] = d[i++];
      if (this.n === 64) { this.block(this.buf, 0); this.n = 0; }
    }
    while (i + 64 <= n) { this.block(d, i); i += 64; }
    while (i < n) this.buf[this.n++] = d[i++];
    return this;
  };
  Sha256.prototype.hex = function () {
    var len = this.len, pad = new Uint8Array(((this.n < 56) ? 56 : 120) - this.n + 8);
    pad[0] = 0x80;
    var hi = Math.floor(len / 0x20000000), lo = (len % 0x20000000) * 8, p = pad.length - 8;
    pad[p] = hi >>> 24; pad[p + 1] = hi >>> 16; pad[p + 2] = hi >>> 8; pad[p + 3] = hi;
    pad[p + 4] = lo >>> 24; pad[p + 5] = lo >>> 16; pad[p + 6] = lo >>> 8; pad[p + 7] = lo;
    this.len = len; this.update(pad);
    var s = '';
    for (var i = 0; i < 8; i++) s += ('00000000' + (this.h[i] >>> 0).toString(16)).slice(-8);
    return s;
  };
  C.Sha256 = Sha256;

  /** Reads blob.slice(start,end) into an ArrayBuffer (FileReader: proven reliable on iOS Safari, see KNOWN_ISSUES §1). */
  C.readSlice = function (blob, start, end) {
    return new Promise(function (res, rej) {
      var r = new FileReader();
      r.onload = function () { res(r.result); };
      r.onerror = function () { rej(r.error || new Error('read')); };
      r.readAsArrayBuffer(blob.slice(start, end));
    });
  };

  /** SHA-256 of a whole File/Blob, read in 2 MB slices; onProgress(doneBytes). */
  C.hashBlob = function (blob, onProgress, isCancelled) {
    var h = new Sha256(), off = 0, STEP = 2 * 1048576;
    function step() {
      if (isCancelled && isCancelled()) return Promise.reject(new Error('cancelled'));
      if (off >= blob.size) return Promise.resolve(h.hex());
      var end = Math.min(off + STEP, blob.size);
      return C.readSlice(blob, off, end).then(function (buf) {
        h.update(new Uint8Array(buf)); off = end; if (onProgress) onProgress(off); return step();
      });
    }
    return step();
  };

  /** "typ host" / "typ srflx" / … from an ICE candidate line. */
  C.candidateType = function (cand) {
    var m = / typ ([a-z]+)/.exec(cand || '');
    return m ? m[1] : '';
  };

  g.Castly = C;
  if (typeof module !== 'undefined') module.exports = C;
})(typeof window !== 'undefined' ? window : globalThis);
