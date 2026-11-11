"""The browser-side verifier.

This JavaScript is embedded verbatim into the generated dashboard. It exists so
that an auditor can check the chain **in their own browser**, without running
any tool and without trusting the tool that produced the file.

Why a hand-written SHA-256
---------------------------
``crypto.subtle`` is only exposed in secure contexts, which rules out
opening the dashboard from a ``file://`` URL in some browsers — exactly the
way an auditor will most likely open it. A self-contained implementation
works everywhere, offline, forever.

The important property is not speed, it is **cross-implementation agreement**.
The dashboard recomputes the canonical JSON and the SHA-256 of every receipt
from scratch and compares that byte-for-byte against what the Python side
produced. If the two implementations ever disagree, the dashboard says so
loudly instead of quietly showing a green check. Two independent
implementations agreeing is much stronger evidence than one implementation
asserting itself correct.
"""

JS_VERIFIER = r"""
// ---------------------------------------------------------------------------
// Canonical JSON — must match agentproof.core.canonical exactly.
// ---------------------------------------------------------------------------
function canonSort(a, b) {
  // Python sorts str by Unicode code point. JS string comparison uses UTF-16
  // code units, which agrees for the whole BMP but puts an astral-plane
  // character (U+10000+) *before* BMP characters in U+D800..U+FFFF, because
  // its first surrogate code unit is < 0xE000. Compare code points explicitly
  // so both implementations agree on every key, emoji included.
  var i = 0;
  var j = 0;
  while (i < a.length && j < b.length) {
    var ca = codePointAt(a, i);
    var cb = codePointAt(b, j);
    if (ca !== cb) return ca < cb ? -1 : 1;
    i += ca > 0xffff ? 2 : 1;
    j += cb > 0xffff ? 2 : 1;
  }
  if (i < a.length) return 1;
  if (j < b.length) return -1;
  return 0;
}

function codePointAt(str, index) {
  var first = str.charCodeAt(index);
  if (first >= 0xd800 && first <= 0xdbff && index + 1 < str.length) {
    var second = str.charCodeAt(index + 1);
    if (second >= 0xdc00 && second <= 0xdfff) {
      return 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
    }
  }
  return first;
}

function zeros(count) {
  var out = '';
  for (var i = 0; i < count; i++) out += '0';
  return out;
}

// Serialize a number the way Python's canonicalizer does. A JSON round-trip
// cannot tell 1 from 1.0, so whole numbers are written as integers (which is
// what Python's int produces). Non-integral values reproduce repr(float):
// shortest round-trippable digits, fixed notation for 1e-4 <= |x| < 1e16,
// otherwise exponent notation with an explicit sign and >= 2 exponent digits.
function canonicalNumber(value) {
  if (!Number.isFinite(value)) throw new Error('non-finite number');
  // JSON.parse('-0.0') yields -0, whose Python repr is '-0.0'; the integer
  // branch below would serialize it as '0'. Python's json.dumps never writes a
  // bare '-0' for int 0, so this is the only zero whose bytes can differ.
  if (Object.is(value, -0)) return '-0.0';
  if (value % 1 === 0) return JSON.stringify(value);
  var negative = value < 0;
  var abs = negative ? -value : value;
  var repr = abs.toExponential(); // shortest round-trip digits, e.g. "1.23e-5"
  var ePos = repr.indexOf('e');
  var digits = repr.slice(0, ePos).replace('.', '');
  var exp10 = parseInt(repr.slice(ePos + 1), 10);
  var decpt = exp10 + 1; // value = 0.<digits> * 10^decpt
  var out;
  if (decpt <= -4 || decpt > 16) {
    var mant = digits.charAt(0) + (digits.length > 1 ? '.' + digits.slice(1) : '');
    var e = decpt - 1;
    out = mant + 'e' + (e < 0 ? '-' : '+') + (Math.abs(e) < 10 ? '0' : '') + Math.abs(e);
  } else if (decpt <= 0) {
    out = '0.' + zeros(-decpt) + digits;
  } else if (decpt >= digits.length) {
    out = digits + zeros(decpt - digits.length) + '.0';
  } else {
    out = digits.slice(0, decpt) + '.' + digits.slice(decpt);
  }
  return (negative ? '-' : '') + out;
}

// Build the canonical text directly instead of rebuilding a JS object and
// calling JSON.stringify on it: JS engines enumerate "integer index" keys
// ("2", "10") in numeric order regardless of insertion order, which would
// silently override the code-point sort Python applies.
function canonicalJson(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return canonicalNumber(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    var items = [];
    for (var i = 0; i < value.length; i++) items.push(canonicalJson(value[i]));
    return '[' + items.join(',') + ']';
  }
  if (typeof value === 'object') {
    var keys = Object.keys(value).sort(canonSort);
    var pairs = [];
    for (var k = 0; k < keys.length; k++) {
      pairs.push(JSON.stringify(keys[k]) + ':' + canonicalJson(value[keys[k]]));
    }
    return '{' + pairs.join(',') + '}';
  }
  throw new Error('unsupported type: ' + typeof value);
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4), UTF-8 input, lowercase hex output.
// ---------------------------------------------------------------------------
var SHA_K = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
];

function utf8Bytes(str) {
  var out = [];
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    if (c < 0x80) {
      out.push(c);
    } else if (c < 0x800) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
      var c2 = str.charCodeAt(i + 1);
      var cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
      out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
      i++;
    } else {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
  }
  return out;
}

function sha256Hex(text) {
  var bytes = utf8Bytes(text);
  var bitLen = bytes.length * 8;
  bytes.push(0x80);
  while (bytes.length % 64 !== 56) bytes.push(0);
  // 64-bit big-endian length; JS numbers are safe to 2^53 so we split it.
  var hi = Math.floor(bitLen / 0x100000000);
  var lo = bitLen >>> 0;
  bytes.push((hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff);
  bytes.push((lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);

  var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
           0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  var w = new Array(64);

  for (var off = 0; off < bytes.length; off += 64) {
    for (var t = 0; t < 16; t++) {
      w[t] = (bytes[off + t * 4] << 24) | (bytes[off + t * 4 + 1] << 16) |
             (bytes[off + t * 4 + 2] << 8) | bytes[off + t * 4 + 3];
    }
    for (var t2 = 16; t2 < 64; t2++) {
      var s0 = (rotr(w[t2 - 15], 7) ^ rotr(w[t2 - 15], 18) ^ (w[t2 - 15] >>> 3)) >>> 0;
      var s1 = (rotr(w[t2 - 2], 17) ^ rotr(w[t2 - 2], 19) ^ (w[t2 - 2] >>> 10)) >>> 0;
      w[t2] = (w[t2 - 16] + s0 + w[t2 - 7] + s1) >>> 0;
    }

    var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];

    for (var i = 0; i < 64; i++) {
      var S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      var ch = ((e & f) ^ (~e & g)) >>> 0;
      var temp1 = (hh + S1 + ch + SHA_K[i] + w[i]) >>> 0;
      var S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      var maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      var temp2 = (S0 + maj) >>> 0;

      hh = g; g = f; f = e;
      e = (d + temp1) >>> 0;
      d = c; c = b; b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }

  var hex = '';
  for (var k = 0; k < 8; k++) {
    hex += ('00000000' + h[k].toString(16)).slice(-8);
  }
  return hex;
}

function rotr(x, n) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------
function verifyChain(data) {
  var results = [];
  var problems = [];
  var prev = '';
  var records = data.records || [];

  for (var i = 0; i < records.length; i++) {
    var r = records[i];
    var row = { seq: r.seq, ok: true, issues: [] };

    // 1. The body is exactly what the Python side hashed. Rebuild it from
    //    the record's own fields, minus the derived hash and signature.
    var body = {
      format: r.format,
      seq: r.seq,
      nonce: r.nonce,
      issued_at: r.issued_at,
      actor: r.actor,
      action: r.action,
      decision: r.decision,
      reason: r.reason,
      policy_id: r.policy_id,
      policy_digest: r.policy_digest,
      inputs_digest: r.inputs_digest,
      context: r.context || {},
      prev_hash: r.prev_hash
    };

    // 2. Cross-implementation check: does our canonical form match the
    //    bytes the Python side actually hashed?
    var myCanonical = canonicalJson(body);
    if (r.canonical_b64 && r.canonical_b64 !== b64Encode(myCanonical)) {
      row.ok = false;
      row.issues.push('canonical form differs from the Python implementation');
      problems.push('seq ' + r.seq + ': canonicalization differs between implementations');
    }

    // 3. Recompute the record hash.
    var myHash = sha256Hex(myCanonical);
    if (myHash !== r.record_hash) {
      row.ok = false;
      row.issues.push('recomputed hash does not match');
      problems.push('seq ' + r.seq + ': recomputed hash does not match the stored hash');
    }
    row.recomputed_hash = myHash;

    // 4. Chain linkage.
    if (r.prev_hash !== prev) {
      row.ok = false;
      row.issues.push('chain link broken');
      problems.push('seq ' + r.seq + ': prev_hash does not match the previous record');
    }
    prev = r.record_hash;

    // 5. Sequence continuity.
    if (r.seq !== i) {
      row.ok = false;
      row.issues.push('sequence number is out of order');
      problems.push('record #' + i + ' has seq ' + r.seq + '; a record was inserted or removed');
    }

    results.push(row);
  }

  // 6. Seal check.
  var sealState = 'absent';
  if (data.seal) {
    var sealBody = {
      chain_id: data.seal.chain_id,
      sealed_at: data.seal.sealed_at,
      record_count: data.seal.record_count,
      final_hash: data.seal.final_hash
    };
    var mySealHash = sha256Hex(canonicalJson(sealBody));
    var sealOk = mySealHash === data.seal.seal_hash;
    if (!sealOk) {
      problems.push('the seal does not match its own contents');
    }
    if (data.seal.record_count !== records.length) {
      sealOk = false;
      problems.push('the seal covers ' + data.seal.record_count + ' records but the file contains ' + records.length);
    }
    var finalHash = records.length ? records[records.length - 1].record_hash : '';
    if (data.seal.final_hash !== finalHash) {
      sealOk = false;
      problems.push('the seal final hash does not match the last record; the chain was rewritten after sealing');
    }
    sealState = sealOk ? 'matches' : 'does not match';
    if (!sealOk) sealState = 'does not match';
  }

  return {
    ok: problems.length === 0,
    rows: results,
    problems: problems,
    seal: sealState,
    records: records.length
  };
}

// ---------------------------------------------------------------------------
// Base64 (UTF-8 safe)
// ---------------------------------------------------------------------------
function b64Encode(str) {
  var bytes = utf8Bytes(str);
  var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var out = '';
  for (var i = 0; i < bytes.length; i += 3) {
    var b0 = bytes[i], b1 = bytes[i + 1], b2 = bytes[i + 2];
    out += chars[b0 >> 2];
    out += chars[((b0 & 3) << 4) | ((b1 === undefined ? 0 : b1) >> 4)];
    out += (b1 === undefined) ? '=' : chars[((b1 & 15) << 2) | ((b2 === undefined ? 0 : b2) >> 6)];
    out += (b2 === undefined) ? '=' : chars[b2 & 63];
  }
  return out;
}
"""
