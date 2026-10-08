/* Copyright (C) 2026 THERSANE
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * DNS checks of the DMARC, SPF and DKIM records of a domain.
 * Static version: Cloudflare DNS-over-HTTPS; server version: index.php?txt=
 * Checks are returned as [level (ok|warn|ko|info), translation key, args].
 */
(function () {
	'use strict';

	var server = false;
	var cache = Object.create(null);

	// Domain names coming from reports are untrusted: only plain DNS names are queried
	var NAME_RE = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$/i;

	function DnsError() {}

	// TXT data from DoH JSON: one or several quoted strings, with \" and \DDD escapes
	function unquote(data) {
		var parts = [], re = /"((?:[^"\\]|\\.)*)"/g, m;
		while ((m = re.exec(data))) parts.push(m[1]);
		var s = parts.length ? parts.join('') : data;
		return s.replace(/\\(\d{3})/g, function (x, d) { return String.fromCharCode(parseInt(d, 10)); }).replace(/\\(.)/g, '$1');
	}

	function queryTxt(name) {
		if (server) {
			return fetch('?txt=' + encodeURIComponent(name), { credentials: 'same-origin' })
				.then(function (r) {
					if (!r.ok) throw new DnsError();
					return r.json();
				})
				.then(function (d) {
					if (!Array.isArray(d.records)) throw new DnsError();
					return d.records.map(String);
				});
		}
		return fetch('https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(name) + '&type=TXT', {
			headers: { accept: 'application/dns-json' },
			credentials: 'omit',
			referrerPolicy: 'no-referrer'
		})
			.then(function (r) {
				if (!r.ok) throw new DnsError();
				return r.json();
			})
			.then(function (d) {
				// 0 = NOERROR, 3 = NXDOMAIN (no record)
				if (d.Status !== 0 && d.Status !== 3) throw new DnsError();
				return (d.Answer || []).filter(function (a) { return a.type === 16; }).map(function (a) { return unquote(String(a.data)); });
			});
	}

	/**
	 * TXT records of a name (cached; failures are not cached).
	 */
	function txt(name) {
		name = String(name).toLowerCase();
		if (!NAME_RE.test(name)) return Promise.reject(new DnsError());
		if (!cache[name]) {
			cache[name] = queryTxt(name);
			cache[name].catch(function () { delete cache[name]; });
		}
		return cache[name];
	}

	function parseTags(record) {
		var tags = Object.create(null);
		record.split(';').forEach(function (part) {
			var i = part.indexOf('=');
			if (i > 0) tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
		});
		return tags;
	}

	// Organizational domain, approximated by the last two labels (no public suffix list)
	function orgDomain(domain) {
		return domain.split('.').slice(-2).join('.');
	}

	// Relaxed alignment approximation: same domain or one is a subdomain of the other
	function aligned(a, b) {
		a = a.toLowerCase();
		b = b.toLowerCase();
		return a === b || a.slice(-b.length - 1) === '.' + b || b.slice(-a.length - 1) === '.' + a || orgDomain(a) === orgDomain(b);
	}

	function isDmarc(r) {
		return /v\s*=\s*dmarc1/i.test(r);
	}

	// ---------- DMARC ----------
	async function checkDmarc(domain) {
		var policyDomain = domain;
		var records = (await txt('_dmarc.' + domain)).filter(isDmarc);
		var checks = [];
		if (!records.length && orgDomain(domain) !== domain) {
			var org = orgDomain(domain);
			records = (await txt('_dmarc.' + org)).filter(isDmarc);
			if (records.length) {
				policyDomain = org;
				checks.push(['info', 'dns_inherited', [org]]);
			}
		}
		var result = { name: '_dmarc.' + policyDomain, records: records, checks: checks };
		if (!records.length) {
			checks.push(['ko', 'dmarc_none', ['_dmarc.' + domain]]);
			return result;
		}
		if (records.length > 1) {
			checks.push(['ko', 'dmarc_multiple', [records.length]]);
			return result;
		}

		var rec = records[0];
		var tags = parseTags(rec);
		var strength = { none: 0, quarantine: 1, reject: 2 };
		if (!/^\s*v\s*=\s*DMARC1\s*(;|$)/i.test(rec)) checks.push(['ko', 'dmarc_bad_version']);

		var p = (tags.p || '').toLowerCase();
		if (!(p in strength)) {
			checks.push(['ko', 'dmarc_bad_p']);
		} else {
			checks.push([p === 'none' ? 'warn' : 'ok', 'dmarc_p_' + p]);
			var sp = (tags.sp || '').toLowerCase();
			if (sp in strength && strength[sp] < strength[p]) checks.push(['warn', 'dmarc_sp_weaker', [sp, p]]);
		}
		if (tags.pct !== undefined && parseInt(tags.pct, 10) < 100) checks.push(['warn', 'dmarc_pct', [parseInt(tags.pct, 10)]]);

		if (!tags.rua) {
			checks.push(['warn', 'dmarc_no_rua']);
		} else {
			var addresses = tags.rua.split(',').map(function (a) { return a.trim(); }).filter(Boolean);
			for (var i = 0; i < addresses.length; i++) {
				var m = /^mailto:([^@!\s]+)@([^!\s]+)/i.exec(addresses[i]);
				if (!m) continue;
				var email = m[1] + '@' + m[2];
				var dest = m[2].toLowerCase();
				if (aligned(dest, policyDomain)) {
					checks.push(['ok', 'dmarc_rua_ok', [email]]);
					continue;
				}
				// RFC 7489 §7.1: an external destination must publish <domain>._report._dmarc.<dest>
				var authName = policyDomain + '._report._dmarc.' + dest;
				try {
					var auth = await txt(authName);
					checks.push(auth.some(isDmarc) ? ['ok', 'dmarc_rua_auth', [email]] : ['ko', 'dmarc_rua_unauth', [email, authName]]);
				} catch (e) {
					checks.push(['warn', 'dmarc_rua_unknown', [email]]);
				}
			}
		}
		return result;
	}

	// ---------- SPF (record reading, no include expansion) ----------
	async function checkSpf(domain) {
		var records = (await txt(domain)).filter(function (r) { return /^\s*v=spf1(\s|$)/i.test(r); });
		var checks = [];
		var result = { name: domain, records: records, checks: checks };
		if (!records.length) {
			checks.push(['ko', 'spf_none']);
			return result;
		}
		if (records.length > 1) {
			checks.push(['ko', 'spf_multiple', [records.length]]);
			return result;
		}
		var all = null, redirect = null, ptr = false;
		records[0].trim().split(/\s+/).slice(1).forEach(function (term) {
			var m = /^([+?~-]?)all$/i.exec(term);
			if (m) all = m[1] || '+';
			else if (/^redirect=/i.test(term)) redirect = term.slice(9);
			else if (/^[+?~-]?ptr(:|$)/i.test(term)) ptr = true;
		});
		if (all === '+') checks.push(['ko', 'spf_all_pass']);
		else if (all === '?') checks.push(['warn', 'spf_all_neutral']);
		else if (all === '~') checks.push(['ok', 'spf_all_soft']);
		else if (all === '-') checks.push(['ok', 'spf_all_fail']);
		else if (redirect) checks.push(['info', 'spf_redirect', [redirect]]);
		else checks.push(['warn', 'spf_no_all']);
		if (ptr) checks.push(['warn', 'spf_ptr']);
		return result;
	}

	// ---------- DKIM ----------
	async function rsaBits(b64) {
		var der;
		try {
			der = Uint8Array.from(atob(b64), function (c) { return c.charCodeAt(0); });
		} catch (e) {
			return 0;
		}
		try {
			var key = await crypto.subtle.importKey('spki', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
			return key.algorithm.modulusLength;
		} catch (e) {
			// Key refused by WebCrypto (e.g. too small): estimate from the DER size (~38 bytes of SPKI overhead)
			var estimate = (der.length - 38) * 8;
			var sizes = [384, 512, 768, 1024, 1536, 2048, 3072, 4096];
			var best = 0;
			sizes.forEach(function (s) { if (!best || Math.abs(s - estimate) < Math.abs(best - estimate)) best = s; });
			return estimate > 0 && Math.abs(best - estimate) <= 64 ? best : 0;
		}
	}

	async function checkDkim(domain, selector) {
		var name = selector + '._domainkey.' + domain;
		var records = (await txt(name)).filter(function (r) { return /(^|;)\s*p\s*=/i.test(r) || /^\s*v\s*=\s*DKIM1/i.test(r); });
		var checks = [];
		var result = { name: name, records: records, checks: checks, keyType: '', bits: 0 };
		if (!records.length) {
			checks.push(['ko', 'dkim_missing']);
			return result;
		}
		if (records.length > 1) checks.push(['warn', 'dkim_multiple']);

		var tags = parseTags(records[0]);
		var k = (tags.k || 'rsa').toLowerCase();
		var p = (tags.p || '').replace(/\s+/g, '');
		result.keyType = k;
		if (tags.v && tags.v.toUpperCase() !== 'DKIM1') {
			checks.push(['ko', 'dkim_bad']);
		} else if (!p) {
			checks.push(['ko', 'dkim_revoked']);
		} else if (k === 'ed25519') {
			result.bits = 256;
			checks.push(['ok', 'dkim_ok']);
		} else if (k === 'rsa') {
			result.bits = await rsaBits(p);
			if (!result.bits) checks.push(['warn', 'dkim_size_unknown']);
			else if (result.bits < 1024) checks.push(['ko', 'dkim_weak', [result.bits]]);
			else if (result.bits < 2048) checks.push(['warn', 'dkim_1024', [result.bits]]);
			else checks.push(['ok', 'dkim_ok']);
		} else {
			checks.push(['ko', 'dkim_bad']);
		}
		if ((tags.t || '').split(':').map(function (f) { return f.trim().toLowerCase(); }).indexOf('y') !== -1) checks.push(['warn', 'dkim_test']);
		return result;
	}

	window.DmarcDns = {
		configure: function (opts) { server = !!opts.server; },
		clearCache: function () { cache = Object.create(null); },
		aligned: aligned,
		validName: function (name) { return NAME_RE.test(name); },
		checkDmarc: checkDmarc,
		checkSpf: checkSpf,
		checkDkim: checkDkim
	};
})();
