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
 * Parse DMARC aggregate reports (RFC 7489, rua) in the browser, from .xml, .xml.gz/.gz or .zip files.
 * Same output as src/DmarcParser.php. Errors are returned as [translation key, arg0, arg1…].
 */
(function () {
	'use strict';

	/** Max size of one decompressed XML (protection against zip/gzip bombs) */
	var MAX_XML_SIZE = 50 * 1024 * 1024;
	/** Max decompressed size for all the files of one drop */
	var MAX_TOTAL_SIZE = 200 * 1024 * 1024;
	/** Max number of files read in one zip */
	var MAX_ZIP_ENTRIES = 50;

	var MB = 1024 * 1024;

	function ParseError(key, args) {
		this.key = key;
		this.args = args || [];
	}

	/**
	 * Decompress a gzip or raw deflate buffer, aborting once max bytes are exceeded.
	 */
	async function inflate(bytes, format, max) {
		if (typeof DecompressionStream === 'undefined') throw new ParseError('err_browser');
		var reader = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format)).getReader();
		var chunks = [], size = 0;
		for (;;) {
			var r;
			try {
				r = await reader.read();
			} catch (e) {
				throw new ParseError(format === 'gzip' ? 'err_gzip' : 'err_zip_read', [max / MB]);
			}
			if (r.done) break;
			size += r.value.length;
			if (size > max) {
				reader.cancel();
				throw new ParseError(format === 'gzip' ? 'err_gzip' : 'err_too_big', [max / MB]);
			}
			chunks.push(r.value);
		}
		var out = new Uint8Array(size), pos = 0;
		chunks.forEach(function (c) { out.set(c, pos); pos += c.length; });
		return out;
	}

	/**
	 * Read the central directory of a zip archive (no zip64, no encryption).
	 */
	function zipEntries(bytes) {
		var dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
		var len = bytes.length, eocd = -1;
		for (var i = len - 22; i >= Math.max(0, len - 65557); i--) {
			if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
		}
		if (eocd < 0) throw new ParseError('err_zip_read');
		var count = dv.getUint16(eocd + 10, true);
		var p = dv.getUint32(eocd + 16, true);
		if (count > MAX_ZIP_ENTRIES) throw new ParseError('err_zip_many', [MAX_ZIP_ENTRIES]);

		var decoder = new TextDecoder('utf-8');
		var entries = [];
		for (var n = 0; n < count; n++) {
			if (p + 46 > len || dv.getUint32(p, true) !== 0x02014b50) throw new ParseError('err_zip_read');
			var nameLen = dv.getUint16(p + 28, true);
			var entry = {
				flags: dv.getUint16(p + 8, true),
				method: dv.getUint16(p + 10, true),
				csize: dv.getUint32(p + 20, true),
				usize: dv.getUint32(p + 24, true),
				offset: dv.getUint32(p + 42, true),
				name: decoder.decode(bytes.subarray(p + 46, p + 46 + nameLen))
			};
			p += 46 + nameLen + dv.getUint16(p + 30, true) + dv.getUint16(p + 32, true);
			entries.push(entry);
		}
		return { dv: dv, entries: entries };
	}

	async function zipEntryData(bytes, dv, e) {
		if (e.offset + 30 > bytes.length || dv.getUint32(e.offset, true) !== 0x04034b50) throw new ParseError('err_zip_read');
		var start = e.offset + 30 + dv.getUint16(e.offset + 26, true) + dv.getUint16(e.offset + 28, true);
		if (start + e.csize > bytes.length) throw new ParseError('err_zip_read');
		var data = bytes.subarray(start, start + e.csize);
		if (e.flags & 1) throw new ParseError('err_zip_method');
		if (e.method === 0) {
			if (data.length > MAX_XML_SIZE) throw new ParseError('err_too_big');
			return data;
		}
		if (e.method === 8) return inflate(data, 'deflate-raw', MAX_XML_SIZE);
		throw new ParseError('err_zip_method');
	}

	function decodeText(bytes) {
		// Honour the encoding declared in the XML prolog (reports are almost always UTF-8)
		var head = new TextDecoder('ascii').decode(bytes.subarray(0, 200));
		var m = /^\s*<\?xml[^>]*encoding\s*=\s*["']([A-Za-z0-9._-]+)["']/.exec(head);
		try {
			return new TextDecoder(m ? m[1] : 'utf-8').decode(bytes);
		} catch (e) {
			return new TextDecoder('utf-8').decode(bytes);
		}
	}

	// ---------- XML helpers (namespace agnostic) ----------
	function kids(el, name) {
		var out = [];
		if (!el) return out;
		for (var c = el.firstElementChild; c; c = c.nextElementSibling) {
			if (c.localName === name) out.push(c);
		}
		return out;
	}
	function kid(el, name) {
		return kids(el, name)[0] || null;
	}
	function txt(el) {
		for (var i = 1; i < arguments.length && el; i++) el = kid(el, arguments[i]);
		return el ? el.textContent.trim() : '';
	}

	function Parser() {
		this.errors = [];
		this.totalSize = 0;
	}

	Parser.prototype.addError = function (key, name, args) {
		this.errors.push([key, name].concat(args || []));
	};

	Parser.prototype.checkTotal = function (name, size) {
		this.totalSize += size;
		if (this.totalSize > MAX_TOTAL_SIZE) {
			this.addError('err_total', name, [MAX_TOTAL_SIZE / MB]);
			return false;
		}
		return true;
	};

	/**
	 * Decompress a file into one or several XML documents.
	 */
	Parser.prototype.extract = async function (name, bytes, inZip) {
		// gzip
		if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
			var xml = await inflate(bytes, 'gzip', MAX_XML_SIZE);
			return this.checkTotal(name, xml.length) ? [{ name: name, bytes: xml }] : [];
		}

		// zip
		if (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) {
			if (inZip) throw new ParseError('err_zip_nested');
			var zip = zipEntries(bytes);
			var result = [];
			for (var i = 0; i < zip.entries.length; i++) {
				var e = zip.entries[i];
				if (e.name.slice(-1) === '/' || e.name.indexOf('__MACOSX/') === 0) continue;
				var entryName = name + '/' + e.name;
				try {
					var data = await zipEntryData(bytes, zip.dv, e);
					// A zip may contain gz files (but not other zips)
					result = result.concat(await this.extract(entryName, data, true));
				} catch (err) {
					if (!(err instanceof ParseError)) throw err;
					this.addError(err.key, entryName, err.args);
				}
			}
			return result;
		}

		return this.checkTotal(name, bytes.length) ? [{ name: name, bytes: bytes }] : [];
	};

	/**
	 * Parse one DMARC XML document.
	 */
	Parser.prototype.parseXml = function (name, text) {
		// DMARC reports never need a DTD: refusing it blocks XXE and entity expansion attacks
		if (/<!DOCTYPE|<!ENTITY/i.test(text)) {
			this.addError('err_doctype', name);
			return null;
		}
		var doc = new DOMParser().parseFromString(text, 'application/xml');
		if (doc.getElementsByTagName('parsererror').length) {
			this.addError('err_xml', name);
			return null;
		}
		var root = doc.documentElement;
		if (root.localName !== 'feedback') {
			this.addError('err_not_dmarc', name, [root.localName]);
			return null;
		}

		var meta = kid(root, 'report_metadata');
		var pol = kid(root, 'policy_published');
		var report = {
			file: name,
			org: txt(meta, 'org_name'),
			email: txt(meta, 'email'),
			id: txt(meta, 'report_id'),
			begin: parseInt(txt(meta, 'date_range', 'begin'), 10) || 0,
			end: parseInt(txt(meta, 'date_range', 'end'), 10) || 0,
			metaErrors: kids(meta, 'error').map(function (e) { return e.textContent.trim(); }),
			policy: {
				domain: txt(pol, 'domain').toLowerCase(),
				adkim: txt(pol, 'adkim') || 'r',
				aspf: txt(pol, 'aspf') || 'r',
				p: txt(pol, 'p'),
				sp: txt(pol, 'sp'),
				pct: txt(pol, 'pct') || '100',
				fo: txt(pol, 'fo')
			},
			records: []
		};

		kids(root, 'record').forEach(function (rec) {
			var row = kid(rec, 'row');
			var pe = kid(row, 'policy_evaluated');
			var id = kid(rec, 'identifiers');
			var auth = kid(rec, 'auth_results');
			var r = {
				ip: txt(row, 'source_ip'),
				count: parseInt(txt(row, 'count'), 10) || 0,
				disposition: txt(pe, 'disposition') || 'none',
				dkim: txt(pe, 'dkim'),
				spf: txt(pe, 'spf'),
				reasons: kids(pe, 'reason').map(function (x) { return (txt(x, 'type') + ' ' + txt(x, 'comment')).trim(); }),
				headerFrom: txt(id, 'header_from').toLowerCase(),
				envelopeFrom: txt(id, 'envelope_from').toLowerCase(),
				envelopeTo: txt(id, 'envelope_to').toLowerCase(),
				authDkim: kids(auth, 'dkim').map(function (d) {
					return { domain: txt(d, 'domain').toLowerCase(), selector: txt(d, 'selector'), result: txt(d, 'result') };
				}),
				authSpf: kids(auth, 'spf').map(function (s) {
					return { domain: txt(s, 'domain').toLowerCase(), scope: txt(s, 'scope') || 'mfrom', result: txt(s, 'result') };
				})
			};
			r.pass = r.dkim === 'pass' || r.spf === 'pass';
			report.records.push(r);
		});
		return report;
	};

	/**
	 * Parse a list of File objects.
	 *
	 * @param {FileList|File[]} files Files
	 * @return {Promise<{reports: Object[], errors: Array[]}>} Reports (deduplicated, newest first) and errors
	 */
	async function parseFiles(files) {
		var parser = new Parser();
		var reports = [];
		for (var i = 0; i < files.length; i++) {
			var file = files[i];
			try {
				var bytes = new Uint8Array(await file.arrayBuffer());
				var docs = await parser.extract(file.name, bytes, false);
				docs.forEach(function (d) {
					var rep = parser.parseXml(d.name, decodeText(d.bytes));
					if (rep) reports.push(rep);
				});
			} catch (err) {
				if (!(err instanceof ParseError)) {
					err = new ParseError('err_xml');
				}
				parser.addError(err.key, file.name, err.args);
			}
		}

		// Remove duplicates (same report received twice)
		var unique = Object.create(null);
		reports.forEach(function (r) { unique[r.org + '|' + r.id + '|' + r.policy.domain] = r; });
		reports = Object.keys(unique).map(function (k) { return unique[k]; });
		reports.sort(function (a, b) { return b.begin - a.begin; });

		return { reports: reports, errors: parser.errors };
	}

	window.DmarcParser = { parseFiles: parseFiles };
})();
