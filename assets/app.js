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

(function () {
	'use strict';

	var $ = function (id) { return document.getElementById(id); };

	// ---------- Helpers ----------
	function esc(s) {
		return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
			return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
		});
	}
	function pct(a, b) { return b ? Math.round(a * 1000 / b) / 10 : 0; }
	function uniq(arr) { return arr.filter(function (v, i) { return v && arr.indexOf(v) === i; }); }

	// ---------- Config: index.php injects {"server": true} ----------
	var config = {};
	try {
		config = JSON.parse($('app-config').textContent) || {};
	} catch (e) {}
	window.DmarcDns.configure({ server: !!config.server });

	// ---------- i18n ----------
	var dicts = window.DMARC_I18N || {};
	var langs = Object.keys(dicts);

	function detectLang() {
		var saved = null;
		try {
			saved = localStorage.getItem('dmarc_lang');
		} catch (e) {}
		if (saved && dicts[saved]) return saved;
		var nav = navigator.languages || [navigator.language || ''];
		for (var i = 0; i < nav.length; i++) {
			var code = String(nav[i]).slice(0, 2).toLowerCase();
			if (dicts[code]) return code;
		}
		return dicts.en ? 'en' : langs[0];
	}

	var lang = detectLang();
	var locale = lang === 'fr' ? 'fr-FR' : 'en-US';

	function fill(text, args, escape) {
		return text.replace(/\{(\d+)\}/g, function (m, i) {
			return args && args[i] != null ? (escape ? esc(args[i]) : String(args[i])) : m;
		});
	}
	// Translation as HTML: text and arguments escaped, except the markup of "_html" keys (trusted dictionary)
	function T(key, args) {
		var text = dicts[lang][key] != null ? dicts[lang][key] : key;
		return fill(/_html$/.test(key) ? text : esc(text), args, true);
	}
	// Translation as plain text (for textContent / document.title)
	function Tp(key, args) {
		var text = dicts[lang][key] != null ? dicts[lang][key] : key;
		return fill(text, args, false);
	}

	function translateStatic() {
		document.documentElement.lang = lang;
		document.title = Tp('title');
		document.querySelectorAll('body [data-i18n]').forEach(function (el) {
			el.innerHTML = T(el.dataset.i18n);
		});
		document.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) {
			el.placeholder = Tp(el.dataset.i18nPlaceholder);
		});
		$('lang-switch').querySelectorAll('button').forEach(function (b) {
			b.classList.toggle('active', b.dataset.lang === lang);
			b.setAttribute('aria-pressed', b.dataset.lang === lang ? 'true' : 'false');
		});
	}

	function setLang(l) {
		if (!dicts[l] || l === lang) return;
		lang = l;
		locale = lang === 'fr' ? 'fr-FR' : 'en-US';
		try {
			localStorage.setItem('dmarc_lang', l);
		} catch (e) {}
		translateStatic();
		renderErrors();
		renderManualCheck();
		if (reports.length) {
			buildLayout();
			render();
		}
	}

	$('lang-switch').innerHTML = langs.map(function (l) {
		return '<button type="button" data-lang="' + esc(l) + '" lang="' + esc(l) + '" title="' + esc(dicts[l].lang_name) + '">' + esc(l.toUpperCase()) + '</button>';
	}).join('');
	$('lang-switch').querySelectorAll('button').forEach(function (b) {
		b.addEventListener('click', function () { setLang(b.dataset.lang); });
	});
	translateStatic();

	// ---------- Formatting ----------
	function fmtNum(n) { return n.toLocaleString(locale); }
	function fmtDate(ts, withTime) {
		if (!ts) return '';
		var d = new Date(ts * 1000);
		var s = d.toLocaleDateString(locale, { day: 'numeric', month: 'short', year: 'numeric' });
		return withTime ? s + ' ' + d.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' }) : s;
	}
	function resultBadge(r) {
		var cls = r === 'pass' ? 'ok' : (r === 'fail' || r === 'permerror' || r === 'softfail' ? 'ko' : (r ? 'warn' : 'neutral'));
		return '<span class="badge ' + cls + '">' + esc(r || '—') + '</span>';
	}
	function dispoBadge(d) {
		var cls = d === 'none' ? 'neutral' : (d === 'reject' ? 'ko' : 'warn');
		return '<span class="badge ' + cls + '">' + esc(d) + '</span>';
	}

	// ---------- Data ----------
	var reports = [];
	var records = [];
	var errors = [];
	var domains = [];
	var orgs = [];
	var ptr = Object.create(null);
	var state;

	function resetState() {
		state = {
			tab: 'ip',
			search: '',
			searchRaw: '',
			domain: '',
			org: '',
			failOnly: false,
			ip: '',
			sort: { ip: ['count', -1], rec: ['count', -1], rep: ['begin', -1] }
		};
	}
	resetState();

	function setData(newReports, newErrors) {
		reports = newReports;
		errors = newErrors;
		records = [];
		reports.forEach(function (rep, ri) {
			rep.idx = ri;
			rep.records.forEach(function (r) {
				r.report = rep;
				r.search = [r.ip, r.headerFrom, r.envelopeFrom, r.envelopeTo, rep.org, rep.policy.domain]
					.concat(r.authDkim.map(function (a) { return a.domain + ' ' + a.selector; }))
					.concat(r.authSpf.map(function (a) { return a.domain; }))
					.join(' ').toLowerCase();
				records.push(r);
			});
		});
		domains = uniq(reports.map(function (r) { return r.policy.domain; })).sort();
		orgs = uniq(reports.map(function (r) { return r.org; })).sort();
		resetState();

		renderErrors();
		$('loader').classList.toggle('compact', reports.length > 0);
		$('help').hidden = reports.length > 0;
		$('app').hidden = !reports.length;
		if (reports.length) {
			buildLayout();
			render();
		} else {
			$('app').innerHTML = '';
		}
	}

	function renderErrors() {
		var box = $('errors');
		box.hidden = !errors.length;
		box.innerHTML = errors.length
			? '<strong>' + T('errors_title', [errors.length]) + '</strong><ul>' +
				errors.map(function (e) { return '<li>' + T(e[0], e.slice(1)) + '</li>'; }).join('') + '</ul>'
			: '';
	}

	// ---------- Upload: drag & drop / file picker, read in the browser ----------
	var input = $('file-input');
	var zone = $('dropzone');
	var busy = false;

	async function loadFiles(files) {
		if (busy || !files || !files.length) return;
		busy = true;
		var title = zone.querySelector('strong');
		title.textContent = Tp('analysing', [files.length]);
		var result;
		try {
			result = await window.DmarcParser.parseFiles(files);
		} catch (e) {
			result = { reports: [], errors: [['err_xml', String(e && e.message || e)]] };
		}
		busy = false;
		title.innerHTML = T('drop_title');
		// Empty the input: re-selecting the same file must fire "change" again
		input.value = '';
		setData(result.reports, result.errors);
	}

	input.addEventListener('change', function () { loadFiles(Array.prototype.slice.call(input.files)); });
	['dragenter', 'dragover'].forEach(function (ev) {
		document.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.add('over'); });
	});
	['dragleave', 'drop'].forEach(function (ev) {
		document.addEventListener(ev, function (e) { e.preventDefault(); if (ev === 'drop' || e.target === zone) zone.classList.remove('over'); });
	});
	document.addEventListener('drop', function (e) {
		if (e.dataTransfer && e.dataTransfer.files.length) loadFiles(Array.prototype.slice.call(e.dataTransfer.files));
	});

	// ---------- Layout ----------
	var app = $('app');

	function buildLayout() {
		app.innerHTML =
			'<div class="cards" id="cards"></div>' +
			'<div class="toolbar">' +
				'<input type="search" id="f-search" placeholder="' + T('search_ph') + '">' +
				'<select id="f-domain"><option value="">' + T('all_domains', [domains.length]) + '</option>' +
					domains.map(function (d) { return '<option>' + esc(d) + '</option>'; }).join('') + '</select>' +
				'<select id="f-org"><option value="">' + T('all_orgs', [orgs.length]) + '</option>' +
					orgs.map(function (o) { return '<option>' + esc(o) + '</option>'; }).join('') + '</select>' +
				'<label><input type="checkbox" id="f-fail"> ' + T('fail_only') + '</label>' +
				'<span id="f-ip"></span>' +
				'<span class="spacer"></span>' +
				'<button class="button" id="btn-ptr" type="button" title="' + T(config.server ? 'ptr_title' : 'ptr_title_doh') + '">' + T('ptr_btn') + '</button>' +
			'</div>' +
			'<div class="tabs" id="tabs"></div>' +
			'<div class="table-wrap" id="table"></div>';

		// Restore the filters (the layout is rebuilt when the language changes)
		$('f-search').value = state.searchRaw;
		$('f-domain').value = state.domain;
		$('f-org').value = state.org;
		$('f-fail').checked = state.failOnly;

		$('f-search').addEventListener('input', function () { state.searchRaw = this.value; state.search = this.value.trim().toLowerCase(); render(); });
		$('f-domain').addEventListener('change', function () { state.domain = this.value; render(); });
		$('f-org').addEventListener('change', function () { state.org = this.value; render(); });
		$('f-fail').addEventListener('change', function () { state.failOnly = this.checked; render(); });
		$('btn-ptr').addEventListener('click', resolvePtr);
	}

	// ---------- Filtering ----------
	function filtered() {
		return records.filter(function (r) {
			if (state.domain && r.report.policy.domain !== state.domain) return false;
			if (state.org && r.report.org !== state.org) return false;
			if (state.failOnly && r.pass) return false;
			if (state.ip && r.ip !== state.ip) return false;
			if (state.search && r.search.indexOf(state.search) === -1 && (ptr[r.ip] || '').toLowerCase().indexOf(state.search) === -1) return false;
			return true;
		});
	}

	function sortRows(rows, getter, dir) {
		rows.forEach(function (r) { r.__k = getter(r); });
		return rows.sort(function (a, b) {
			var x = a.__k, y = b.__k;
			if (typeof x === 'string' || typeof y === 'string') return String(x || '').localeCompare(String(y || ''), locale, { numeric: true }) * dir;
			return ((x || 0) - (y || 0)) * dir;
		});
	}

	// ---------- Render ----------
	function render() {
		var recs = filtered();
		renderCards(recs);
		$('f-ip').innerHTML = state.ip
			? '<span class="chip">' + T('ip_chip') + ' <span class="mono">' + esc(state.ip) + '</span><button type="button" title="' + T('remove') + '">✕</button></span>' : '';
		if (state.ip) $('f-ip').querySelector('button').onclick = function () { state.ip = ''; render(); };

		var byIp = groupByIp(recs);
		var byRep = groupByReport(recs);
		var doms = uniq(recs.map(function (r) { return r.report.policy.domain; })).sort();
		var tabs = [['ip', T('tab_ip'), byIp.length], ['rec', T('tab_rec'), recs.length], ['rep', T('tab_rep'), byRep.length], ['dom', T('tab_dom'), doms.length]];
		$('tabs').innerHTML = tabs.map(function (t) {
			return '<button type="button" data-tab="' + t[0] + '" class="' + (state.tab === t[0] ? 'active' : '') + '">' + t[1] + ' <span class="count">' + fmtNum(t[2]) + '</span></button>';
		}).join('');
		$('tabs').querySelectorAll('button').forEach(function (b) {
			b.onclick = function () { state.tab = b.dataset.tab; render(); };
		});

		if (state.tab === 'ip') renderTable('ip', byIp, ipColumns, function (row) { state.ip = row.ip; state.tab = 'rec'; render(); });
		else if (state.tab === 'rec') renderTable('rec', recs, recColumns);
		else if (state.tab === 'rep') renderTable('rep', byRep, repColumns);
		else renderDomains(recs, doms);
	}

	function renderCards(recs) {
		var total = 0, pass = 0, dkim = 0, spf = 0, quar = 0, rej = 0, ips = Object.create(null), reps = Object.create(null);
		recs.forEach(function (r) {
			total += r.count;
			if (r.pass) pass += r.count;
			if (r.dkim === 'pass') dkim += r.count;
			if (r.spf === 'pass') spf += r.count;
			if (r.disposition === 'quarantine') quar += r.count;
			if (r.disposition === 'reject') rej += r.count;
			ips[r.ip] = 1;
			reps[r.report.idx] = 1;
		});
		var minD = Infinity, maxD = 0;
		Object.keys(reps).forEach(function (i) {
			minD = Math.min(minD, reports[i].begin); maxD = Math.max(maxD, reports[i].end);
		});
		var p = pct(pass, total);
		function card(label, value, sub, cls, bar) {
			return '<div class="card ' + (cls || '') + '"><div class="label">' + label + '</div><div class="value">' + value + '</div>' +
				(sub ? '<div class="sub">' + sub + '</div>' : '') + (bar != null ? '<div class="bar"><i style="width:' + bar + '%"></i></div>' : '') + '</div>';
		}
		$('cards').innerHTML =
			card(T('card_reports'), fmtNum(Object.keys(reps).length), maxD ? T('card_range', [fmtDate(minD), fmtDate(maxD)]) : '') +
			card(T('card_messages'), fmtNum(total), T('card_ips', [fmtNum(Object.keys(ips).length)])) +
			card(T('card_pass'), p + ' %', fmtNum(pass) + ' / ' + fmtNum(total), p >= 98 ? 'ok' : (p >= 80 ? 'warn' : 'ko'), p) +
			card(T('card_fail'), fmtNum(total - pass), pct(total - pass, total) + ' %', total - pass ? 'ko' : 'ok') +
			card(T('card_dkim'), pct(dkim, total) + ' %', T('card_msgs', [fmtNum(dkim)]), '', pct(dkim, total)) +
			card(T('card_spf'), pct(spf, total) + ' %', T('card_msgs', [fmtNum(spf)]), '', pct(spf, total)) +
			card(T('card_quar'), fmtNum(quar) + ' / ' + fmtNum(rej), T('card_quar_sub'), quar + rej ? 'warn' : '');
	}

	function groupByIp(recs) {
		var map = Object.create(null);
		recs.forEach(function (r) {
			var g = map[r.ip];
			if (!g) g = map[r.ip] = { ip: r.ip, count: 0, pass: 0, dkim: 0, spf: 0, dispo: Object.create(null), from: [], orgs: [], dkimDomains: [], last: 0 };
			g.count += r.count;
			if (r.pass) g.pass += r.count;
			if (r.dkim === 'pass') g.dkim += r.count;
			if (r.spf === 'pass') g.spf += r.count;
			g.dispo[r.disposition] = (g.dispo[r.disposition] || 0) + r.count;
			g.from.push(r.headerFrom);
			g.orgs.push(r.report.org);
			r.authDkim.forEach(function (a) { g.dkimDomains.push(a.domain); });
			g.last = Math.max(g.last, r.report.end);
		});
		return Object.keys(map).map(function (k) {
			var g = map[k];
			g.from = uniq(g.from); g.orgs = uniq(g.orgs); g.dkimDomains = uniq(g.dkimDomains);
			g.fail = g.count - g.pass;
			g.rate = pct(g.pass, g.count);
			return g;
		});
	}

	function groupByReport(recs) {
		var map = Object.create(null);
		recs.forEach(function (r) {
			var rep = r.report;
			var g = map[rep.idx];
			if (!g) g = map[rep.idx] = { rep: rep, org: rep.org, begin: rep.begin, domain: rep.policy.domain, count: 0, pass: 0 };
			g.count += r.count;
			if (r.pass) g.pass += r.count;
		});
		return Object.keys(map).map(function (k) { var g = map[k]; g.rate = pct(g.pass, g.count); return g; });
	}

	function ipCell(ip) {
		return '<span class="mono">' + esc(ip) + '</span><span class="sub ptr" data-ip="' + esc(ip) + '">' + esc(ptr[ip] || '') + '</span>';
	}
	function noSignature() {
		return '<span class="muted">' + T('no_signature') + '</span>';
	}

	// Column definitions: [translation key, sortKey, renderer, className]
	var ipColumns = [
		['col_ip', 'ip', function (g) { return ipCell(g.ip); }],
		['col_messages', 'count', function (g) { return fmtNum(g.count); }, 'num'],
		['col_dmarc', 'rate', function (g) {
			return '<span class="badge ' + (g.fail ? (g.pass ? 'warn' : 'ko') : 'ok') + '">' + g.rate + ' %</span>' +
				(g.fail ? '<span class="sub">' + T('failing', [fmtNum(g.fail)]) + '</span>' : '');
		}],
		['col_dkim_ok', 'dkim', function (g) { return fmtNum(g.dkim); }, 'num'],
		['col_spf_ok', 'spf', function (g) { return fmtNum(g.spf); }, 'num'],
		['col_action', null, function (g) {
			return Object.keys(g.dispo).map(function (d) { return dispoBadge(d) + ' ' + fmtNum(g.dispo[d]); }).join('<br>');
		}],
		['col_from', null, function (g) { return g.from.map(esc).join('<br>'); }],
		['col_dkim_by', null, function (g) { return g.dkimDomains.map(esc).join('<br>') || noSignature(); }],
		['col_reporters', null, function (g) { return g.orgs.map(esc).join('<br>'); }],
		['col_last', 'last', function (g) { return fmtDate(g.last); }]
	];

	var recColumns = [
		['col_period', function () { return this.report.begin; }, function (r) {
			return fmtDate(r.report.begin) + '<span class="sub">' + esc(r.report.org) + '</span>';
		}],
		['col_ip', 'ip', function (r) { return ipCell(r.ip); }],
		['col_msg', 'count', function (r) { return fmtNum(r.count); }, 'num'],
		['col_dmarc', function () { return this.pass ? 1 : 0; }, function (r) {
			return '<span class="badge ' + (r.pass ? 'ok' : 'ko') + '">' + (r.pass ? 'pass' : 'fail') + '</span>';
		}],
		['col_action', 'disposition', function (r) {
			return dispoBadge(r.disposition) + r.reasons.map(function (x) { return '<span class="sub">' + esc(x) + '</span>'; }).join('');
		}],
		['col_dkim_aligned', 'dkim', function (r) { return resultBadge(r.dkim); }],
		['col_spf_aligned', 'spf', function (r) { return resultBadge(r.spf); }],
		['col_from_env', 'headerFrom', function (r) {
			return esc(r.headerFrom) + (r.envelopeFrom && r.envelopeFrom !== r.headerFrom ? '<span class="sub">env: ' + esc(r.envelopeFrom) + '</span>' : '') +
				(r.envelopeTo ? '<span class="sub">to: ' + esc(r.envelopeTo) + '</span>' : '');
		}],
		['col_dkim_results', null, function (r) {
			return r.authDkim.map(function (a) {
				return '<span class="auth">' + resultBadge(a.result) + ' ' + esc(a.domain) + (a.selector ? ' <span class="muted">s=' + esc(a.selector) + '</span>' : '') + '</span>';
			}).join('') || noSignature();
		}],
		['col_spf_results', null, function (r) {
			return r.authSpf.map(function (a) {
				return '<span class="auth">' + resultBadge(a.result) + ' ' + esc(a.domain) + (a.scope !== 'mfrom' ? ' <span class="muted">(' + esc(a.scope) + ')</span>' : '') + '</span>';
			}).join('') || '<span class="muted">—</span>';
		}]
	];

	var repColumns = [
		['col_period', 'begin', function (g) {
			return fmtDate(g.rep.begin, true) + '<span class="sub">→ ' + fmtDate(g.rep.end, true) + '</span>';
		}],
		['col_reporter', 'org', function (g) {
			return esc(g.rep.org) + '<span class="sub">' + esc(g.rep.email) + '</span>';
		}],
		['col_domain', 'domain', function (g) { return esc(g.domain); }],
		['col_policy', null, function (g) {
			var p = g.rep.policy;
			return '<span class="mono">p=' + esc(p.p) + (p.sp ? '; sp=' + esc(p.sp) : '') + '; pct=' + esc(p.pct) +
				'; adkim=' + esc(p.adkim) + '; aspf=' + esc(p.aspf) + (p.fo ? '; fo=' + esc(p.fo) : '') + '</span>';
		}],
		['col_messages', 'count', function (g) { return fmtNum(g.count); }, 'num'],
		['col_dmarc', 'rate', function (g) {
			return '<span class="badge ' + (g.rate >= 100 ? 'ok' : (g.pass ? 'warn' : 'ko')) + '">' + g.rate + ' %</span>';
		}],
		['col_file', null, function (g) {
			return '<span class="mono">' + esc(g.rep.file) + '</span><span class="sub">id: ' + esc(g.rep.id) + '</span>' +
				g.rep.metaErrors.map(function (e) { return '<span class="sub" style="color:var(--ko)">' + esc(e) + '</span>'; }).join('');
		}]
	];

	function renderTable(tab, rows, cols, onRowClick) {
		var sort = state.sort[tab];
		var col = cols.filter(function (c) { return (typeof c[1] === 'function' ? c[0] : c[1]) === sort[0]; })[0];
		var getter = col && typeof col[1] === 'function' ? function (r) { return col[1].call(r); } : function (r) { return r[sort[0]]; };
		rows = sortRows(rows.slice(), getter, sort[1]);

		var limit = 2000;
		var html = '<table><thead><tr>' + cols.map(function (c) {
			var key = typeof c[1] === 'function' ? c[0] : c[1];
			var cls = (c[3] || '') + (key && key === sort[0] ? ' sorted' + (sort[1] > 0 ? ' asc' : '') : '');
			return '<th class="' + cls + '"' + (key ? ' data-key="' + esc(key) + '"' : ' style="cursor:default"') + '>' + T(c[0]) + '</th>';
		}).join('') + '</tr></thead><tbody>';
		if (!rows.length) {
			html += '<tr><td colspan="' + cols.length + '" class="empty">' + T('no_result') + '</td></tr>';
		}
		rows.slice(0, limit).forEach(function (row, i) {
			var fail = row.pass === false || (row.fail > 0 && row.pass === 0);
			html += '<tr data-i="' + i + '" class="' + (onRowClick ? 'clickable' : '') + '"' + (fail ? ' style="box-shadow: inset 3px 0 var(--ko)"' : '') + '>' +
				cols.map(function (c) { return '<td class="' + (c[3] || '') + '">' + c[2](row) + '</td>'; }).join('') + '</tr>';
		});
		html += '</tbody></table>';
		if (rows.length > limit) html += '<div class="empty">' + T('more_rows', [fmtNum(rows.length - limit)]) + '</div>';
		$('table').innerHTML = html;

		$('table').querySelectorAll('th[data-key]').forEach(function (th) {
			th.onclick = function () {
				var k = th.dataset.key;
				state.sort[tab] = [k, state.sort[tab][0] === k ? -state.sort[tab][1] : (k === 'ip' || k === 'org' || k === 'domain' || k === 'headerFrom' ? 1 : -1)];
				render();
			};
		});
		if (onRowClick) {
			$('table').querySelectorAll('tbody tr[data-i]').forEach(function (tr) {
				tr.onclick = function () { onRowClick(rows[tr.dataset.i]); };
			});
		}
	}

	// ---------- Domains: DNS checks of DMARC, SPF and DKIM ----------
	var dnsResults = Object.create(null);
	var dnsPending = Object.create(null);
	var dnsRenderTimer = null;

	// Selectors tried when a domain is checked by hand without selector
	var COMMON_SELECTORS = ['default', 'dkim', 'mail', 'google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2', 's1024', 's2048', 'smtp', 'mx',
		'key1', 'key2', 'mxvault', 'zmail', 'protonmail', 'protonmail2', 'protonmail3', 'fm1', 'fm2', 'fm3', 'mandrill', 'mailjet',
		'everlytickey1', 'everlytickey2', 'sig1', 'dk', '20230601', '20221208', '20210112', '20161025'];

	// Result of a check, or null while loading (the query is started and the views re-rendered when done)
	function dnsCheck(kind, domain, selector) {
		var key = kind + '|' + domain + '|' + (selector || '');
		if (key in dnsResults) return dnsResults[key];
		if (!dnsPending[key]) {
			dnsPending[key] = true;
			var check = kind === 'dmarc' ? window.DmarcDns.checkDmarc(domain)
				: kind === 'spf' ? window.DmarcDns.checkSpf(domain)
				: window.DmarcDns.checkDkim(domain, selector);
			check.then(function (res) { dnsResults[key] = res; }, function () { dnsResults[key] = { error: true }; }).then(function () {
				delete dnsPending[key];
				scheduleDnsRender();
			});
		}
		return null;
	}

	function scheduleDnsRender() {
		clearTimeout(dnsRenderTimer);
		dnsRenderTimer = setTimeout(function () {
			if (reports.length && state.tab === 'dom') render();
			renderManualCheck();
		}, 80);
	}

	function resetDns() {
		window.DmarcDns.clearCache();
		dnsResults = Object.create(null);
	}

	function checksList(checks) {
		return '<ul class="checks">' + checks.map(function (c) {
			return '<li class="' + c[0] + '">' + T(c[1], c[2]) + '</li>';
		}).join('') + '</ul>';
	}

	function dnsSection(title, res) {
		var html = '<div class="dns-section"><h4>' + title + (res && res.name ? '<span class="mono">' + esc(res.name) + '</span>' : '') + '</h4>';
		if (res === null) return html + '<p class="muted">' + T('dns_loading') + '</p></div>';
		if (res.error) return html + checksList([['ko', 'dns_error']]) + '</div>';
		return html + res.records.map(function (r) { return '<code class="dns-record">' + esc(r) + '</code>'; }).join('') + checksList(res.checks) + '</div>';
	}

	function dnsNote() {
		return '<div class="dns-note"><span>' + T(config.server ? 'dns_note_server' : 'dns_note_doh') + '</span>' +
			'<button class="button small" type="button" data-recheck>' + T('dns_recheck') + '</button></div>';
	}

	function bindRecheck(el) {
		el.querySelectorAll('[data-recheck]').forEach(function (b) {
			b.onclick = function () {
				resetDns();
				if (reports.length) render();
				renderManualCheck();
			};
		});
	}

	/**
	 * DMARC, SPF and DKIM checks of one domain.
	 *
	 * @param {string} d          Domain
	 * @param {Object[]} sels     DKIM selectors: {domain, selector, count, pass}
	 * @param {boolean} withStats Show the signing domain and message columns (selectors seen in reports)
	 * @param {string} emptyKey   Message when there is no selector (none: no message)
	 * @param {string} intro      HTML shown above the DKIM table
	 */
	function domainCard(d, sels, withStats, emptyKey, intro) {
		var html = '<div class="domain-card"><h3>' + esc(d) + '</h3>' +
			dnsSection('DMARC', dnsCheck('dmarc', d)) +
			dnsSection('SPF', dnsCheck('spf', d)) +
			'<div class="dns-section"><h4>DKIM</h4>' + (intro || '');
		if (!sels.length) {
			if (emptyKey) html += '<p class="muted">' + T(emptyKey) + '</p>';
			return html + '</div></div>';
		}
		html += '<table class="dkim-table"><thead><tr><th>' + T('dkim_col_selector') + '</th>' +
			(withStats ? '<th>' + T('col_domain') + '</th><th class="num">' + T('dkim_col_seen') + '</th>' : '') +
			'<th>' + T('dkim_col_key') + '</th><th>' + T('dkim_col_status') + '</th></tr></thead><tbody>';
		sels.forEach(function (s) {
			var res = dnsCheck('dkim', s.domain, s.selector);
			var checks = res && !res.error ? res.checks.slice() : [];
			if (!window.DmarcDns.aligned(s.domain, d)) checks.push(['info', 'dkim_unaligned', [d]]);
			html += '<tr><td class="mono">' + esc(s.selector) + '</td>' +
				(withStats ? '<td>' + esc(s.domain) + '</td><td class="num">' + fmtNum(s.count) + '<span class="sub">' + T('dkim_pass_count', [fmtNum(s.pass)]) + '</span></td>' : '') +
				'<td>' + (res && !res.error && res.keyType ? esc(res.keyType.toUpperCase()) + (res.bits ? ' ' + res.bits + ' bits' : '') : '') + '</td>' +
				'<td>' + (res === null ? '<span class="muted">' + T('dns_loading') + '</span>' : res.error ? checksList([['ko', 'dns_error']]) : checksList(checks)) + '</td></tr>';
		});
		return html + '</tbody></table></div></div>';
	}

	// Domains tab: domains and DKIM selectors found in the reports
	function renderDomains(recs, doms) {
		var html = dnsNote();
		if (!doms.length) html += '<div class="empty">' + T('no_result') + '</div>';
		doms.forEach(function (d) {
			var sels = Object.create(null);
			recs.forEach(function (r) {
				if (r.report.policy.domain !== d) return;
				r.authDkim.forEach(function (a) {
					if (!a.selector || !a.domain) return;
					var k = a.domain + '|' + a.selector;
					var s = sels[k] || (sels[k] = { domain: a.domain, selector: a.selector, count: 0, pass: 0 });
					s.count += r.count;
					if (a.result === 'pass') s.pass += r.count;
				});
			});
			var selList = Object.keys(sels).map(function (k) { return sels[k]; }).sort(function (a, b) { return b.count - a.count; });
			html += domainCard(d, selList, true, 'dkim_none_seen');
		});
		$('table').innerHTML = html;
		bindRecheck($('table'));
	}

	// ---------- Domain checked by hand (form above the reports) ----------
	var manual = null;

	// Accept a domain, an email address or a URL; IDN converted to punycode
	function normalizeDomain(value) {
		var v = String(value || '').trim().toLowerCase().replace(/^mailto:/, '');
		var isUrl = /^[a-z][a-z0-9+.-]*:\/\//.test(v);
		v = v.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/[\/?#].*$/, '');
		// The web site of a domain is usually www.<domain>: check the mail domain
		if (isUrl) v = v.replace(/^www\./, '');
		if (v.indexOf('@') !== -1) v = v.slice(v.lastIndexOf('@') + 1);
		v = v.replace(/:\d+$/, '').replace(/\.$/, '');
		try {
			v = new URL('http://' + v).hostname;
		} catch (e) {}
		return v;
	}

	function runManualCheck(domainInput, selectorsInput) {
		var d = normalizeDomain(domainInput);
		var sels = uniq(String(selectorsInput || '').toLowerCase().split(/[\s,;]+/).filter(function (s) {
			return /^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/.test(s);
		}));
		if (!window.DmarcDns.validName(d)) {
			manual = { error: true, input: String(domainInput || '').trim() };
		} else {
			manual = { domain: d, selectors: sels, auto: !sels.length };
			// Shareable link: ?domain=…&selectors=…
			try {
				var url = new URL(location.href);
				url.searchParams.set('domain', d);
				if (sels.length) url.searchParams.set('selectors', sels.join(','));
				else url.searchParams.delete('selectors');
				history.replaceState(null, '', url);
			} catch (e) {}
		}
		renderManualCheck();
	}

	function renderManualCheck() {
		var box = $('check-result');
		if (!manual) {
			box.innerHTML = '';
			return;
		}
		if (manual.error) {
			box.innerHTML = checksList([['ko', 'check_invalid', [manual.input]]]);
			return;
		}
		var d = manual.domain;
		var rows, intro = '', emptyKey = 'check_no_selector_found';
		if (manual.auto) {
			var pending = 0;
			rows = COMMON_SELECTORS.filter(function (s) {
				var res = dnsCheck('dkim', d, s);
				if (res === null) {
					pending++;
					return false;
				}
				// Revoked keys of rotated selectors are normal: only active keys are listed
				return !res.error && res.records.length > 0 && !res.checks.some(function (c) { return c[1] === 'dkim_revoked'; });
			}).map(function (s) { return { domain: d, selector: s }; });
			intro = '<p class="muted">' + T(pending ? 'check_auto_searching' : 'check_auto_hint', [COMMON_SELECTORS.length - pending, COMMON_SELECTORS.length]) + '</p>';
			if (pending) emptyKey = null;
		} else {
			rows = manual.selectors.map(function (s) { return { domain: d, selector: s }; });
		}
		box.innerHTML = dnsNote() + domainCard(d, rows, false, emptyKey, intro);
		bindRecheck(box);
	}

	$('check-form').addEventListener('submit', function (e) {
		e.preventDefault();
		resetDns();
		runManualCheck($('check-domain').value, $('check-selectors').value);
	});

	// ---------- Reverse DNS ----------
	// Expand an IPv6 address to its 32 hex digits, or '' if invalid
	function expandIpv6(ip) {
		if (ip.indexOf('.') !== -1) return '';
		var parts = ip.split('::');
		if (parts.length > 2) return '';
		var head = parts[0] ? parts[0].split(':') : [];
		var tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
		var missing = 8 - head.length - tail.length;
		if (missing < 0 || (parts.length === 1 && missing !== 0)) return '';
		var groups = head.concat(new Array(parts.length === 2 ? missing : 0).fill('0'), tail);
		if (groups.length !== 8 || groups.some(function (g) { return !/^[0-9a-f]{1,4}$/i.test(g); })) return '';
		return groups.map(function (g) { return ('0000' + g).slice(-4); }).join('').toLowerCase();
	}

	function reverseName(ip) {
		if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return ip.split('.').reverse().join('.') + '.in-addr.arpa';
		var hex = ip.indexOf(':') !== -1 ? expandIpv6(ip) : '';
		return hex ? hex.split('').reverse().join('.') + '.ip6.arpa' : '';
	}

	// Server version: lookup by index.php; static version: Cloudflare DNS-over-HTTPS
	function lookupPtr(ip) {
		if (config.server) {
			return fetch('?ptr=' + encodeURIComponent(ip), { credentials: 'same-origin' })
				.then(function (r) { return r.ok ? r.json() : {}; })
				.then(function (d) { return typeof d.host === 'string' ? d.host : ''; });
		}
		var name = reverseName(ip);
		if (!name) return Promise.resolve('');
		return fetch('https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(name) + '&type=PTR', {
			headers: { accept: 'application/dns-json' },
			credentials: 'omit',
			referrerPolicy: 'no-referrer'
		})
			.then(function (r) { return r.json(); })
			.then(function (d) {
				var answer = (d.Answer || []).filter(function (a) { return a.type === 12; })[0];
				return answer ? String(answer.data).replace(/\.$/, '') : '';
			});
	}

	function resolvePtr() {
		var ips = uniq(filtered().map(function (r) { return r.ip; })).filter(function (ip) { return !(ip in ptr); });
		if (!ips.length) return;
		var done = 0, running = 0, queue = ips.slice();
		$('btn-ptr').disabled = true;
		function next() {
			while (running < 6 && queue.length) {
				lookup(queue.shift());
			}
		}
		function lookup(ip) {
			running++;
			lookupPtr(ip).then(function (host) {
				ptr[ip] = host;
				document.querySelectorAll('.ptr[data-ip="' + CSS.escape(ip) + '"]').forEach(function (el) { el.textContent = host; });
			}).catch(function () {}).then(function () {
				running--; done++;
				// The button may have been rebuilt by a language change
				var btn = $('btn-ptr');
				if (btn) {
					btn.disabled = done !== ips.length;
					btn.textContent = done === ips.length ? Tp('ptr_btn') : Tp('ptr_progress', [done, ips.length]);
				}
				next();
			});
		}
		next();
	}

	// ---------- Check given in the URL ----------
	try {
		var params = new URLSearchParams(location.search);
		if (params.get('domain')) {
			$('check-domain').value = params.get('domain');
			$('check-selectors').value = params.get('selectors') || '';
			runManualCheck(params.get('domain'), params.get('selectors'));
		}
	} catch (e) {}
})();
