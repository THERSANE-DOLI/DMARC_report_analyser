<?php

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
 * DMARC report analyser - server version
 *
 * Serves the same page as index.html (reports are still read in the browser) and adds server features:
 * - ?ptr=IP   : reverse DNS lookup done by this server
 * - ?txt=name : TXT records (DMARC, SPF, DKIM checks) queried by this server
 * (the static version uses Cloudflare DNS-over-HTTPS for both)
 * Later: reading the reports from a mailbox with src/DmarcParser.php.
 */

/** Max DNS queries (PTR + TXT) per client IP and per hour */
define('DNS_RATE_LIMIT', 1000);

ini_set('display_errors', '0');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

/**
 * Count the DNS queries of the client IP (fixed one hour window, stored in the temp folder).
 *
 * @return bool False when the limit is reached
 */
function dnsRateLimitOk()
{
	$client = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
	$fp = @fopen(sys_get_temp_dir().'/dmarc-dns-'.sha1($client), 'c+');
	if (!$fp) {
		return true;
	}
	flock($fp, LOCK_EX);
	$data = json_decode(stream_get_contents($fp), true);
	$now = time();
	if (!is_array($data) || !isset($data['start'], $data['count']) || $data['start'] < $now - 3600) {
		$data = array('start' => $now, 'count' => 0);
	}
	$data['count']++;
	ftruncate($fp, 0);
	rewind($fp);
	fwrite($fp, json_encode($data));
	flock($fp, LOCK_UN);
	fclose($fp);
	return $data['count'] <= DNS_RATE_LIMIT;
}

// Reverse DNS lookup (called in AJAX by the page)
if (isset($_GET['ptr'])) {
	header('Content-Type: application/json; charset=utf-8');
	header('Cache-Control: no-store');
	$ip = is_string($_GET['ptr']) ? filter_var($_GET['ptr'], FILTER_VALIDATE_IP) : false;
	if (!$ip) {
		http_response_code(400);
		echo json_encode(array('host' => ''));
		exit;
	}
	if (!dnsRateLimitOk()) {
		http_response_code(429);
		echo json_encode(array('host' => ''));
		exit;
	}
	$host = gethostbyaddr($ip);
	echo json_encode(array('ip' => $ip, 'host' => ($host && $host !== $ip) ? $host : ''));
	exit;
}

// TXT records (called in AJAX by the Domains tab)
if (isset($_GET['txt'])) {
	header('Content-Type: application/json; charset=utf-8');
	header('Cache-Control: no-store');
	$name = is_string($_GET['txt']) ? strtolower($_GET['txt']) : '';
	if (!preg_match('/^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$/', $name)) {
		http_response_code(400);
		echo json_encode(array('records' => array()));
		exit;
	}
	if (!dnsRateLimitOk()) {
		http_response_code(429);
		echo json_encode(array('records' => array()));
		exit;
	}
	$found = @dns_get_record($name, DNS_TXT);
	if ($found === false) {
		http_response_code(502);
		echo json_encode(array('records' => array()));
		exit;
	}
	$records = array();
	foreach ($found as $rr) {
		// Long TXT records are split in several strings: "entries" keeps them, "txt" is their concatenation
		$records[] = isset($rr['entries']) ? implode('', $rr['entries']) : (isset($rr['txt']) ? $rr['txt'] : '');
	}
	echo json_encode(array('records' => $records), JSON_INVALID_UTF8_SUBSTITUTE);
	exit;
}

// Page: index.html with server features enabled.
// The CSP header replaces the meta of index.html (no Cloudflare needed, frame-ancestors only works as a header).
header("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
header('X-Frame-Options: DENY');

$config = array('server' => true);
$html = file_get_contents(__DIR__.'/index.html');
$html = preg_replace('/\s*<meta http-equiv="Content-Security-Policy"[^>]*>/', '', $html, 1);
$html = str_replace(
	'<script type="application/json" id="app-config">{}</script>',
	'<script type="application/json" id="app-config">'.json_encode($config, JSON_HEX_TAG).'</script>',
	$html
);
echo $html;
