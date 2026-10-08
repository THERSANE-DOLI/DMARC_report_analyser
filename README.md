# DMARC report analyser

*[Version française](README_FR.md)*

A web page to easily read DMARC aggregate reports (`rua`) sent every day by Google, Microsoft, Yahoo, GMX… to the address declared in your DMARC record.

Files are read **directly in the browser**: they are not sent to any server.

**Online version: https://thersane-doli.github.io/DMARC_report_analyser/**

## Two versions in one repository

| | Static version (`index.html`) | Server version (`index.php`) |
|---|---|---|
| Hosting | Any static hosting, e.g. **GitHub Pages** | Web server with PHP |
| Report reading | In the browser | In the browser (same) |
| IP reverse DNS (PTR) | Through Cloudflare DNS-over-HTTPS (the IPs are sent to Cloudflare) | By your server |
| Planned | | Reading the reports from a mailbox |

Both versions share the interface (`assets/`), the report reader and the translations (`lang/`). `index.php` simply serves `index.html` with the server features enabled.

## Features

- Supported formats: `.xml`, `.gz` / `.xml.gz`, `.zip` (including a zip containing `.gz` files)
- Several files at once, by drag and drop or file picker
- Summary: number of reports and covered period, messages, source IPs, DMARC pass rate, aligned DKIM and SPF, quarantine / reject
- Three sortable views:
  - **By source IP**: volume, pass rate, DKIM signing domains, reporters (click a row to see the IP details)
  - **Records**: every report row (DKIM results with selector, SPF, `From`, envelope)
  - **Reports**: reporter, period, published policy (`p`, `sp`, `pct`, `adkim`, `aspf`, `fo`)
- Filters: free search (IP, domain, DKIM selector, reporter…), domain, reporter, failures only
- On-demand reverse DNS (PTR) lookup of the IPs, IPv4 and IPv6
- Duplicates ignored (same report dropped twice)
- English and French interface, detected from the browser, switchable with the EN | FR button (remembered in the browser)
- Automatic light / dark theme

A message **passes DMARC** when DKIM *or* SPF is valid *and aligned* with the `From:` domain.

## Requirements

- A recent browser: Chrome / Edge 103+, Firefox 113+, Safari 16.4+ (native `DecompressionStream`)
- Server version only: PHP 7.3 or later (tested with PHP 8.3)

## Installation

### Static version on GitHub Pages

1. Push the repository to GitHub
2. In **Settings > Pages**, choose *Deploy from a branch*, branch `main`, folder `/ (root)`
3. The page is available at `https://<user>.github.io/<repository>/`

GitHub Pages does not run PHP: `index.php` is ignored there and `index.html` is served.

### Server version

Copy the folder to a web server with PHP. No database, no dependency to install. The provided `.htaccess` makes Apache serve `index.php` first (`DirectoryIndex index.php index.html`); on nginx, use `index index.php index.html;`.

To try it locally:

```bash
php -S 127.0.0.1:8765
```

then open http://127.0.0.1:8765/ (server version) or http://127.0.0.1:8765/index.html (static version).

## Configuration

### In `assets/parser.js`

| Constant | Default | Purpose |
|---|---|---|
| `MAX_XML_SIZE` | 50 MB | Max size of one decompressed XML |
| `MAX_TOTAL_SIZE` | 200 MB | Max decompressed volume for one drop of files |
| `MAX_ZIP_ENTRIES` | 50 | Max number of files read in one zip |

### In `index.php`

| Constant | Default | Purpose |
|---|---|---|
| `PTR_RATE_LIMIT` | 500 | Max PTR lookups per visitor IP address and per hour |

## Adding a language

1. Copy `lang/en.js` to `lang/xx.js`, replace `.en =` with `.xx =` and translate the values (keep the keys and the `{0}`, `{1}`… placeholders)
2. Add `<script src="lang/xx.js"></script>` in `index.html`, next to the other languages

Keys ending with `_html` may contain HTML; all others are escaped. If the browser asks for none of the available languages, the page is displayed in English.

## Security

Report content must be treated as hostile: anybody can send a fake report to your `rua=` address. The page is built accordingly:

- All report content is escaped when displayed
- Strict `Content-Security-Policy` (no external or inline script): `<meta>` tag in the static version, HTTP header in the server version (with `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`)
- XML with `DOCTYPE` / `ENTITY` refused (XXE and “billion laughs” protection)
- Decompression limits against gzip / zip bombs, nested zips refused
- Files never leave the browser
- Server version: PTR lookup only accepts valid IP addresses and is rate limited per visitor (`PTR_RATE_LIMIT`)

### Before putting the server version online

- Serve the page over **HTTPS**
- Deny direct access to the `src/` folder. The provided `.htaccess` does it on Apache; on **nginx**, add for example:

  ```nginx
  location ~ ^/src/ { deny all; }
  location ~ /\. { deny all; }
  ```

## Structure

```
index.html            Page (static version), also used by index.php
index.php             Server version: serves index.html + PTR lookup
assets/parser.js      Reads .xml / .gz / .zip reports in the browser
assets/app.js         Display, filters, sorting, language, PTR
assets/style.css      Styles (light / dark)
lang/en.js, fr.js     Translations
src/DmarcParser.php   PHP report reader, for the future mailbox reading
```

## Limitations

- Only **aggregate** reports (`rua`) are supported, not failure reports (`ruf`)
- Zip64 and encrypted zip archives are not supported
- Above 2,000 rows the table is truncated: refine the filters
- No history: each analysis starts from the dropped files

## License

Copyright (C) 2026 THERSANE

This program is free software, released under the [GNU GPL version 3](LICENSE) or (at your option) any later version. It comes with no warranty.
