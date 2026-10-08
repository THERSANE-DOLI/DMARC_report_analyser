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
 * Parse DMARC aggregate reports (RFC 7489, rua) from .xml, .xml.gz/.gz or .zip files.
 */
class DmarcParser
{
	/** Max size of one decompressed XML (protection against zip/gzip bombs) */
	const MAX_XML_SIZE = 30 * 1024 * 1024;

	/** Max decompressed size for all the files of one request */
	const MAX_TOTAL_SIZE = 100 * 1024 * 1024;

	/** Max number of files read in one zip */
	const MAX_ZIP_ENTRIES = 50;

	/** @var int Decompressed bytes read so far */
	private $totalSize = 0;

	/** @var array[] Errors collected while parsing: array(translation key, arg0, arg1…) */
	public $errors = array();

	/**
	 * Parse a raw file (any supported format) and return the reports found in it.
	 *
	 * @param string $fileName Original file name (used for messages only)
	 * @param string $data     Raw file content
	 * @return array[]         List of reports
	 */
	public function parseFile($fileName, $data)
	{
		$reports = array();
		foreach ($this->extractXml($fileName, $data) as $name => $xml) {
			$report = $this->parseXml($name, $xml);
			if ($report !== null) {
				$reports[] = $report;
			}
		}
		return $reports;
	}

	/**
	 * Decompress a file into one or several XML strings.
	 *
	 * @param string $fileName File name
	 * @param string $data     Raw content
	 * @param bool   $inZip    True when the file comes from a zip (nested zips are refused)
	 * @return array<string,string> name => xml
	 */
	public function extractXml($fileName, $data, $inZip = false)
	{
		// gzip
		if (strncmp($data, "\x1f\x8b", 2) === 0) {
			$xml = @gzdecode($data, self::MAX_XML_SIZE);
			if ($xml === false) {
				$this->errors[] = array('err_gzip', $fileName, self::MAX_XML_SIZE / 1048576);
				return array();
			}
			return $this->checkTotal($fileName, $xml) ? array($fileName => $xml) : array();
		}

		// zip
		if (strncmp($data, "PK\x03\x04", 4) === 0) {
			if ($inZip) {
				$this->errors[] = array('err_zip_nested', $fileName);
				return array();
			}
			if (!class_exists('ZipArchive')) {
				$this->errors[] = array('err_zip_ext', $fileName);
				return array();
			}
			$tmp = tempnam(sys_get_temp_dir(), 'dmarc');
			file_put_contents($tmp, $data);
			$zip = new ZipArchive();
			$result = array();
			try {
				if ($zip->open($tmp, ZipArchive::RDONLY) !== true) {
					$this->errors[] = array('err_zip_read', $fileName);
					return array();
				}
				if ($zip->numFiles > self::MAX_ZIP_ENTRIES) {
					$this->errors[] = array('err_zip_many', $fileName, self::MAX_ZIP_ENTRIES);
					$zip->close();
					return array();
				}
				for ($i = 0; $i < $zip->numFiles; $i++) {
					$stat = $zip->statIndex($i);
					if (!$stat || substr($stat['name'], -1) === '/') {
						continue;
					}
					if ($stat['size'] > self::MAX_XML_SIZE) {
						$this->errors[] = array('err_too_big', $fileName.'/'.$stat['name']);
						continue;
					}
					// Length limited: the size declared in the zip directory cannot be trusted
					$content = $zip->getFromIndex($i, self::MAX_XML_SIZE);
					if ($content === false) {
						continue;
					}
					// A zip may itself contain gz files (but not other zips)
					foreach ($this->extractXml($fileName.'/'.$stat['name'], $content, true) as $n => $x) {
						$result[$n] = $x;
					}
				}
				$zip->close();
			} finally {
				@unlink($tmp);
			}
			return $result;
		}

		return $this->checkTotal($fileName, $data) ? array($fileName => $data) : array();
	}

	/**
	 * Count decompressed bytes and refuse once the request budget is exceeded.
	 *
	 * @param string $fileName File name
	 * @param string $xml      Decompressed content
	 * @return bool            False if over budget
	 */
	private function checkTotal($fileName, $xml)
	{
		$this->totalSize += strlen($xml);
		if ($this->totalSize > self::MAX_TOTAL_SIZE) {
			$this->errors[] = array('err_total', $fileName, self::MAX_TOTAL_SIZE / 1048576);
			return false;
		}
		return true;
	}

	/**
	 * Parse one DMARC XML document.
	 *
	 * @param string $name File name
	 * @param string $xml  XML content
	 * @return array|null  Report or null on error
	 */
	public function parseXml($name, $xml)
	{
		// DMARC reports never need a DTD: refusing it blocks XXE and entity expansion attacks
		if (stripos($xml, '<!DOCTYPE') !== false || stripos($xml, '<!ENTITY') !== false) {
			$this->errors[] = array('err_doctype', $name);
			return null;
		}

		$prev = libxml_use_internal_errors(true);
		$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOCDATA | LIBXML_COMPACT);
		libxml_clear_errors();
		libxml_use_internal_errors($prev);

		if ($doc === false) {
			$this->errors[] = array('err_xml', $name);
			return null;
		}
		if ($doc->getName() !== 'feedback') {
			$this->errors[] = array('err_not_dmarc', $name, $doc->getName());
			return null;
		}
		// Some reporters use a namespace (DMARC v2 drafts): strip it by re-reading children without prefix
		$ns = $doc->getNamespaces();
		if (!empty($ns[''])) {
			$doc = $doc->children($ns['']);
		}

		$meta = $doc->report_metadata;
		$pol = $doc->policy_published;

		$report = array(
			'file' => $name,
			'org' => $this->s($meta->org_name),
			'email' => $this->s($meta->email),
			'id' => $this->s($meta->report_id),
			'begin' => (int) $meta->date_range->begin,
			'end' => (int) $meta->date_range->end,
			'metaErrors' => array(),
			'policy' => array(
				'domain' => strtolower($this->s($pol->domain)),
				'adkim' => $this->s($pol->adkim) ?: 'r',
				'aspf' => $this->s($pol->aspf) ?: 'r',
				'p' => $this->s($pol->p),
				'sp' => $this->s($pol->sp),
				'pct' => $this->s($pol->pct) !== '' ? $this->s($pol->pct) : '100',
				'fo' => $this->s($pol->fo),
			),
			'records' => array(),
		);
		foreach ($meta->error as $e) {
			$report['metaErrors'][] = $this->s($e);
		}

		foreach ($doc->record as $rec) {
			$row = $rec->row;
			$pe = $row->policy_evaluated;
			$id = $rec->identifiers;

			$record = array(
				'ip' => $this->s($row->source_ip),
				'count' => (int) $row->count,
				'disposition' => $this->s($pe->disposition) ?: 'none',
				'dkim' => $this->s($pe->dkim),
				'spf' => $this->s($pe->spf),
				'reasons' => array(),
				'headerFrom' => strtolower($this->s($id->header_from)),
				'envelopeFrom' => strtolower($this->s($id->envelope_from)),
				'envelopeTo' => strtolower($this->s($id->envelope_to)),
				'authDkim' => array(),
				'authSpf' => array(),
			);
			foreach ($pe->reason as $reason) {
				$record['reasons'][] = trim($this->s($reason->type).' '.$this->s($reason->comment));
			}
			foreach ($rec->auth_results->dkim as $d) {
				$record['authDkim'][] = array(
					'domain' => strtolower($this->s($d->domain)),
					'selector' => $this->s($d->selector),
					'result' => $this->s($d->result),
				);
			}
			foreach ($rec->auth_results->spf as $s) {
				$record['authSpf'][] = array(
					'domain' => strtolower($this->s($s->domain)),
					'scope' => $this->s($s->scope) ?: 'mfrom',
					'result' => $this->s($s->result),
				);
			}
			$record['pass'] = ($record['dkim'] === 'pass' || $record['spf'] === 'pass');
			$report['records'][] = $record;
		}

		return $report;
	}

	/**
	 * @param SimpleXMLElement|null $node Node
	 * @return string Trimmed string value
	 */
	private function s($node)
	{
		return $node === null ? '' : trim((string) $node);
	}
}
