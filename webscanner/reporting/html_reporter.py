
from typing import List, Dict

class HTMLReporter:
	"""Generates an HTML report from vulnerability data."""

	def generate(self, vulnerabilities: List[Dict], output_path: str = None) -> str:
		html = [
			'<!DOCTYPE html>',
			'<html lang="en">',
			'<head>',
			'<meta charset="UTF-8">',
			'<title>Web Security Scan Report</title>',
			'<style>body{font-family:sans-serif;} table{border-collapse:collapse;width:100%;} th,td{border:1px solid #ccc;padding:8px;} th{background:#eee;} tr.high{background:#fdd;} tr.medium{background:#ffd;} tr.low{background:#dfd;}</style>',
			'</head>',
			'<body>',
			'<h1>Web Security Scan Report</h1>',
			'<table>',
			'<tr><th>Type</th><th>URL</th><th>Severity</th><th>Confidence</th><th>Evidence</th><th>Timestamp</th></tr>'
		]
		for vuln in vulnerabilities:
			severity = vuln.get('severity', 'medium')
			html.append(f'<tr class="{severity}"><td>{vuln.get("type")}</td><td>{vuln.get("url","")}</td><td>{severity}</td><td>{vuln.get("confidence","")}</td><td>{vuln.get("evidence","")}</td><td>{vuln.get("timestamp","")}</td></tr>')
		html += ['</table>', '</body>', '</html>']
		result = '\n'.join(html)
		if output_path:
			with open(output_path, 'w', encoding='utf-8') as f:
				f.write(result)
		return result
