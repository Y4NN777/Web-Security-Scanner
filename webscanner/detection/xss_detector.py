
from .detector_base import DetectorBase
from ..crawling.url_handler import URLHandler
from ..analysis.response_analyzer import ResponseAnalyzer
from typing import List, Dict
import html

class XSSDetector(DetectorBase):
	"""Detects reflected and stored XSS vulnerabilities."""
	XSS_PAYLOADS = [
		'<script>alert(1)</script>',
		'" onmouseover="alert(1)',
		"'><img src=x onerror=alert(1)>",
		'<svg/onload=alert(1)>',
		'javascript:alert(1)'
	]

	def __init__(self, session, config=None):
		super().__init__(session, config)
		self.url_handler = URLHandler()
		self.response_analyzer = ResponseAnalyzer()

	def detect(self, page_data: Dict) -> List[Dict]:
		url = page_data.get('url', '')
		response = page_data.get('response', '')
		found = []
		for payload in self.XSS_PAYLOADS:
			if payload in response or html.escape(payload) in response:
				found.append(self.create_vulnerability(
					vuln_type='XSS',
					url=url,
					payload=payload,
					severity='high',
					confidence=0.9
				))
		return found
