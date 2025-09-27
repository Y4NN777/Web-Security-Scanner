
from .detector_base import DetectorBase
from typing import List, Dict
import re

class InfoDetector(DetectorBase):
	"""Detects sensitive information exposure in HTTP responses."""
	SENSITIVE_PATTERNS = {
		'email': r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
		'credit_card': r'\b(?:\d[ -]*?){13,16}\b',
		'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
		'api_key': r'(?:api[_-]?key|secret|token)["\'=:\s]+[a-zA-Z0-9]{16,}'
	}

	def detect(self, page_data: Dict) -> List[Dict]:
		response_text = page_data.get('response', '')
		url = page_data.get('url', '')
		found = []
		for label, pattern in self.SENSITIVE_PATTERNS.items():
			matches = re.findall(pattern, response_text)
			for match in matches:
				found.append(self.create_vulnerability(
					vuln_type='SensitiveInfo',
					url=url,
					info_type=label,
					evidence=match,
					severity='high',
					confidence=0.8
				))
		return found
