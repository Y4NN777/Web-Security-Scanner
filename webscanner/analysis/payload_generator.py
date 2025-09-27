
from typing import List

class PayloadGenerator:
	"""Generates payloads for vulnerability testing."""
	def __init__(self):
		self.base_payloads = [
			"' OR '1'='1",
			'" OR "1"="1',
			'<script>alert(1)</script>',
			'test@example.com',
			'123-45-6789',
		]

	def generate(self, encoding: str = 'none') -> List[str]:
		"""Generate payloads with specified encoding."""
		if encoding == 'none':
			return self.base_payloads
		elif encoding == 'single':
			return [self._url_encode(p) for p in self.base_payloads]
		elif encoding == 'double':
			return [self._url_encode(self._url_encode(p)) for p in self.base_payloads]
		elif encoding == 'html':
			return [self._html_encode(p) for p in self.base_payloads]
		elif encoding == 'unicode':
			return [self._unicode_encode(p) for p in self.base_payloads]
		else:
			return self.base_payloads

	def _url_encode(self, payload: str) -> str:
		from urllib.parse import quote
		return quote(payload)

	def _html_encode(self, payload: str) -> str:
		import html
		return html.escape(payload)

	def _unicode_encode(self, payload: str) -> str:
		return ''.join(f'\\u{ord(c):04x}' for c in payload)
