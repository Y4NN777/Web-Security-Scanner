
import json
from typing import Dict, Any

class ConfigManager:
	"""Handles loading and saving scanner configuration."""
	def __init__(self, config_path: str = None):
		self.config_path = config_path
		self.config = {}
		if config_path:
			self.load(config_path)

	def load(self, path: str) -> Dict[str, Any]:
		with open(path, 'r') as f:
			self.config = json.load(f)
		return self.config

	def save(self, path: str = None):
		path = path or self.config_path
		if not path:
			raise ValueError("No config path specified")
		with open(path, 'w') as f:
			json.dump(self.config, f, indent=2)
