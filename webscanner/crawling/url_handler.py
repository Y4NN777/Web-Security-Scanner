# URL normalization & encoding
import urllib.parse
from typing import List, Dict, Set
import re

class URLHAndler:
    """Class for handling URL normalization and encoding.
    """

    def __init__(self):
        self.encoding_variations =[
            "none",   # No encoding
            "single", # Single URL encoding %27
            "double", # Double URL encoding %2527
            "html", # HTML entities &#x27
            "unicode", #Unicode
        ]

    def normalize_url(self, url: str) -> str:
        """Normalize a URL by removing fragments and redundant slashes."""
       
        try:
            parsed = urllib.parse.urlparse(url)
            # Normalize scheme and netloc to lowercase
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            
            # Decode and re-encode path consistently
            path = urllib.parse.unquote(parsed.path)
            path = urllib.parse.quote(path, safe='/')
            
            # Sort query parameters for consistency
            if parsed.query:
                params = urllib.parse.parse_qs(parsed.query)
                sorted_params = []
                for key in sorted(params.keys()):
                    for value in params[key]:
                        sorted_params.append(f"{key}={value}")
                query = '&'.join(sorted_params)
            else:
                query = parsed.query
            
            return urllib.parse.urlunparse((scheme, netloc, path, parsed.params, query, parsed.fragment))
            
        except Exception as e:
            print(f"Error normalizing URL {url}: {e}")
            return url
    
    def extract_parameters(self, url: str) -> Dict[str, List[str]]:
        """Extract all parameters from URL with proper decoding"""
        parameters = {}
        
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.query:
                params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                for key, values in params.items():
                    decoded_key = urllib.parse.unquote_plus(key)
                    decoded_values = [urllib.parse.unquote_plus(v) for v in values]
                    parameters[decoded_key] = decoded_values
        except Exception as e:
            print(f"Error extracting parameters: {e}")
        
        return parameters
    
    def generate_payload_variations(self, payload: str) -> List[Dict[str, str]]:
        """Generate multiple encoded variations of a payload"""
        variations = []
        
        # Original payload
        variations.append({'payload': payload, 'encoding': 'none'})
        
        # Single URL encoding
        single_encoded = urllib.parse.quote(payload, safe='')
        variations.append({'payload': single_encoded, 'encoding': 'single'})
        
        # Double URL encoding
        double_encoded = urllib.parse.quote(single_encoded, safe='')
        variations.append({'payload': double_encoded, 'encoding': 'double'})
        
        # HTML entity encoding
        html_encoded = ''.join([f'&#{ord(c)};' for c in payload])
        variations.append({'payload': html_encoded, 'encoding': 'html'})
        
        # Unicode encoding
        unicode_encoded = ''.join([f'\\u{ord(c):04x}' for c in payload])
        variations.append({'payload': unicode_encoded, 'encoding': 'unicode'})
        
        return variations
    
    def build_test_url(self, base_url: str, param_name: str, payload: str) -> str:
        """Build test URL with payload in specified parameter"""
        try:
            parsed = urllib.parse.urlparse(base_url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            
            # Update parameter with payload
            params[param_name] = [payload]
            
            # Rebuild query string
            new_query = urllib.parse.urlencode(params, doseq=True)
            
            # Reconstruct URL
            return urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
        except Exception as e:
            print(f"Error building test URL: {e}")
            return base_url