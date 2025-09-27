# URL discovery &import requests
from bs4 import BeautifulSoup
from typing import Set, Generator, Dict, List
import time
from .url_handler import URLHandler
import requests

class WebCrawler:
    """Enhanced web crawler with form detection and URL handling"""
    
    def __init__(self, session: requests.Session, config: Dict = None):
        self.session = session
        self.config = config or {}
        self.max_depth = self.config.get('max_depth', 3)
        self.delay = self.config.get('crawl_delay', 0.5)
        self.visited_urls: Set[str] = set()
        self.url_handler = URLHandler()
        
    def crawl(self, start_url: str) -> Generator[Dict, None, None]:
        """Crawl website and yield page data for testing"""
        normalized_start = self.url_handler.normalize_url(start_url)
        urls_to_visit = [(normalized_start, 0)]
        
        while urls_to_visit:
            url, depth = urls_to_visit.pop(0)
            
            if depth > self.max_depth or url in self.visited_urls:
                continue
            
            try:
                self.visited_urls.add(url)
                response = self._make_request(url)
                
                if response and response.status_code == 200:
                    # Extract forms for parameter testing
                    forms = self._extract_forms(response.text, url)
                    
                    # Extract URL parameters
                    url_params = self.url_handler.extract_parameters(url)
                    
                    yield {
                        'url': url,
                        'response': response,
                        'forms': forms,
                        'url_parameters': url_params,
                        'depth': depth,
                        'content_type': response.headers.get('content-type', '')
                    }
                    
                    # Find new URLs to crawl
                    if depth < self.max_depth:
                        new_urls = self._extract_links(url, response.text)
                        for new_url in new_urls:
                            normalized = self.url_handler.normalize_url(new_url)
                            if normalized not in self.visited_urls:
                                urls_to_visit.append((normalized, depth + 1))
                
                time.sleep(self.delay)  # Respectful crawling
                
            except Exception as e:
                print(f"Error crawling {url}: {e}")
    
    def _make_request(self, url: str) -> requests.Response:
        """Make HTTP request with error handling"""
        try:
            return self.session.get(url, timeout=self.config.get('timeout', 10), verify=False)
        except requests.RequestException as e:
            print(f"Request failed for {url}: {e}")
            return None
    
    def _extract_forms(self, html_content: str, base_url: str) -> List[Dict]:
        """Extract forms with all input fields"""
        forms = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': self._resolve_url(base_url, form.get('action', '')),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                # Extract all input types
                for input_elem in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'name': input_elem.get('name', ''),
                        'type': input_elem.get('type', 'text'),
                        'value': input_elem.get('value', ''),
                        'required': input_elem.has_attr('required')
                    }
                    
                    # Handle select options
                    if input_elem.name == 'select':
                        options = [opt.get('value', opt.get_text()) for opt in input_elem.find_all('option')]
                        input_data['options'] = options
                        if options and not input_data['value']:
                            input_data['value'] = options[0]
                    
                    if input_data['name']:  # Only include named inputs
                        form_data['inputs'].append(input_data)
                
                if form_data['inputs']:  # Only include forms with inputs
                    forms.append(form_data)
                    
        except Exception as e:
            print(f"Error extracting forms: {e}")
        
        return forms
    
    def _extract_links(self, base_url: str, html_content: str) -> Set[str]:
        """Extract links for further crawling"""
        links = set()
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract links from various elements
            for element in soup.find_all(['a', 'form'], href=True):
                href = element.get('href') or element.get('action')
                if href:
                    full_url = self._resolve_url(base_url, href)
                    if self._is_same_domain(base_url, full_url):
                        links.add(full_url)
                        
        except Exception as e:
            print(f"Error extracting links: {e}")
        
        return links
    
    def _resolve_url(self, base_url: str, relative_url: str) -> str:
        """Resolve relative URL to absolute"""
        import urllib.parse
        return urllib.parse.urljoin(base_url, relative_url)
    
    def _is_same_domain(self, base_url: str, test_url: str) -> bool:
        """Check if URLs are from same domain"""
        import urllib.parse
        base_domain = urllib.parse.urlparse(base_url).netloc
        test_domain = urllib.parse.urlparse(test_url).netloc
        return base_domain == test_domain
