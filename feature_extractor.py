import re
import socket
import logging
import requests
import tldextract
import whois
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

# Configure logging
logger = logging.getLogger(__name__)

# List of TLDs commonly associated with phishing
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.info', '.xyz', '.top', '.work', '.date']

# List of keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'secure', 'account', 'login', 'signin', 'verify', 'banking', 'update', 'confirm',
    'password', 'credential', 'wallet', 'authenticate', 'recovery', 'suspend'
]

def extract_features(url):
    """
    Extract various features from a URL for phishing detection.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Dictionary of extracted features
    """
    try:
        parsed_url = urlparse(url)
        extracted = tldextract.extract(url)
        
        # Basic URL features
        features = {
            'url': url,
            'domain': extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain,
            'subdomain': extracted.subdomain,
            'path': parsed_url.path,
            'tld': '.' + extracted.suffix if extracted.suffix else '',
            'url_length': len(url),
            'num_subdomains': len(extracted.subdomain.split('.')) if extracted.subdomain else 0,
            'has_at_symbol': '@' in url,
            'has_ip_address': is_ip_address(extracted.domain),
            'has_suspicious_tld': any(tld in url.lower() for tld in SUSPICIOUS_TLDS),
            'uses_https': parsed_url.scheme == 'https',
            'path_length': len(parsed_url.path),
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_underscores': url.count('_'),
            'has_suspicious_words': any(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS),
            'domain_age': get_domain_age(extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain),
        }
        
        # Additional features that require making a request to the website
        try:
            # Try to get more information from the website
            site_features = get_site_features(url)
            features.update(site_features)
        except Exception as e:
            # If we can't access the site, log the error and proceed with basic features
            logger.warning(f"Couldn't get site-based features for {url}: {e}")
            features.update({
                'has_form': False,
                'has_password_field': False,
                'has_suspicious_redirects': False,
                'external_resources_ratio': 0,
                'favicon_domain_match': False,
                'has_suspicious_scripts': False
            })
        
        return features
        
    except Exception as e:
        logger.error(f"Error extracting features from URL {url}: {e}", exc_info=True)
        # Return basic features with default values if extraction fails
        return {
            'url': url,
            'domain': '',
            'url_length': len(url),
            'has_at_symbol': '@' in url,
            'has_ip_address': False,
            'has_suspicious_tld': False,
            'uses_https': url.startswith('https://'),
            'domain_age': 0,
            'has_form': False,
            'has_password_field': False,
            'has_suspicious_redirects': False,
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'has_suspicious_words': False,
        }

def is_ip_address(domain):
    """Check if a string is a valid IP address."""
    try:
        socket.inet_aton(domain)
        return True
    except:
        return False

def get_domain_age(domain):
    """
    Get the age of a domain in days.
    
    Args:
        domain (str): The domain name
        
    Returns:
        int: Age in days, or 0 if can't determine
    """
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        
        # Handle different return types (could be a list or a single datetime)
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            days_since_creation = (datetime.now() - creation_date).days
            return max(0, days_since_creation)  # Ensure non-negative
        return 0
    except Exception as e:
        logger.warning(f"Couldn't get domain age for {domain}: {e}")
        return 0  # Default to 0 days (treat as new domain) if we can't determine

def get_site_features(url):
    """
    Extract features from the website content.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Dictionary of site-based features
    """
    features = {}
    
    try:
        # Set a timeout to avoid hanging on slow/non-responsive sites
        response = requests.get(url, timeout=5, allow_redirects=False)
        
        # Check for redirects
        features['has_suspicious_redirects'] = (
            response.status_code in [301, 302, 303, 307, 308] and
            urlparse(url).netloc != urlparse(response.headers.get('Location', '')).netloc
        )
        
        # Parse the HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for forms and password fields
        forms = soup.find_all('form')
        features['has_form'] = len(forms) > 0
        features['has_password_field'] = len(soup.find_all('input', {'type': 'password'})) > 0
        
        # Check external resources
        all_resources = soup.find_all(['script', 'link', 'img', 'iframe'])
        external_resources = [
            r for r in all_resources 
            if r.get('src') and urlparse(r.get('src')).netloc and 
            urlparse(r.get('src')).netloc != urlparse(url).netloc
        ]
        
        features['external_resources_ratio'] = (
            len(external_resources) / len(all_resources) if all_resources else 0
        )
        
        # Check if favicon matches domain
        favicon_link = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
        if favicon_link and favicon_link.get('href'):
            favicon_domain = urlparse(favicon_link['href']).netloc
            features['favicon_domain_match'] = (
                not favicon_domain or  # Relative path
                favicon_domain == urlparse(url).netloc  # Same domain
            )
        else:
            features['favicon_domain_match'] = True  # No favicon, so no mismatch
        
        # Check for suspicious scripts (obfuscated or with suspicious patterns)
        script_tags = soup.find_all('script')
        suspicious_patterns = [
            r'(document\.location|window\.location)\s*=',
            r'eval\(.*\)',
            r'unescape\(.*\)',
            r'decodeURIComponent\(.*\)',
            r'document\.write\(.*\)',
            r'fromCharCode'
        ]
        
        suspicious_scripts = 0
        for script in script_tags:
            script_text = script.string if script.string else ""
            if any(re.search(pattern, script_text) for pattern in suspicious_patterns):
                suspicious_scripts += 1
        
        features['has_suspicious_scripts'] = suspicious_scripts > 0
        
        return features
    
    except RequestException as e:
        logger.warning(f"Error accessing {url}: {e}")
        # Return default values if we can't access the site
        return {
            'has_form': False,
            'has_password_field': False,
            'has_suspicious_redirects': False,
            'external_resources_ratio': 0,
            'favicon_domain_match': False,
            'has_suspicious_scripts': False
        }
