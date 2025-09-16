"""
Web Protection Module
Real-time web browsing protection, URL filtering, and phishing detection
"""
import os
import re
import socket
import ssl
import urllib.parse
import hashlib
import json
import sqlite3
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import logging
from pathlib import Path
import dns.resolver
import requests
from bs4 import BeautifulSoup
import threading
import queue

class WebProtection:
    """Comprehensive web protection system"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.logger = logging.getLogger(__name__)
        self.config = config or {}
        
        # Protection components
        self.url_filter = URLFilter()
        self.phishing_detector = PhishingDetector()
        self.malicious_script_detector = MaliciousScriptDetector()
        self.ssl_inspector = SSLInspector()
        self.download_scanner = DownloadScanner()
        self.browser_protection = BrowserProtection()
        
        # Categories and policies
        self.blocked_categories = self.config.get('blocked_categories', [
            'malware', 'phishing', 'adult', 'gambling', 'violence'
        ])
        
        # Real-time protection
        self.is_active = False
        self.proxy_server = None
        
        # Initialize database
        self.init_database()
    
    def init_database(self):
        """Initialize web protection database"""
        self.db_path = "data/web_protection.db"
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # URL reputation database
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS url_reputation (
                url TEXT PRIMARY KEY,
                category TEXT,
                reputation_score INTEGER,
                is_malicious BOOLEAN,
                phishing_score REAL,
                last_checked DATE,
                metadata TEXT
            )
        ''')
        
        # Blocked URLs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_urls (
                url TEXT PRIMARY KEY,
                reason TEXT,
                blocked_date DATE,
                category TEXT
            )
        ''')
        
        # Domain reputation
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domain_reputation (
                domain TEXT PRIMARY KEY,
                reputation INTEGER,
                category TEXT,
                is_parked BOOLEAN,
                is_new BOOLEAN,
                last_checked DATE
            )
        ''')
        
        # Phishing signatures
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS phishing_signatures (
                signature_id TEXT PRIMARY KEY,
                pattern TEXT,
                target_brand TEXT,
                confidence REAL,
                created_date DATE
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Load phishing signatures
        self.load_phishing_signatures()
    
    def load_phishing_signatures(self):
        """Load phishing detection signatures"""
        signatures = [
            {
                'id': 'phish_001',
                'pattern': r'(paypal|ebay|amazon|bank)\.(tk|ml|ga|cf)',
                'target': 'Major Brands',
                'confidence': 0.95
            },
            {
                'id': 'phish_002',
                'pattern': r'secure.*verification.*account',
                'target': 'Account Phishing',
                'confidence': 0.85
            },
            {
                'id': 'phish_003',
                'pattern': r'suspended.*account.*verify',
                'target': 'Account Suspension',
                'confidence': 0.90
            }
        ]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for sig in signatures:
            cursor.execute('''
                INSERT OR IGNORE INTO phishing_signatures
                (signature_id, pattern, target_brand, confidence, created_date)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                sig['id'],
                sig['pattern'],
                sig['target'],
                sig['confidence'],
                datetime.now().isoformat()
            ))
        
        conn.commit()
        conn.close()
    
    def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL for threats"""
        result = {
            'url': url,
            'is_safe': True,
            'is_blocked': False,
            'category': 'unknown',
            'threats': [],
            'reputation_score': 100,
            'ssl_valid': True
        }
        
        try:
            # Parse URL
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc
            
            # Check URL reputation
            reputation = self.check_url_reputation(url)
            result['reputation_score'] = reputation.get('score', 100)
            
            if reputation.get('is_malicious'):
                result['is_safe'] = False
                result['threats'].append('malicious_url')
            
            # Check domain reputation
            domain_rep = self.check_domain_reputation(domain)
            if domain_rep.get('is_suspicious'):
                result['is_safe'] = False
                result['threats'].append('suspicious_domain')
            
            # Check for phishing
            phishing_result = self.phishing_detector.check_url(url)
            if phishing_result.get('is_phishing'):
                result['is_safe'] = False
                result['threats'].append('phishing')
                result['phishing_details'] = phishing_result
            
            # Check URL category
            category = self.url_filter.categorize_url(url)
            result['category'] = category
            
            if category in self.blocked_categories:
                result['is_blocked'] = True
                result['block_reason'] = f'Category blocked: {category}'
            
            # SSL/TLS validation for HTTPS
            if parsed.scheme == 'https':
                ssl_result = self.ssl_inspector.validate_certificate(domain)
                result['ssl_valid'] = ssl_result.get('valid', True)
                if not result['ssl_valid']:
                    result['threats'].append('invalid_certificate')
            
            # Check for malicious redirects
            if self.has_malicious_redirects(url):
                result['is_safe'] = False
                result['threats'].append('malicious_redirect')
            
            # Check for exploit kits
            if self.detect_exploit_kit(url):
                result['is_safe'] = False
                result['threats'].append('exploit_kit')
                
        except Exception as e:
            self.logger.error(f"Error checking URL {url}: {e}")
            result['error'] = str(e)
        
        # Log blocked URLs
        if result['is_blocked'] or not result['is_safe']:
            self.log_blocked_url(url, result)
        
        return result
    
    def check_url_reputation(self, url: str) -> Dict[str, Any]:
        """Check URL reputation in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT reputation_score, is_malicious, category, metadata
            FROM url_reputation
            WHERE url = ?
        ''', (url,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'score': result[0],
                'is_malicious': bool(result[1]),
                'category': result[2],
                'metadata': json.loads(result[3]) if result[3] else {}
            }
        
        # If not in database, check with cloud service
        return self.query_cloud_reputation(url)
    
    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation"""
        reputation = {
            'domain': domain,
            'is_suspicious': False,
            'reasons': []
        }
        
        try:
            # Check domain age
            domain_age = self.get_domain_age(domain)
            if domain_age and domain_age.days < 30:
                reputation['is_suspicious'] = True
                reputation['reasons'].append('newly_registered_domain')
            
            # Check for typosquatting
            if self.is_typosquatting(domain):
                reputation['is_suspicious'] = True
                reputation['reasons'].append('typosquatting')
            
            # Check for homograph attacks
            if self.has_homograph_characters(domain):
                reputation['is_suspicious'] = True
                reputation['reasons'].append('homograph_attack')
            
            # Check DNS records
            dns_check = self.check_dns_records(domain)
            if dns_check.get('suspicious'):
                reputation['is_suspicious'] = True
                reputation['reasons'].extend(dns_check.get('reasons', []))
            
            # Check if domain is parked
            if self.is_parked_domain(domain):
                reputation['reasons'].append('parked_domain')
                
        except Exception as e:
            self.logger.debug(f"Domain reputation check error: {e}")
        
        return reputation
    
    def query_cloud_reputation(self, url: str) -> Dict[str, Any]:
        """Query cloud service for URL reputation"""
        # In production, would query actual threat intelligence service
        # Simulated response
        import random
        
        score = random.randint(0, 100)
        is_malicious = score < 30
        
        return {
            'score': score,
            'is_malicious': is_malicious,
            'category': 'malware' if is_malicious else 'unknown'
        }
    
    def has_malicious_redirects(self, url: str) -> bool:
        """Check for malicious redirect chains"""
        try:
            # Follow redirects and check each hop
            session = requests.Session()
            session.max_redirects = 10
            
            response = session.head(url, allow_redirects=True, timeout=5)
            
            # Check redirect chain
            if len(response.history) > 5:
                return True  # Too many redirects
            
            for redirect in response.history:
                redirect_url = redirect.headers.get('Location', '')
                
                # Check if redirect goes to suspicious domain
                parsed = urllib.parse.urlparse(redirect_url)
                if self.is_suspicious_redirect(parsed.netloc):
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def detect_exploit_kit(self, url: str) -> bool:
        """Detect exploit kit landing pages"""
        try:
            # Fetch page content
            response = requests.get(url, timeout=5)
            content = response.text
            
            # Check for exploit kit indicators
            exploit_indicators = [
                r'<iframe.*hidden.*src=',
                r'eval\(unescape\(',
                r'document\.write\(unescape\(',
                r'String\.fromCharCode\([0-9,\s]+\)',
                r'<script>.*obfuscated.*</script>',
                r'ActiveXObject.*Shell\.Application'
            ]
            
            for pattern in exploit_indicators:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
            
            # Check for suspicious JavaScript
            if self.malicious_script_detector.scan_content(content):
                return True
                
        except Exception:
            pass
        
        return False
    
    def get_domain_age(self, domain: str) -> Optional[timedelta]:
        """Get domain registration age"""
        try:
            import whois
            
            w = whois.whois(domain)
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                return datetime.now() - creation_date
                
        except Exception:
            pass
        
        return None
    
    def is_typosquatting(self, domain: str) -> bool:
        """Check for typosquatting attempts"""
        legitimate_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'paypal.com', 'ebay.com', 'netflix.com',
            'twitter.com', 'instagram.com', 'linkedin.com'
        ]
        
        domain_lower = domain.lower()
        
        for legit in legitimate_domains:
            # Check Levenshtein distance
            if self.levenshtein_distance(domain_lower, legit) <= 2:
                if domain_lower != legit:
                    return True
        
        return False
    
    def has_homograph_characters(self, domain: str) -> bool:
        """Check for homograph attacks using similar-looking characters"""
        # Check for mix of scripts (Latin + Cyrillic, etc.)
        scripts = set()
        
        for char in domain:
            if 'a' <= char <= 'z' or 'A' <= char <= 'Z':
                scripts.add('latin')
            elif '\u0400' <= char <= '\u04FF':
                scripts.add('cyrillic')
            elif '\u0370' <= char <= '\u03FF':
                scripts.add('greek')
        
        # Mixed scripts are suspicious
        return len(scripts) > 1
    
    def check_dns_records(self, domain: str) -> Dict[str, Any]:
        """Check DNS records for suspicious patterns"""
        result = {
            'suspicious': False,
            'reasons': []
        }
        
        try:
            # Check A records
            a_records = dns.resolver.resolve(domain, 'A')
            
            for rdata in a_records:
                ip = str(rdata)
                
                # Check if IP is in suspicious ranges
                if self.is_suspicious_ip(ip):
                    result['suspicious'] = True
                    result['reasons'].append(f'suspicious_ip: {ip}')
            
            # Check MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                if not mx_records:
                    result['reasons'].append('no_mx_records')
            except:
                pass
                
        except Exception:
            result['reasons'].append('dns_resolution_failed')
        
        return result
    
    def is_parked_domain(self, domain: str) -> bool:
        """Check if domain is parked"""
        try:
            response = requests.get(f'http://{domain}', timeout=5)
            content = response.text.lower()
            
            parking_indicators = [
                'domain for sale',
                'this domain is parked',
                'buy this domain',
                'domain parking',
                'under construction'
            ]
            
            return any(indicator in content for indicator in parking_indicators)
            
        except Exception:
            pass
        
        return False
    
    def is_suspicious_redirect(self, domain: str) -> bool:
        """Check if redirect destination is suspicious"""
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
        
        return any(domain.endswith(tld) for tld in suspicious_tlds)
    
    def is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is in suspicious ranges"""
        suspicious_ranges = [
            '10.0.0.0/8',     # Private
            '172.16.0.0/12',  # Private
            '192.168.0.0/16', # Private
        ]
        
        # In production, would check against threat intelligence
        return False
    
    def levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between strings"""
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            
            previous_row = current_row
        
        return previous_row[-1]
    
    def log_blocked_url(self, url: str, result: Dict[str, Any]):
        """Log blocked URL to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            reason = result.get('block_reason', 'threat_detected')
            if result.get('threats'):
                reason = f"Threats: {', '.join(result['threats'])}"
            
            cursor.execute('''
                INSERT OR REPLACE INTO blocked_urls
                (url, reason, blocked_date, category)
                VALUES (?, ?, ?, ?)
            ''', (
                url,
                reason,
                datetime.now().isoformat(),
                result.get('category', 'unknown')
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to log blocked URL: {e}")


class URLFilter:
    """URL categorization and filtering"""
    
    def categorize_url(self, url: str) -> str:
        """Categorize URL based on content and patterns"""
        # In production, would use ML model or cloud service
        # Simple pattern-based categorization
        
        categories = {
            'adult': ['porn', 'xxx', 'adult', 'sex'],
            'gambling': ['casino', 'poker', 'betting', 'lottery'],
            'malware': ['malware', 'virus', 'trojan'],
            'phishing': ['phishing', 'scam'],
            'social': ['facebook', 'twitter', 'instagram'],
            'shopping': ['amazon', 'ebay', 'shop'],
            'news': ['news', 'cnn', 'bbc'],
            'education': ['edu', 'school', 'university']
        }
        
        url_lower = url.lower()
        
        for category, keywords in categories.items():
            if any(keyword in url_lower for keyword in keywords):
                return category
        
        return 'uncategorized'


class PhishingDetector:
    """Advanced phishing detection"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.legitimate_brands = [
            'paypal', 'amazon', 'ebay', 'microsoft', 'google',
            'apple', 'facebook', 'netflix', 'bank'
        ]
    
    def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL for phishing indicators"""
        result = {
            'is_phishing': False,
            'confidence': 0.0,
            'indicators': [],
            'target_brand': None
        }
        
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            
            # Check for brand impersonation
            impersonation = self.check_brand_impersonation(domain, path)
            if impersonation['is_impersonation']:
                result['is_phishing'] = True
                result['target_brand'] = impersonation['brand']
                result['indicators'].append('brand_impersonation')
                result['confidence'] = max(result['confidence'], 0.8)
            
            # Check for suspicious URL patterns
            if self.has_suspicious_patterns(url):
                result['indicators'].append('suspicious_url_pattern')
                result['confidence'] = max(result['confidence'], 0.6)
            
            # Check for URL shorteners
            if self.is_url_shortener(domain):
                result['indicators'].append('url_shortener')
                result['confidence'] = max(result['confidence'], 0.4)
            
            # Check page content if possible
            page_check = self.check_page_content(url)
            if page_check['is_phishing']:
                result['is_phishing'] = True
                result['indicators'].extend(page_check['indicators'])
                result['confidence'] = max(result['confidence'], page_check['confidence'])
            
            # Determine if phishing based on confidence
            if result['confidence'] >= 0.7:
                result['is_phishing'] = True
                
        except Exception as e:
            self.logger.debug(f"Phishing check error: {e}")
        
        return result
    
    def check_brand_impersonation(self, domain: str, path: str) -> Dict[str, Any]:
        """Check for brand impersonation attempts"""
        result = {
            'is_impersonation': False,
            'brand': None
        }
        
        domain_lower = domain.lower()
        
        for brand in self.legitimate_brands:
            # Check if brand name is in domain but not legitimate
            if brand in domain_lower:
                legitimate_domains = self.get_legitimate_domains(brand)
                
                if domain not in legitimate_domains:
                    result['is_impersonation'] = True
                    result['brand'] = brand
                    break
        
        return result
    
    def has_suspicious_patterns(self, url: str) -> bool:
        """Check for suspicious URL patterns"""
        suspicious_patterns = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP address
            r'@',  # @ symbol in URL
            r'-{2,}',  # Multiple hyphens
            r'[0-9]{5,}',  # Long number sequences
            r'(verify|confirm|update|secure|account|suspended)',  # Phishing keywords
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        return False
    
    def is_url_shortener(self, domain: str) -> bool:
        """Check if domain is a URL shortener"""
        shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
            'short.link', 'ow.ly', 'is.gd', 'buff.ly'
        ]
        
        return domain in shorteners
    
    def check_page_content(self, url: str) -> Dict[str, Any]:
        """Analyze page content for phishing indicators"""
        result = {
            'is_phishing': False,
            'indicators': [],
            'confidence': 0.0
        }
        
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for password fields
            password_fields = soup.find_all('input', {'type': 'password'})
            if password_fields:
                result['indicators'].append('password_field')
                
                # Check if legitimate login page
                if not self.is_legitimate_login(url):
                    result['confidence'] = max(result['confidence'], 0.7)
            
            # Check for urgency indicators
            text_content = soup.get_text().lower()
            urgency_phrases = [
                'urgent', 'immediate action', 'account suspended',
                'verify now', 'limited time', 'act now'
            ]
            
            for phrase in urgency_phrases:
                if phrase in text_content:
                    result['indicators'].append('urgency_indicator')
                    result['confidence'] = max(result['confidence'], 0.5)
            
            # Check for data harvesting forms
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input')
                sensitive_fields = ['ssn', 'credit', 'card', 'cvv', 'pin']
                
                for input_field in inputs:
                    field_name = input_field.get('name', '').lower()
                    if any(sensitive in field_name for sensitive in sensitive_fields):
                        result['indicators'].append('sensitive_data_form')
                        result['confidence'] = max(result['confidence'], 0.8)
            
            if result['confidence'] >= 0.7:
                result['is_phishing'] = True
                
        except Exception:
            pass
        
        return result
    
    def get_legitimate_domains(self, brand: str) -> List[str]:
        """Get legitimate domains for a brand"""
        legitimate = {
            'paypal': ['paypal.com', 'www.paypal.com'],
            'amazon': ['amazon.com', 'www.amazon.com', 'amazon.co.uk'],
            'microsoft': ['microsoft.com', 'login.microsoftonline.com'],
            'google': ['google.com', 'accounts.google.com'],
            'apple': ['apple.com', 'icloud.com'],
            'facebook': ['facebook.com', 'www.facebook.com'],
            'bank': []  # Would include actual bank domains
        }
        
        return legitimate.get(brand, [])
    
    def is_legitimate_login(self, url: str) -> bool:
        """Check if URL is a legitimate login page"""
        legitimate_login_urls = [
            'accounts.google.com',
            'login.microsoftonline.com',
            'signin.aws.amazon.com',
            'github.com/login'
        ]
        
        return any(legit in url for legit in legitimate_login_urls)


class MaliciousScriptDetector:
    """Detect malicious JavaScript and other scripts"""
    
    def scan_content(self, content: str) -> bool:
        """Scan content for malicious scripts"""
        malicious_patterns = [
            r'eval\s*\([^)]+\)',  # eval() usage
            r'document\.write\s*\([^)]+\)',  # document.write
            r'unescape\s*\([^)]+\)',  # unescape (often used in obfuscation)
            r'String\.fromCharCode',  # Character code obfuscation
            r'atob\s*\([^)]+\)',  # Base64 decoding
            r'<script[^>]*src=["\']data:',  # Data URI scripts
        ]
        
        for pattern in malicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False


class SSLInspector:
    """SSL/TLS certificate validation"""
    
    def validate_certificate(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """Validate SSL certificate"""
        result = {
            'valid': True,
            'issues': [],
            'certificate_info': {}
        }
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    not_after = datetime.strptime(
                        cert['notAfter'], 
                        '%b %d %H:%M:%S %Y %Z'
                    )
                    
                    if not_after < datetime.now():
                        result['valid'] = False
                        result['issues'].append('expired_certificate')
                    
                    # Check subject alternative names
                    san = cert.get('subjectAltName', [])
                    valid_for_domain = any(
                        domain == name[1] or 
                        (name[1].startswith('*.') and domain.endswith(name[1][2:]))
                        for name in san
                    )
                    
                    if not valid_for_domain:
                        result['valid'] = False
                        result['issues'].append('domain_mismatch')
                    
                    result['certificate_info'] = {
                        'issuer': dict(cert.get('issuer', [])),
                        'subject': dict(cert.get('subject', [])),
                        'not_after': not_after.isoformat(),
                        'san': [name[1] for name in san]
                    }
                    
        except ssl.SSLError as e:
            result['valid'] = False
            result['issues'].append(f'ssl_error: {e}')
        except Exception as e:
            result['valid'] = False
            result['issues'].append(f'validation_error: {e}')
        
        return result


class DownloadScanner:
    """Scan downloaded files for threats"""
    
    def scan_download(self, file_path: str, source_url: str) -> Dict[str, Any]:
        """Scan downloaded file"""
        # Would integrate with main scanner
        return {
            'file': file_path,
            'source': source_url,
            'is_safe': True,
            'threats': []
        }


class BrowserProtection:
    """Browser-specific protection"""
    
    def __init__(self):
        self.browser_extensions = []
        
    def install_extension(self, browser: str):
        """Install browser extension for protection"""
        # Would install browser-specific extension
        pass
    
    def block_malicious_extension(self, extension_id: str):
        """Block malicious browser extension"""
        pass