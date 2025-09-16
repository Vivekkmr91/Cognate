"""
Data Leak Prevention (DLP) Module
Prevents unauthorized data exfiltration and protects sensitive information
"""
import re
import os
import json
import hashlib
import threading
from typing import List, Dict, Any, Set, Pattern
from datetime import datetime
import logging
from pathlib import Path
import mimetypes

class DataLeakPrevention:
    """DLP system to prevent sensitive data leakage"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.sensitive_patterns = self.compile_patterns()
        self.monitored_applications = set()
        self.blocked_transfers = []
        self.clipboard_monitor = ClipboardMonitor(self)
        self.usb_monitor = USBMonitor(self)
        self.network_monitor = NetworkDataMonitor(self)
        self.document_classifier = DocumentClassifier()
        
    def compile_patterns(self) -> Dict[str, Pattern]:
        """Compile regex patterns for sensitive data detection"""
        patterns = {
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'phone': re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
            'api_key': re.compile(r'(?i)(api[_\s-]?key|apikey|api_token|token)[\s:=]+[\'\"]?([a-zA-Z0-9]{32,})[\'\"]?'),
            'aws_key': re.compile(r'(?i)(aws_access_key_id|aws_secret_access_key)[\s:=]+[\'\"]?([a-zA-Z0-9/+=]{20,})[\'\"]?'),
            'password': re.compile(r'(?i)(password|passwd|pwd|pass)[\s:=]+[\'\"]?([^\s\'\"]{8,})[\'\"]?'),
            'private_key': re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
            'jwt_token': re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
            'bank_account': re.compile(r'\b\d{8,17}\b'),  # Various bank account formats
            'passport': re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),
            'driver_license': re.compile(r'\b[A-Z]{1,2}\d{5,12}\b'),
        }
        
        # Add custom patterns from config
        custom_patterns = self.config.get('custom_patterns', [])
        for i, pattern in enumerate(custom_patterns):
            try:
                patterns[f'custom_{i}'] = re.compile(pattern)
            except re.error:
                self.logger.error(f"Invalid regex pattern: {pattern}")
                
        return patterns
    
    def scan_content(self, content: str) -> Dict[str, Any]:
        """Scan content for sensitive data"""
        findings = {
            'has_sensitive_data': False,
            'sensitive_data_types': [],
            'risk_score': 0,
            'matches': []
        }
        
        for data_type, pattern in self.sensitive_patterns.items():
            matches = pattern.findall(content)
            if matches:
                findings['has_sensitive_data'] = True
                findings['sensitive_data_types'].append(data_type)
                
                # Redact sensitive data for logging
                redacted_matches = [self.redact_sensitive_data(match, data_type) 
                                  for match in matches[:5]]  # Limit to first 5
                findings['matches'].extend(redacted_matches)
                
                # Calculate risk score
                findings['risk_score'] += self.calculate_risk_score(data_type, len(matches))
        
        # Classify document sensitivity
        doc_classification = self.document_classifier.classify(content)
        findings['document_classification'] = doc_classification
        
        if doc_classification['is_sensitive']:
            findings['risk_score'] += doc_classification['confidence'] * 10
            
        return findings
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scan a file for sensitive data"""
        try:
            # Determine file type
            mime_type, _ = mimetypes.guess_type(file_path)
            
            # Skip binary files except documents
            if mime_type and not mime_type.startswith(('text/', 'application/pdf', 
                                                       'application/msword', 
                                                       'application/vnd.')):
                return {'has_sensitive_data': False, 'skipped': True}
            
            # Read file content
            content = self.read_file_content(file_path)
            
            # Scan content
            findings = self.scan_content(content)
            findings['file_path'] = file_path
            findings['scan_time'] = datetime.now().isoformat()
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {e}")
            return {'has_sensitive_data': False, 'error': str(e)}
    
    def read_file_content(self, file_path: str) -> str:
        """Read and extract text content from various file types"""
        content = ""
        
        try:
            # For now, simple text reading
            # In production, use libraries like PyPDF2, python-docx, etc.
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024 * 1024)  # Read up to 1MB
                
        except Exception as e:
            self.logger.debug(f"Could not read {file_path}: {e}")
            
        return content
    
    def redact_sensitive_data(self, data: str, data_type: str) -> str:
        """Redact sensitive data for safe logging"""
        if isinstance(data, tuple):
            data = str(data[0]) if data else ""
            
        if data_type == 'ssn':
            return 'XXX-XX-' + data[-4:] if len(data) >= 4 else 'XXX-XX-XXXX'
        elif data_type == 'credit_card':
            return 'XXXX-XXXX-XXXX-' + data[-4:] if len(data) >= 4 else 'XXXX'
        elif data_type == 'email':
            parts = data.split('@')
            if len(parts) == 2:
                return parts[0][:2] + '***@' + parts[1]
            return '***@***'
        elif data_type in ('password', 'api_key', 'aws_key', 'private_key'):
            return '[REDACTED]'
        else:
            # Partial redaction for other types
            if len(data) > 4:
                return data[:2] + '*' * (len(data) - 4) + data[-2:]
            return '*' * len(data)
    
    def calculate_risk_score(self, data_type: str, count: int) -> int:
        """Calculate risk score based on data type and count"""
        risk_weights = {
            'ssn': 10,
            'credit_card': 10,
            'private_key': 15,
            'api_key': 8,
            'aws_key': 12,
            'password': 7,
            'bank_account': 9,
            'passport': 8,
            'driver_license': 7,
            'email': 3,
            'phone': 2,
            'jwt_token': 6,
        }
        
        weight = risk_weights.get(data_type, 5)
        return min(weight * count, 100)  # Cap at 100
    
    def monitor_data_transfer(self, source: str, destination: str, 
                            data: bytes) -> bool:
        """Monitor and potentially block data transfers"""
        # Convert bytes to string for scanning
        try:
            content = data.decode('utf-8', errors='ignore')
        except:
            content = str(data)
        
        # Scan for sensitive data
        findings = self.scan_content(content)
        
        if findings['has_sensitive_data']:
            # Log the attempt
            self.log_blocked_transfer(source, destination, findings)
            
            # Decide whether to block
            if findings['risk_score'] >= self.config.get('blocking_threshold', 50):
                self.blocked_transfers.append({
                    'timestamp': datetime.now().isoformat(),
                    'source': source,
                    'destination': destination,
                    'risk_score': findings['risk_score'],
                    'data_types': findings['sensitive_data_types']
                })
                return False  # Block transfer
                
        return True  # Allow transfer
    
    def log_blocked_transfer(self, source: str, destination: str, 
                            findings: Dict[str, Any]):
        """Log blocked data transfer attempt"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'source': source,
            'destination': destination,
            'findings': findings
        }
        
        log_file = "data/logs/dlp_blocks.json"
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        try:
            # Read existing logs
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    logs = json.load(f)
            else:
                logs = []
            
            logs.append(log_entry)
            
            # Keep last 1000 entries
            logs = logs[-1000:]
            
            with open(log_file, 'w') as f:
                json.dump(logs, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Error logging DLP block: {e}")


class ClipboardMonitor:
    """Monitor clipboard for sensitive data"""
    
    def __init__(self, dlp: DataLeakPrevention):
        self.dlp = dlp
        self.logger = logging.getLogger(__name__)
        self.last_clipboard = ""
        self.monitor_thread = None
        self.is_active = False
        
    def start(self):
        """Start clipboard monitoring"""
        if self.is_active:
            return
            
        self.is_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop(self):
        """Stop clipboard monitoring"""
        self.is_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
            
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.is_active:
            try:
                # This is a placeholder - actual implementation would use
                # platform-specific clipboard APIs
                self.check_clipboard()
                threading.Event().wait(1)  # Check every second
            except Exception as e:
                self.logger.error(f"Clipboard monitoring error: {e}")
                
    def check_clipboard(self):
        """Check clipboard content for sensitive data"""
        try:
            # Placeholder for clipboard access
            # In real implementation, use pyperclip or platform-specific APIs
            clipboard_content = self.get_clipboard_content()
            
            if clipboard_content and clipboard_content != self.last_clipboard:
                self.last_clipboard = clipboard_content
                
                # Scan for sensitive data
                findings = self.dlp.scan_content(clipboard_content)
                
                if findings['has_sensitive_data']:
                    self.handle_sensitive_clipboard(findings)
                    
        except Exception as e:
            self.logger.debug(f"Clipboard check error: {e}")
            
    def get_clipboard_content(self) -> str:
        """Get clipboard content (platform-specific)"""
        # Placeholder - actual implementation would use platform APIs
        return ""
        
    def handle_sensitive_clipboard(self, findings: Dict[str, Any]):
        """Handle sensitive data in clipboard"""
        self.logger.warning(f"Sensitive data detected in clipboard: {findings['sensitive_data_types']}")
        
        # In production, might clear clipboard or warn user
        if findings['risk_score'] >= 50:
            self.clear_clipboard()
            
    def clear_clipboard(self):
        """Clear clipboard content"""
        # Placeholder - actual implementation would clear clipboard
        pass


class USBMonitor:
    """Monitor USB devices for data exfiltration"""
    
    def __init__(self, dlp: DataLeakPrevention):
        self.dlp = dlp
        self.logger = logging.getLogger(__name__)
        self.known_devices = set()
        self.monitor_thread = None
        self.is_active = False
        
    def start(self):
        """Start USB monitoring"""
        if self.is_active:
            return
            
        self.is_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop(self):
        """Stop USB monitoring"""
        self.is_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
            
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.is_active:
            try:
                self.check_usb_devices()
                threading.Event().wait(5)  # Check every 5 seconds
            except Exception as e:
                self.logger.error(f"USB monitoring error: {e}")
                
    def check_usb_devices(self):
        """Check for new USB devices"""
        # Placeholder - actual implementation would use pyudev or WMI
        current_devices = self.get_usb_devices()
        
        new_devices = current_devices - self.known_devices
        for device in new_devices:
            self.handle_new_usb_device(device)
            
        self.known_devices = current_devices
        
    def get_usb_devices(self) -> Set[str]:
        """Get list of USB devices"""
        # Placeholder - actual implementation would enumerate USB devices
        return set()
        
    def handle_new_usb_device(self, device: str):
        """Handle new USB device connection"""
        self.logger.info(f"New USB device detected: {device}")
        
        # In production, might:
        # - Block device
        # - Scan files being copied
        # - Alert administrator


class NetworkDataMonitor:
    """Monitor network traffic for data exfiltration"""
    
    def __init__(self, dlp: DataLeakPrevention):
        self.dlp = dlp
        self.logger = logging.getLogger(__name__)
        self.suspicious_destinations = set()
        
    def check_network_transfer(self, destination: str, data: bytes) -> bool:
        """Check network data transfer for sensitive information"""
        # Check if destination is suspicious
        if self.is_suspicious_destination(destination):
            self.logger.warning(f"Data transfer to suspicious destination: {destination}")
            return False
            
        # Scan data for sensitive content
        return self.dlp.monitor_data_transfer("network", destination, data)
        
    def is_suspicious_destination(self, destination: str) -> bool:
        """Check if destination is suspicious"""
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        suspicious_keywords = ['upload', 'exfil', 'c2', 'command', 'mal']
        
        for tld in suspicious_tlds:
            if destination.endswith(tld):
                return True
                
        for keyword in suspicious_keywords:
            if keyword in destination.lower():
                return True
                
        return destination in self.suspicious_destinations


class DocumentClassifier:
    """Classify documents based on sensitivity"""
    
    def __init__(self):
        self.sensitive_keywords = {
            'confidential', 'secret', 'classified', 'proprietary',
            'internal only', 'restricted', 'sensitive', 'private',
            'do not distribute', 'company confidential', 'trade secret',
            'attorney-client', 'privileged', 'personal information',
            'financial', 'medical', 'health', 'salary', 'compensation'
        }
        
    def classify(self, content: str) -> Dict[str, Any]:
        """Classify document sensitivity"""
        lower_content = content.lower()
        
        # Count sensitive keywords
        keyword_count = sum(1 for keyword in self.sensitive_keywords 
                          if keyword in lower_content)
        
        # Calculate confidence
        content_length = len(content.split())
        if content_length > 0:
            keyword_density = keyword_count / content_length
        else:
            keyword_density = 0
            
        is_sensitive = keyword_count >= 2 or keyword_density > 0.01
        confidence = min(keyword_density * 100, 1.0)
        
        return {
            'is_sensitive': is_sensitive,
            'confidence': confidence,
            'keyword_count': keyword_count,
            'classification': 'sensitive' if is_sensitive else 'normal'
        }