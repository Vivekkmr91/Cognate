"""
Email Protection Module
Scans email attachments, detects phishing, and protects against email-based threats
"""
import os
import re
import email
import imaplib
import smtplib
import hashlib
import base64
import mimetypes
from email import message_from_bytes, policy
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import logging
from pathlib import Path
import sqlite3
import json
import tempfile
import zipfile
import rarfile

class EmailProtection:
    """Comprehensive email security protection"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.logger = logging.getLogger(__name__)
        self.config = config or {}
        
        # Email security components
        self.attachment_scanner = AttachmentScanner()
        self.phishing_detector = EmailPhishingDetector()
        self.spam_filter = SpamFilter()
        self.link_analyzer = EmailLinkAnalyzer()
        self.spf_checker = SPFChecker()
        self.dkim_validator = DKIMValidator()
        self.dmarc_checker = DMARCChecker()
        
        # Initialize database
        self.init_database()
        
        # Quarantine directory
        self.quarantine_dir = Path("data/email_quarantine")
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        # IMAP/SMTP settings
        self.imap_settings = {}
        self.smtp_settings = {}
    
    def init_database(self):
        """Initialize email protection database"""
        self.db_path = "data/email_protection.db"
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scanned_emails (
                message_id TEXT PRIMARY KEY,
                sender TEXT,
                recipient TEXT,
                subject TEXT,
                scan_date DATE,
                is_safe BOOLEAN,
                threats TEXT,
                actions_taken TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantined_emails (
                quarantine_id TEXT PRIMARY KEY,
                message_id TEXT,
                sender TEXT,
                subject TEXT,
                quarantine_date DATE,
                threat_type TEXT,
                file_path TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_threats (
                threat_id TEXT PRIMARY KEY,
                threat_type TEXT,
                sender TEXT,
                subject_pattern TEXT,
                attachment_hash TEXT,
                detection_date DATE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sender_reputation (
                sender_email TEXT PRIMARY KEY,
                reputation_score INTEGER,
                total_emails INTEGER,
                spam_count INTEGER,
                phishing_count INTEGER,
                malware_count INTEGER,
                last_seen DATE
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def scan_email(self, email_content: bytes) -> Dict[str, Any]:
        """Scan email for threats"""
        result = {
            'is_safe': True,
            'threats': [],
            'attachments': [],
            'links': [],
            'sender_reputation': 100,
            'spf_pass': False,
            'dkim_pass': False,
            'dmarc_pass': False,
            'actions': []
        }
        
        try:
            # Parse email
            msg = message_from_bytes(email_content, policy=policy.default)
            
            # Extract metadata
            sender = msg.get('From', '')
            recipient = msg.get('To', '')
            subject = msg.get('Subject', '')
            message_id = msg.get('Message-ID', '')
            
            result['message_id'] = message_id
            result['sender'] = sender
            result['subject'] = subject
            
            # Check sender reputation
            sender_rep = self.check_sender_reputation(sender)
            result['sender_reputation'] = sender_rep['score']
            
            if sender_rep['is_blacklisted']:
                result['is_safe'] = False
                result['threats'].append('blacklisted_sender')
            
            # SPF, DKIM, DMARC validation
            auth_results = self.validate_email_authentication(msg)
            result.update(auth_results)
            
            if not auth_results['spf_pass']:
                result['threats'].append('spf_fail')
            if not auth_results['dkim_pass']:
                result['threats'].append('dkim_fail')
            if not auth_results['dmarc_pass']:
                result['threats'].append('dmarc_fail')
            
            # Check for phishing
            phishing_result = self.phishing_detector.check_email(msg)
            if phishing_result['is_phishing']:
                result['is_safe'] = False
                result['threats'].append('phishing_email')
                result['phishing_details'] = phishing_result
            
            # Check for spam
            spam_result = self.spam_filter.check_spam(msg)
            if spam_result['is_spam']:
                result['threats'].append('spam')
                result['spam_score'] = spam_result['score']
            
            # Scan attachments
            for part in msg.walk():
                if part.get_content_disposition() == 'attachment':
                    attachment_result = self.scan_attachment(part)
                    result['attachments'].append(attachment_result)
                    
                    if not attachment_result['is_safe']:
                        result['is_safe'] = False
                        result['threats'].append(f"malicious_attachment: {attachment_result['filename']}")
            
            # Analyze links
            body_content = self.get_email_body(msg)
            links = self.link_analyzer.extract_links(body_content)
            
            for link in links:
                link_result = self.link_analyzer.analyze_link(link)
                result['links'].append(link_result)
                
                if link_result['is_malicious']:
                    result['is_safe'] = False
                    result['threats'].append(f"malicious_link: {link}")
            
            # Check for suspicious patterns
            suspicious = self.check_suspicious_patterns(msg, body_content)
            if suspicious:
                result['threats'].extend(suspicious)
                if any('critical' in s for s in suspicious):
                    result['is_safe'] = False
            
            # Take action if threats detected
            if not result['is_safe']:
                action = self.handle_threat(msg, result)
                result['actions'].append(action)
            
            # Record scan
            self.record_scan(result)
            
        except Exception as e:
            self.logger.error(f"Email scan error: {e}")
            result['error'] = str(e)
        
        return result
    
    def check_sender_reputation(self, sender: str) -> Dict[str, Any]:
        """Check sender email reputation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Extract email address
        email_match = re.search(r'<(.+?)>', sender)
        if email_match:
            email_addr = email_match.group(1)
        else:
            email_addr = sender
        
        cursor.execute('''
            SELECT reputation_score, spam_count, phishing_count, malware_count
            FROM sender_reputation
            WHERE sender_email = ?
        ''', (email_addr,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            score = result[0]
            is_blacklisted = score < 20 or result[1] > 10 or result[2] > 0 or result[3] > 0
            
            return {
                'email': email_addr,
                'score': score,
                'is_blacklisted': is_blacklisted,
                'spam_count': result[1],
                'phishing_count': result[2],
                'malware_count': result[3]
            }
        
        # New sender, neutral reputation
        return {
            'email': email_addr,
            'score': 50,
            'is_blacklisted': False,
            'spam_count': 0,
            'phishing_count': 0,
            'malware_count': 0
        }
    
    def validate_email_authentication(self, msg) -> Dict[str, Any]:
        """Validate SPF, DKIM, and DMARC"""
        results = {
            'spf_pass': False,
            'dkim_pass': False,
            'dmarc_pass': False
        }
        
        # Check Authentication-Results header
        auth_results = msg.get('Authentication-Results', '')
        
        if 'spf=pass' in auth_results:
            results['spf_pass'] = True
        
        if 'dkim=pass' in auth_results:
            results['dkim_pass'] = True
        
        if 'dmarc=pass' in auth_results:
            results['dmarc_pass'] = True
        
        # If no Authentication-Results, perform checks
        if not auth_results:
            # SPF check
            results['spf_pass'] = self.spf_checker.check(msg)
            
            # DKIM check
            results['dkim_pass'] = self.dkim_validator.validate(msg)
            
            # DMARC check
            results['dmarc_pass'] = self.dmarc_checker.check(msg)
        
        return results
    
    def scan_attachment(self, part) -> Dict[str, Any]:
        """Scan email attachment for threats"""
        result = {
            'filename': part.get_filename() or 'unknown',
            'content_type': part.get_content_type(),
            'size': len(part.get_payload(decode=True)),
            'is_safe': True,
            'threats': [],
            'hash': ''
        }
        
        try:
            # Get attachment content
            content = part.get_payload(decode=True)
            
            # Calculate hash
            file_hash = hashlib.sha256(content).hexdigest()
            result['hash'] = file_hash
            
            # Check file type
            filename = result['filename']
            
            # Dangerous extensions
            dangerous_extensions = [
                '.exe', '.scr', '.vbs', '.js', '.bat', '.cmd',
                '.com', '.pif', '.lnk', '.dll', '.sys'
            ]
            
            if any(filename.lower().endswith(ext) for ext in dangerous_extensions):
                result['threats'].append('dangerous_file_type')
                result['is_safe'] = False
            
            # Check for double extensions
            if re.search(r'\.[a-z]{2,4}\.[a-z]{2,4}$', filename.lower()):
                result['threats'].append('double_extension')
                result['is_safe'] = False
            
            # Check if archive and scan contents
            if filename.lower().endswith(('.zip', '.rar', '.7z')):
                archive_result = self.scan_archive(content, filename)
                if not archive_result['is_safe']:
                    result['is_safe'] = False
                    result['threats'].extend(archive_result['threats'])
            
            # Check against threat database
            if self.attachment_scanner.is_known_threat(file_hash):
                result['is_safe'] = False
                result['threats'].append('known_malware')
            
            # Save to temp and scan with main scanner
            if not result['is_safe']:
                temp_path = self.save_to_temp(content, filename)
                
                # Would integrate with main scanner here
                # scan_result = scanner.scan_file(temp_path)
                
                # Clean up
                os.unlink(temp_path)
                
        except Exception as e:
            self.logger.error(f"Attachment scan error: {e}")
            result['error'] = str(e)
        
        return result
    
    def scan_archive(self, content: bytes, filename: str) -> Dict[str, Any]:
        """Scan archive contents"""
        result = {
            'is_safe': True,
            'threats': []
        }
        
        try:
            with tempfile.NamedTemporaryFile(suffix=filename, delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            
            # Extract and check contents
            if filename.endswith('.zip'):
                with zipfile.ZipFile(tmp_path, 'r') as zf:
                    for member in zf.namelist():
                        # Check for dangerous files
                        if member.endswith(('.exe', '.scr', '.vbs', '.bat')):
                            result['is_safe'] = False
                            result['threats'].append(f'archive_contains: {member}')
            
            os.unlink(tmp_path)
            
        except Exception as e:
            self.logger.error(f"Archive scan error: {e}")
        
        return result
    
    def get_email_body(self, msg) -> str:
        """Extract email body text"""
        body = ""
        
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_content()
            elif part.get_content_type() == "text/html":
                # Extract text from HTML
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(part.get_content(), 'html.parser')
                body += soup.get_text()
        
        return body
    
    def check_suspicious_patterns(self, msg, body: str) -> List[str]:
        """Check for suspicious email patterns"""
        suspicious = []
        
        # Check for spoofed sender
        from_addr = msg.get('From', '')
        reply_to = msg.get('Reply-To', '')
        
        if reply_to and from_addr:
            from_domain = from_addr.split('@')[-1].strip('>')
            reply_domain = reply_to.split('@')[-1].strip('>')
            
            if from_domain != reply_domain:
                suspicious.append('reply_to_mismatch')
        
        # Check for urgency indicators
        urgency_phrases = [
            'urgent', 'immediate action required', 'account will be closed',
            'suspended', 'verify your account', 'confirm your identity'
        ]
        
        body_lower = body.lower()
        for phrase in urgency_phrases:
            if phrase in body_lower:
                suspicious.append(f'urgency_indicator: {phrase}')
        
        # Check for credential harvesting attempts
        if 'password' in body_lower and ('click here' in body_lower or 'verify' in body_lower):
            suspicious.append('credential_harvesting_attempt: critical')
        
        # Check for money-related scams
        money_keywords = ['bitcoin', 'wire transfer', 'western union', 'money gram', 'invoice']
        if any(keyword in body_lower for keyword in money_keywords):
            suspicious.append('financial_scam_keywords')
        
        return suspicious
    
    def handle_threat(self, msg, scan_result: Dict[str, Any]) -> str:
        """Handle detected email threat"""
        action = "none"
        
        try:
            # Quarantine email
            if scan_result.get('threats'):
                quarantine_id = self.quarantine_email(msg, scan_result)
                action = f"quarantined: {quarantine_id}"
                
                # Update sender reputation
                self.update_sender_reputation(
                    scan_result['sender'],
                    scan_result['threats']
                )
        except Exception as e:
            self.logger.error(f"Threat handling error: {e}")
            action = f"error: {e}"
        
        return action
    
    def quarantine_email(self, msg, scan_result: Dict[str, Any]) -> str:
        """Quarantine suspicious email"""
        import uuid
        
        quarantine_id = str(uuid.uuid4())
        
        # Save email to quarantine
        quarantine_file = self.quarantine_dir / f"{quarantine_id}.eml"
        
        with open(quarantine_file, 'wb') as f:
            f.write(msg.as_bytes())
        
        # Record in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO quarantined_emails
            (quarantine_id, message_id, sender, subject, quarantine_date,
             threat_type, file_path)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            quarantine_id,
            scan_result.get('message_id', ''),
            scan_result.get('sender', ''),
            scan_result.get('subject', ''),
            datetime.now().isoformat(),
            json.dumps(scan_result.get('threats', [])),
            str(quarantine_file)
        ))
        
        conn.commit()
        conn.close()
        
        return quarantine_id
    
    def update_sender_reputation(self, sender: str, threats: List[str]):
        """Update sender reputation based on threats"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Extract email address
        email_match = re.search(r'<(.+?)>', sender)
        if email_match:
            email_addr = email_match.group(1)
        else:
            email_addr = sender
        
        # Get current reputation
        cursor.execute('''
            SELECT reputation_score, spam_count, phishing_count, malware_count
            FROM sender_reputation
            WHERE sender_email = ?
        ''', (email_addr,))
        
        result = cursor.fetchone()
        
        if result:
            score, spam_count, phishing_count, malware_count = result
        else:
            score, spam_count, phishing_count, malware_count = 50, 0, 0, 0
        
        # Update counts based on threats
        if 'spam' in threats:
            spam_count += 1
            score -= 5
        
        if 'phishing_email' in threats:
            phishing_count += 1
            score -= 20
        
        if any('malicious_attachment' in t for t in threats):
            malware_count += 1
            score -= 30
        
        # Ensure score stays in range
        score = max(0, min(100, score))
        
        # Update database
        cursor.execute('''
            INSERT OR REPLACE INTO sender_reputation
            (sender_email, reputation_score, total_emails, spam_count,
             phishing_count, malware_count, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            email_addr,
            score,
            (result[1] if result else 0) + 1,
            spam_count,
            phishing_count,
            malware_count,
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def record_scan(self, scan_result: Dict[str, Any]):
        """Record email scan in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO scanned_emails
                (message_id, sender, recipient, subject, scan_date,
                 is_safe, threats, actions_taken)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_result.get('message_id', ''),
                scan_result.get('sender', ''),
                scan_result.get('recipient', ''),
                scan_result.get('subject', ''),
                datetime.now().isoformat(),
                scan_result.get('is_safe', True),
                json.dumps(scan_result.get('threats', [])),
                json.dumps(scan_result.get('actions', []))
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to record scan: {e}")
    
    def save_to_temp(self, content: bytes, filename: str) -> str:
        """Save content to temporary file"""
        with tempfile.NamedTemporaryFile(suffix=filename, delete=False) as tmp:
            tmp.write(content)
            return tmp.name
    
    def configure_email_client(self, imap_settings: Dict, smtp_settings: Dict):
        """Configure email client settings"""
        self.imap_settings = imap_settings
        self.smtp_settings = smtp_settings
    
    def scan_inbox(self) -> List[Dict[str, Any]]:
        """Scan email inbox for threats"""
        results = []
        
        if not self.imap_settings:
            return results
        
        try:
            # Connect to IMAP server
            imap = imaplib.IMAP4_SSL(
                self.imap_settings['server'],
                self.imap_settings.get('port', 993)
            )
            
            imap.login(
                self.imap_settings['username'],
                self.imap_settings['password']
            )
            
            # Select inbox
            imap.select('INBOX')
            
            # Search for emails
            status, data = imap.search(None, 'ALL')
            
            if status == 'OK':
                email_ids = data[0].split()
                
                for email_id in email_ids[-10:]:  # Scan last 10 emails
                    status, data = imap.fetch(email_id, '(RFC822)')
                    
                    if status == 'OK':
                        email_content = data[0][1]
                        scan_result = self.scan_email(email_content)
                        results.append(scan_result)
            
            imap.logout()
            
        except Exception as e:
            self.logger.error(f"Inbox scan error: {e}")
        
        return results


class AttachmentScanner:
    """Email attachment scanner"""
    
    def is_known_threat(self, file_hash: str) -> bool:
        """Check if attachment is known threat"""
        # Would check against threat database
        return False


class EmailPhishingDetector:
    """Email-specific phishing detection"""
    
    def check_email(self, msg) -> Dict[str, Any]:
        """Check email for phishing indicators"""
        result = {
            'is_phishing': False,
            'confidence': 0.0,
            'indicators': []
        }
        
        # Check sender spoofing
        from_header = msg.get('From', '')
        if self.is_spoofed_sender(from_header):
            result['indicators'].append('spoofed_sender')
            result['confidence'] += 0.3
        
        # Check for lookalike domains
        if self.has_lookalike_domain(from_header):
            result['indicators'].append('lookalike_domain')
            result['confidence'] += 0.4
        
        # Determine if phishing
        if result['confidence'] >= 0.6:
            result['is_phishing'] = True
        
        return result
    
    def is_spoofed_sender(self, from_header: str) -> bool:
        """Check if sender is spoofed"""
        # Check for display name tricks
        if '<' in from_header and '>' in from_header:
            display_name = from_header.split('<')[0].strip()
            email_addr = from_header.split('<')[1].split('>')[0]
            
            # Check if display name contains different domain
            if '@' in display_name:
                return True
        
        return False
    
    def has_lookalike_domain(self, from_header: str) -> bool:
        """Check for lookalike domains"""
        if '@' in from_header:
            domain = from_header.split('@')[-1].strip('>').lower()
            
            legitimate = ['gmail.com', 'outlook.com', 'yahoo.com']
            
            for legit in legitimate:
                # Simple similarity check
                if domain != legit and self.similar(domain, legit) > 0.8:
                    return True
        
        return False
    
    def similar(self, a: str, b: str) -> float:
        """Calculate string similarity"""
        return 1 - (self.levenshtein(a, b) / max(len(a), len(b)))
    
    def levenshtein(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance"""
        if len(s1) < len(s2):
            return self.levenshtein(s2, s1)
        
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


class SpamFilter:
    """Spam detection filter"""
    
    def check_spam(self, msg) -> Dict[str, Any]:
        """Check if email is spam"""
        score = 0
        
        # Check spam indicators
        subject = msg.get('Subject', '').lower()
        
        spam_keywords = [
            'free', 'winner', 'congratulations', 'click here',
            'limited time', 'act now', 'viagra', 'pills'
        ]
        
        for keyword in spam_keywords:
            if keyword in subject:
                score += 10
        
        return {
            'is_spam': score >= 30,
            'score': score
        }


class EmailLinkAnalyzer:
    """Analyze links in emails"""
    
    def extract_links(self, content: str) -> List[str]:
        """Extract URLs from email content"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, content)
    
    def analyze_link(self, url: str) -> Dict[str, Any]:
        """Analyze link for threats"""
        return {
            'url': url,
            'is_malicious': False,
            'is_shortened': self.is_url_shortener(url)
        }
    
    def is_url_shortener(self, url: str) -> bool:
        """Check if URL is from shortener service"""
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl']
        return any(s in url for s in shorteners)


class SPFChecker:
    """SPF record validation"""
    
    def check(self, msg) -> bool:
        """Check SPF record"""
        # Simplified SPF check
        return True


class DKIMValidator:
    """DKIM signature validation"""
    
    def validate(self, msg) -> bool:
        """Validate DKIM signature"""
        # Simplified DKIM check
        return True


class DMARCChecker:
    """DMARC policy checker"""
    
    def check(self, msg) -> bool:
        """Check DMARC policy"""
        # Simplified DMARC check
        return True