"""
Core Antivirus Scanner Engine
"""
import os
import hashlib
import sqlite3
import json
import shutil
import threading
import queue
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil
import time

from .ml_engine import AIThreatDetector

class AntivirusScanner:
    """Main antivirus scanning engine"""
    
    def __init__(self, config_path: str = None):
        self.config = self.load_config(config_path)
        self.ai_detector = AIThreatDetector()
        self.signature_db = SignatureDatabase()
        self.whitelist = Whitelist()
        self.quarantine = QuarantineManager()
        self.scan_history = []
        self.logger = logging.getLogger(__name__)
        self.scan_queue = queue.Queue()
        self.is_scanning = False
        self.scan_stats = {
            'files_scanned': 0,
            'threats_found': 0,
            'files_cleaned': 0,
            'files_quarantined': 0,
            'scan_time': 0
        }
        
    def load_config(self, config_path: str) -> Dict:
        """Load configuration settings"""
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
        return {}
    
    def scan_file(self, file_path: str, deep_scan: bool = False) -> Dict[str, Any]:
        """Scan a single file for threats"""
        result = {
            'file_path': file_path,
            'scan_time': datetime.now().isoformat(),
            'is_safe': True,
            'threats': [],
            'actions_taken': []
        }
        
        try:
            # Check if file exists and is readable
            if not os.path.exists(file_path):
                result['error'] = 'File not found'
                return result
            
            # Check whitelist
            if self.whitelist.is_whitelisted(file_path):
                result['whitelisted'] = True
                return result
            
            # Calculate file hash
            file_hash = self.calculate_file_hash(file_path)
            result['file_hash'] = file_hash
            
            # Check signature database
            signature_threat = self.signature_db.check_signature(file_hash)
            if signature_threat:
                result['is_safe'] = False
                result['threats'].append({
                    'type': 'signature_match',
                    'threat_name': signature_threat['name'],
                    'severity': signature_threat['severity'],
                    'confidence': 1.0
                })
            
            # AI-based detection
            if self.config.get('ml_detection', True):
                is_threat, confidence, threat_type = self.ai_detector.predict_threat(file_path)
                if is_threat:
                    result['is_safe'] = False
                    result['threats'].append({
                        'type': 'ml_detection',
                        'threat_name': threat_type,
                        'severity': self.calculate_severity(confidence),
                        'confidence': confidence
                    })
            
            # Heuristic analysis
            if deep_scan or self.config.get('heuristic_analysis', True):
                heuristic_threats = self.perform_heuristic_analysis(file_path)
                if heuristic_threats:
                    result['is_safe'] = False
                    result['threats'].extend(heuristic_threats)
            
            # Take action on threats
            if not result['is_safe']:
                action = self.handle_threat(file_path, result['threats'])
                result['actions_taken'].append(action)
                
        except Exception as e:
            self.logger.error(f"Error scanning {file_path}: {e}")
            result['error'] = str(e)
        
        # Update statistics
        self.scan_stats['files_scanned'] += 1
        if not result['is_safe']:
            self.scan_stats['threats_found'] += 1
            
        return result
    
    def scan_directory(self, directory_path: str, recursive: bool = True) -> List[Dict[str, Any]]:
        """Scan an entire directory for threats"""
        results = []
        start_time = time.time()
        
        # Get list of files to scan
        files_to_scan = []
        if recursive:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    files_to_scan.append(file_path)
        else:
            for file in os.listdir(directory_path):
                file_path = os.path.join(directory_path, file)
                if os.path.isfile(file_path):
                    files_to_scan.append(file_path)
        
        # Parallel scanning
        max_workers = self.config.get('max_threads', 4)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan_file, file_path): file_path 
                      for file_path in files_to_scan}
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Scan error: {e}")
        
        self.scan_stats['scan_time'] = time.time() - start_time
        return results
    
    def quick_scan(self) -> List[Dict[str, Any]]:
        """Perform a quick scan of common threat locations"""
        quick_scan_locations = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
            "/tmp",
            os.environ.get("TEMP", "/tmp"),
            os.path.expanduser("~/.local/share"),
        ]
        
        results = []
        for location in quick_scan_locations:
            if os.path.exists(location):
                results.extend(self.scan_directory(location, recursive=False))
                
        return results
    
    def full_scan(self) -> List[Dict[str, Any]]:
        """Perform a full system scan"""
        # This would scan the entire system in a real implementation
        # For safety in sandbox, we'll limit to user directories
        home_dir = os.path.expanduser("~")
        return self.scan_directory(home_dir, recursive=True)
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def calculate_severity(self, confidence: float) -> str:
        """Calculate threat severity based on confidence"""
        if confidence >= 0.9:
            return "critical"
        elif confidence >= 0.75:
            return "high"
        elif confidence >= 0.5:
            return "medium"
        else:
            return "low"
    
    def perform_heuristic_analysis(self, file_path: str) -> List[Dict[str, Any]]:
        """Perform heuristic analysis on a file"""
        threats = []
        
        try:
            # Check file extension mismatches
            if self.check_extension_mismatch(file_path):
                threats.append({
                    'type': 'heuristic',
                    'threat_name': 'extension_mismatch',
                    'severity': 'medium',
                    'confidence': 0.7
                })
            
            # Check for hidden executables
            if self.is_hidden_executable(file_path):
                threats.append({
                    'type': 'heuristic',
                    'threat_name': 'hidden_executable',
                    'severity': 'high',
                    'confidence': 0.8
                })
            
            # Check for suspicious file size patterns
            if self.check_suspicious_size(file_path):
                threats.append({
                    'type': 'heuristic',
                    'threat_name': 'suspicious_size',
                    'severity': 'low',
                    'confidence': 0.5
                })
                
        except Exception as e:
            self.logger.error(f"Heuristic analysis error: {e}")
            
        return threats
    
    def check_extension_mismatch(self, file_path: str) -> bool:
        """Check if file extension matches its actual type"""
        import magic
        
        try:
            file_type = magic.from_file(file_path, mime=True)
            extension = os.path.splitext(file_path)[1].lower()
            
            # Define expected MIME types for common extensions
            expected_types = {
                '.exe': 'application/x-executable',
                '.pdf': 'application/pdf',
                '.jpg': 'image/jpeg',
                '.png': 'image/png',
                '.doc': 'application/msword',
                '.zip': 'application/zip',
            }
            
            if extension in expected_types:
                expected = expected_types[extension]
                if expected not in file_type:
                    return True
                    
        except Exception:
            pass
            
        return False
    
    def is_hidden_executable(self, file_path: str) -> bool:
        """Check if file is a hidden executable"""
        filename = os.path.basename(file_path)
        
        # Check if file is hidden (starts with .)
        if filename.startswith('.'):
            # Check if it's an executable
            if os.access(file_path, os.X_OK):
                return True
                
            # Check for executable extensions
            exec_extensions = ['.exe', '.dll', '.sys', '.bat', '.cmd', '.sh']
            if any(filename.lower().endswith(ext) for ext in exec_extensions):
                return True
                
        return False
    
    def check_suspicious_size(self, file_path: str) -> bool:
        """Check for suspicious file sizes"""
        try:
            size = os.path.getsize(file_path)
            
            # Files that are exactly powers of 2 might be suspicious
            if size > 1024 and (size & (size - 1)) == 0:
                return True
                
            # Very small executables might be droppers
            if file_path.endswith(('.exe', '.dll')) and size < 5000:
                return True
                
        except Exception:
            pass
            
        return False
    
    def handle_threat(self, file_path: str, threats: List[Dict[str, Any]]) -> str:
        """Handle detected threats"""
        # Determine action based on threat severity
        max_severity = max(threats, key=lambda x: self.severity_to_int(x['severity']))
        
        if self.config.get('auto_quarantine', True):
            if self.severity_to_int(max_severity['severity']) >= 2:  # medium or higher
                self.quarantine.quarantine_file(file_path)
                self.scan_stats['files_quarantined'] += 1
                return "quarantined"
        
        return "detected_only"
    
    def severity_to_int(self, severity: str) -> int:
        """Convert severity to integer for comparison"""
        severity_map = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        return severity_map.get(severity, 0)


class SignatureDatabase:
    """Manage virus signature database"""
    
    def __init__(self, db_path: str = "data/signatures.db"):
        self.db_path = db_path
        self.init_database()
        
    def init_database(self):
        """Initialize signature database"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT UNIQUE NOT NULL,
                threat_name TEXT NOT NULL,
                threat_type TEXT,
                severity TEXT,
                first_seen DATE,
                last_updated DATE
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Load initial signatures
        self.load_default_signatures()
    
    def load_default_signatures(self):
        """Load default malware signatures"""
        # In a real implementation, these would be real malware hashes
        # These are example hashes only
        default_signatures = [
            {
                'hash': 'd41d8cd98f00b204e9800998ecf8427e',
                'threat_name': 'TestVirus.Generic',
                'threat_type': 'virus',
                'severity': 'high'
            },
            {
                'hash': 'e3b0c44298fc1c149afbf4c8996fb924',
                'threat_name': 'Trojan.Generic',
                'threat_type': 'trojan',
                'severity': 'critical'
            }
        ]
        
        for sig in default_signatures:
            self.add_signature(sig)
    
    def add_signature(self, signature: Dict[str, Any]):
        """Add a new signature to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO signatures 
                (hash, threat_name, threat_type, severity, first_seen, last_updated)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                signature['hash'],
                signature['threat_name'],
                signature.get('threat_type', 'unknown'),
                signature.get('severity', 'medium'),
                datetime.now().isoformat(),
                datetime.now().isoformat()
            ))
            conn.commit()
        except Exception as e:
            logging.error(f"Error adding signature: {e}")
        finally:
            conn.close()
    
    def check_signature(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Check if a file hash matches any known signature"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT threat_name, threat_type, severity 
            FROM signatures 
            WHERE hash = ?
        ''', (file_hash,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'name': result[0],
                'type': result[1],
                'severity': result[2]
            }
        return None


class Whitelist:
    """Manage whitelisted files and applications"""
    
    def __init__(self):
        self.whitelist_paths = set()
        self.whitelist_hashes = set()
        self.load_whitelist()
        
    def load_whitelist(self):
        """Load whitelist from configuration"""
        # System files and trusted applications
        self.whitelist_paths.update([
            '/usr/bin',
            '/usr/sbin',
            '/bin',
            '/sbin',
            '/System',  # macOS
            'C:\\Windows\\System32',  # Windows
            'C:\\Program Files',
        ])
    
    def is_whitelisted(self, file_path: str) -> bool:
        """Check if a file is whitelisted"""
        # Check if file is in whitelisted directory
        for whitelist_path in self.whitelist_paths:
            if file_path.startswith(whitelist_path):
                return True
                
        # Check hash whitelist
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                if file_hash in self.whitelist_hashes:
                    return True
        except Exception:
            pass
            
        return False
    
    def add_to_whitelist(self, file_path: str):
        """Add a file to whitelist"""
        self.whitelist_paths.add(file_path)


class QuarantineManager:
    """Manage quarantined files"""
    
    def __init__(self, quarantine_dir: str = "data/quarantine"):
        self.quarantine_dir = quarantine_dir
        os.makedirs(quarantine_dir, exist_ok=True)
        
    def quarantine_file(self, file_path: str) -> bool:
        """Move a file to quarantine"""
        try:
            # Generate quarantine name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.basename(file_path)
            quarantine_name = f"{timestamp}_{filename}.quarantine"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
            
            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            
            # Save metadata
            metadata = {
                'original_path': file_path,
                'quarantine_time': datetime.now().isoformat(),
                'quarantine_path': quarantine_path
            }
            
            metadata_path = quarantine_path + '.json'
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f)
                
            logging.info(f"File quarantined: {file_path}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to quarantine {file_path}: {e}")
            return False
    
    def restore_file(self, quarantine_name: str) -> bool:
        """Restore a file from quarantine"""
        try:
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
            metadata_path = quarantine_path + '.json'
            
            # Load metadata
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            # Restore file
            shutil.move(quarantine_path, metadata['original_path'])
            
            # Remove metadata
            os.remove(metadata_path)
            
            logging.info(f"File restored: {metadata['original_path']}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to restore {quarantine_name}: {e}")
            return False