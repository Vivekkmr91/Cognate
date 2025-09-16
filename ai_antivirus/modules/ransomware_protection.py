"""
Ransomware Protection Module
Advanced protection against ransomware attacks
"""
import os
import shutil
import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Dict, List, Set, Any, Optional
from datetime import datetime, timedelta
import logging
from collections import defaultdict, deque

class RansomwareProtection:
    """Comprehensive ransomware protection system"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.honeypot = HoneypotSystem()
        self.behavior_monitor = RansomwareBehaviorMonitor()
        self.file_backup = FileBackupSystem()
        self.shadow_protector = ShadowCopyProtector()
        self.process_injector = ProcessInjectionDetector()
        self.crypto_monitor = CryptoAPIMonitor()
        self.is_active = False
        self.protected_folders = self.get_protected_folders()
        
    def get_protected_folders(self) -> Set[str]:
        """Get list of protected folders"""
        protected = {
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Pictures"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Videos"),
            os.path.expanduser("~/Music"),
        }
        
        # Add custom protected folders from config
        custom_folders = self.config.get('protected_folders', [])
        protected.update(custom_folders)
        
        return protected
    
    def start(self):
        """Start ransomware protection"""
        if self.is_active:
            return
            
        # Initialize components
        self.honeypot.deploy()
        self.behavior_monitor.start()
        self.file_backup.start()
        self.shadow_protector.start()
        self.process_injector.start()
        self.crypto_monitor.start()
        
        self.is_active = True
        self.logger.info("Ransomware protection activated")
        
    def stop(self):
        """Stop ransomware protection"""
        if not self.is_active:
            return
            
        self.honeypot.cleanup()
        self.behavior_monitor.stop()
        self.file_backup.stop()
        self.shadow_protector.stop()
        self.process_injector.stop()
        self.crypto_monitor.stop()
        
        self.is_active = False
        self.logger.info("Ransomware protection deactivated")
    
    def check_ransomware_behavior(self, process_info: Dict[str, Any]) -> bool:
        """Check if process exhibits ransomware behavior"""
        indicators = 0
        
        # Check for suspicious file operations
        if self.behavior_monitor.check_file_operations(process_info):
            indicators += 1
            
        # Check for crypto API usage
        if self.crypto_monitor.check_crypto_usage(process_info):
            indicators += 1
            
        # Check for shadow copy deletion attempts
        if self.shadow_protector.check_deletion_attempt(process_info):
            indicators += 2  # Higher weight for this indicator
            
        # Check for process injection
        if self.process_injector.check_injection(process_info):
            indicators += 1
            
        # Check honeypot access
        if self.honeypot.check_access(process_info):
            indicators += 3  # Very high weight for honeypot access
            
        return indicators >= 3
    
    def handle_ransomware_detection(self, process_info: Dict[str, Any]):
        """Handle detected ransomware"""
        self.logger.critical(f"RANSOMWARE DETECTED: {process_info}")
        
        # Immediate actions
        self.isolate_process(process_info)
        self.backup_critical_files()
        self.alert_user(process_info)
        
        # Log incident
        self.log_incident(process_info)
        
    def isolate_process(self, process_info: Dict[str, Any]):
        """Isolate suspected ransomware process"""
        try:
            pid = process_info.get('pid')
            if pid:
                # In real implementation, would terminate process
                self.logger.warning(f"Isolating process {pid}")
                
                # Block network access for process
                self.block_network_access(pid)
                
                # Suspend process
                self.suspend_process(pid)
                
        except Exception as e:
            self.logger.error(f"Failed to isolate process: {e}")
            
    def block_network_access(self, pid: int):
        """Block network access for a process"""
        # In real implementation, would use firewall rules
        pass
        
    def suspend_process(self, pid: int):
        """Suspend a process"""
        # In real implementation, would suspend process
        pass
        
    def backup_critical_files(self):
        """Emergency backup of critical files"""
        self.file_backup.emergency_backup(self.protected_folders)
        
    def alert_user(self, process_info: Dict[str, Any]):
        """Alert user about ransomware detection"""
        alert = {
            'type': 'RANSOMWARE_ALERT',
            'severity': 'CRITICAL',
            'process': process_info,
            'timestamp': datetime.now().isoformat(),
            'message': 'Ransomware activity detected and blocked!'
        }
        
        # In real implementation, would show system notification
        self.logger.critical(f"USER ALERT: {alert}")
        
    def log_incident(self, process_info: Dict[str, Any]):
        """Log ransomware incident"""
        incident = {
            'timestamp': datetime.now().isoformat(),
            'process_info': process_info,
            'actions_taken': [
                'process_isolated',
                'network_blocked',
                'files_backed_up',
                'user_alerted'
            ]
        }
        
        log_file = "data/logs/ransomware_incidents.json"
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    logs = json.load(f)
            else:
                logs = []
                
            logs.append(incident)
            
            with open(log_file, 'w') as f:
                json.dump(logs, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to log incident: {e}")


class HoneypotSystem:
    """Honeypot system for ransomware detection"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.honeypot_dir = "data/honeypot"
        self.honeypot_files = []
        self.file_hashes = {}
        self.access_log = []
        
    def deploy(self):
        """Deploy honeypot files"""
        os.makedirs(self.honeypot_dir, exist_ok=True)
        
        # Create decoy files with tempting names
        decoy_names = [
            "passwords.txt",
            "bitcoin_wallet.dat",
            "financial_records.xlsx",
            "confidential_2024.docx",
            "private_keys.txt",
            "bank_accounts.pdf",
            "tax_returns.pdf",
            "ssn_list.csv",
            "credit_cards.txt",
            "important_backup.zip"
        ]
        
        for name in decoy_names:
            file_path = os.path.join(self.honeypot_dir, name)
            
            # Create file with identifiable content
            content = f"HONEYPOT FILE - DO NOT MODIFY\n{name}\n{datetime.now()}"
            
            with open(file_path, 'w') as f:
                f.write(content)
                
            # Calculate and store hash
            self.file_hashes[file_path] = self.calculate_hash(file_path)
            self.honeypot_files.append(file_path)
            
        # Set file permissions to be readable but track modifications
        for file_path in self.honeypot_files:
            os.chmod(file_path, 0o644)
            
        self.logger.info(f"Deployed {len(self.honeypot_files)} honeypot files")
        
    def check_access(self, process_info: Dict[str, Any]) -> bool:
        """Check if process accessed honeypot files"""
        accessed_files = process_info.get('accessed_files', [])
        
        for file_path in accessed_files:
            if file_path in self.honeypot_files:
                self.log_access(process_info, file_path)
                
                # Check if file was modified
                if self.is_modified(file_path):
                    self.logger.critical(f"HONEYPOT TRIGGERED: {file_path} modified by {process_info}")
                    return True
                    
        return False
    
    def is_modified(self, file_path: str) -> bool:
        """Check if honeypot file was modified"""
        if not os.path.exists(file_path):
            return True  # File deleted
            
        current_hash = self.calculate_hash(file_path)
        original_hash = self.file_hashes.get(file_path)
        
        return current_hash != original_hash
    
    def calculate_hash(self, file_path: str) -> str:
        """Calculate file hash"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return ""
            
    def log_access(self, process_info: Dict[str, Any], file_path: str):
        """Log honeypot access"""
        self.access_log.append({
            'timestamp': datetime.now().isoformat(),
            'process': process_info,
            'file': file_path
        })
        
    def cleanup(self):
        """Clean up honeypot files"""
        for file_path in self.honeypot_files:
            try:
                os.remove(file_path)
            except:
                pass
                
        self.honeypot_files.clear()
        self.file_hashes.clear()


class RansomwareBehaviorMonitor:
    """Monitor for ransomware-specific behaviors"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.file_operations = defaultdict(lambda: deque(maxlen=100))
        self.encryption_patterns = []
        self.monitor_thread = None
        self.is_active = False
        
    def start(self):
        """Start behavior monitoring"""
        if self.is_active:
            return
            
        self.is_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop(self):
        """Stop behavior monitoring"""
        self.is_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
            
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.is_active:
            try:
                self.analyze_behaviors()
                time.sleep(1)
            except Exception as e:
                self.logger.error(f"Behavior monitoring error: {e}")
                
    def check_file_operations(self, process_info: Dict[str, Any]) -> bool:
        """Check for suspicious file operation patterns"""
        pid = process_info.get('pid')
        operations = self.file_operations.get(pid, [])
        
        # Check for mass file modifications
        recent_ops = [op for op in operations 
                     if time.time() - op['timestamp'] < 60]
        
        if len(recent_ops) > 50:  # More than 50 files in a minute
            # Check for encryption patterns
            if self.check_encryption_pattern(recent_ops):
                return True
                
            # Check for mass renaming
            if self.check_mass_renaming(recent_ops):
                return True
                
        return False
    
    def check_encryption_pattern(self, operations: List[Dict]) -> bool:
        """Check if file operations match encryption pattern"""
        # Look for: read original -> write encrypted -> delete original
        read_files = set()
        written_files = set()
        deleted_files = set()
        
        for op in operations:
            if op['type'] == 'read':
                read_files.add(op['file'])
            elif op['type'] == 'write':
                written_files.add(op['file'])
            elif op['type'] == 'delete':
                deleted_files.add(op['file'])
                
        # Check for pattern
        encrypted_count = 0
        for file in read_files:
            base_name = os.path.splitext(file)[0]
            
            # Check if file was read, new version written, and original deleted
            encrypted_versions = [f for f in written_files 
                                if base_name in f and f != file]
            
            if encrypted_versions and file in deleted_files:
                encrypted_count += 1
                
        return encrypted_count > 10
    
    def check_mass_renaming(self, operations: List[Dict]) -> bool:
        """Check for mass file renaming with suspicious extensions"""
        suspicious_extensions = [
            '.locked', '.encrypted', '.crypto', '.enc',
            '.cipher', '.corona', '.satan', '.ransom',
            '.crypted', '.cryptolocker', '.locky', '.cerber'
        ]
        
        rename_count = 0
        for op in operations:
            if op['type'] == 'rename':
                new_name = op.get('new_name', '')
                if any(new_name.endswith(ext) for ext in suspicious_extensions):
                    rename_count += 1
                    
        return rename_count > 5
    
    def track_file_operation(self, pid: int, operation: Dict[str, Any]):
        """Track file operation by process"""
        operation['timestamp'] = time.time()
        self.file_operations[pid].append(operation)
        
    def analyze_behaviors(self):
        """Analyze collected behaviors for patterns"""
        # Clean old data
        current_time = time.time()
        for pid in list(self.file_operations.keys()):
            # Remove old operations
            self.file_operations[pid] = deque(
                [op for op in self.file_operations[pid]
                 if current_time - op['timestamp'] < 300],  # Keep 5 minutes
                maxlen=100
            )
            
            # Remove empty entries
            if not self.file_operations[pid]:
                del self.file_operations[pid]


class FileBackupSystem:
    """Automated file backup system for ransomware protection"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.backup_dir = "data/backups"
        self.shadow_copies = {}
        self.backup_thread = None
        self.is_active = False
        
    def start(self):
        """Start backup system"""
        if self.is_active:
            return
            
        os.makedirs(self.backup_dir, exist_ok=True)
        self.is_active = True
        self.backup_thread = threading.Thread(target=self._backup_loop)
        self.backup_thread.daemon = True
        self.backup_thread.start()
        
    def stop(self):
        """Stop backup system"""
        self.is_active = False
        if self.backup_thread:
            self.backup_thread.join(timeout=5)
            
    def _backup_loop(self):
        """Main backup loop"""
        while self.is_active:
            try:
                # Periodic backup of important files
                time.sleep(3600)  # Backup every hour
                self.create_shadow_copies()
            except Exception as e:
                self.logger.error(f"Backup error: {e}")
                
    def emergency_backup(self, folders: Set[str]):
        """Create emergency backup of specified folders"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        emergency_dir = os.path.join(self.backup_dir, f"emergency_{timestamp}")
        os.makedirs(emergency_dir, exist_ok=True)
        
        for folder in folders:
            if os.path.exists(folder):
                try:
                    folder_name = os.path.basename(folder)
                    dest = os.path.join(emergency_dir, folder_name)
                    
                    # Copy important files only (to save time)
                    self.selective_backup(folder, dest)
                    
                    self.logger.info(f"Emergency backup created: {dest}")
                except Exception as e:
                    self.logger.error(f"Backup failed for {folder}: {e}")
                    
    def selective_backup(self, source: str, dest: str):
        """Selective backup of important files"""
        important_extensions = [
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.pdf', '.txt', '.jpg', '.jpeg', '.png', '.gif',
            '.mp3', '.mp4', '.avi', '.mov', '.zip', '.rar'
        ]
        
        os.makedirs(dest, exist_ok=True)
        
        for root, dirs, files in os.walk(source):
            for file in files:
                if any(file.endswith(ext) for ext in important_extensions):
                    src_file = os.path.join(root, file)
                    
                    # Create relative path
                    rel_path = os.path.relpath(src_file, source)
                    dest_file = os.path.join(dest, rel_path)
                    
                    # Create dest directory
                    os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                    
                    # Copy file
                    try:
                        shutil.copy2(src_file, dest_file)
                    except:
                        pass
                        
    def create_shadow_copies(self):
        """Create shadow copies of important files"""
        # In real implementation, would use VSS on Windows
        pass
        
    def restore_file(self, file_path: str) -> bool:
        """Restore file from backup"""
        # Find most recent backup
        backup_file = self.find_backup(file_path)
        
        if backup_file and os.path.exists(backup_file):
            try:
                shutil.copy2(backup_file, file_path)
                self.logger.info(f"File restored: {file_path}")
                return True
            except Exception as e:
                self.logger.error(f"Restore failed: {e}")
                
        return False
    
    def find_backup(self, file_path: str) -> Optional[str]:
        """Find most recent backup of a file"""
        # Search in backup directory for matching file
        # In real implementation, would maintain index
        return None


class ShadowCopyProtector:
    """Protect Windows Shadow Copies from deletion"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.protected_commands = [
            'vssadmin delete shadows',
            'wmic shadowcopy delete',
            'bcdedit /set recoveryenabled no',
            'wbadmin delete catalog'
        ]
        
    def start(self):
        """Start shadow copy protection"""
        # In real implementation, would hook system calls
        pass
        
    def stop(self):
        """Stop shadow copy protection"""
        pass
        
    def check_deletion_attempt(self, process_info: Dict[str, Any]) -> bool:
        """Check if process attempted to delete shadow copies"""
        command = process_info.get('command', '').lower()
        
        for protected_cmd in self.protected_commands:
            if protected_cmd in command:
                self.logger.critical(f"Shadow copy deletion attempt: {command}")
                return True
                
        return False


class ProcessInjectionDetector:
    """Detect process injection attempts"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.suspicious_apis = [
            'CreateRemoteThread',
            'SetWindowsHookEx',
            'VirtualAllocEx',
            'WriteProcessMemory',
            'NtCreateThreadEx',
            'RtlCreateUserThread'
        ]
        
    def start(self):
        """Start injection detection"""
        # In real implementation, would monitor API calls
        pass
        
    def stop(self):
        """Stop injection detection"""
        pass
        
    def check_injection(self, process_info: Dict[str, Any]) -> bool:
        """Check for process injection attempts"""
        api_calls = process_info.get('api_calls', [])
        
        for api in api_calls:
            if api in self.suspicious_apis:
                self.logger.warning(f"Suspicious API call: {api}")
                return True
                
        return False


class CryptoAPIMonitor:
    """Monitor cryptographic API usage"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.crypto_apis = [
            'CryptEncrypt',
            'CryptDecrypt',
            'CryptGenKey',
            'CryptAcquireContext',
            'BCryptGenerateSymmetricKey',
            'BCryptEncrypt'
        ]
        self.process_crypto_usage = defaultdict(int)
        
    def start(self):
        """Start crypto API monitoring"""
        # In real implementation, would hook crypto APIs
        pass
        
    def stop(self):
        """Stop crypto API monitoring"""
        pass
        
    def check_crypto_usage(self, process_info: Dict[str, Any]) -> bool:
        """Check for excessive cryptographic API usage"""
        pid = process_info.get('pid')
        api_calls = process_info.get('api_calls', [])
        
        crypto_count = sum(1 for api in api_calls if api in self.crypto_apis)
        
        if crypto_count > 0:
            self.process_crypto_usage[pid] += crypto_count
            
            # Check for excessive usage
            if self.process_crypto_usage[pid] > 100:
                self.logger.warning(f"Excessive crypto API usage by PID {pid}")
                return True
                
        return False