"""
Real-time Protection Module
Monitors file system activities and provides real-time threat detection
"""
import os
import threading
import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
import psutil
from typing import Set, Dict, Any, List
from datetime import datetime, timedelta
import hashlib
import json

class RealtimeProtection(FileSystemEventHandler):
    """Real-time file system monitoring and protection"""
    
    def __init__(self, scanner, config: Dict[str, Any]):
        super().__init__()
        self.scanner = scanner
        self.config = config
        self.observer = Observer()
        self.is_active = False
        self.monitored_paths = set()
        self.scan_cache = {}
        self.cache_ttl = 300  # 5 minutes
        self.logger = logging.getLogger(__name__)
        self.threat_log = []
        self.process_monitor = ProcessMonitor()
        self.behavior_analyzer = BehaviorAnalyzer()
        
    def start(self):
        """Start real-time protection"""
        if self.is_active:
            return
            
        # Monitor common directories
        paths_to_monitor = [
            os.path.expanduser("~"),
            "/tmp",
            os.environ.get("TEMP", "/tmp"),
        ]
        
        for path in paths_to_monitor:
            if os.path.exists(path):
                self.observer.schedule(self, path, recursive=True)
                self.monitored_paths.add(path)
        
        self.observer.start()
        self.is_active = True
        
        # Start process monitoring
        self.process_monitor.start()
        
        self.logger.info("Real-time protection started")
        
    def stop(self):
        """Stop real-time protection"""
        if not self.is_active:
            return
            
        self.observer.stop()
        self.observer.join()
        self.is_active = False
        
        # Stop process monitoring
        self.process_monitor.stop()
        
        self.logger.info("Real-time protection stopped")
        
    def on_created(self, event):
        """Handle file creation event"""
        if not event.is_directory:
            self.scan_file_async(event.src_path)
            
    def on_modified(self, event):
        """Handle file modification event"""
        if not event.is_directory:
            # Check if file was recently scanned
            if not self.is_recently_scanned(event.src_path):
                self.scan_file_async(event.src_path)
                
    def on_moved(self, event):
        """Handle file move event"""
        if not event.is_directory:
            self.scan_file_async(event.dest_path)
            
    def scan_file_async(self, file_path: str):
        """Scan file asynchronously"""
        thread = threading.Thread(target=self._scan_file, args=(file_path,))
        thread.daemon = True
        thread.start()
        
    def _scan_file(self, file_path: str):
        """Internal method to scan file"""
        try:
            # Skip if file doesn't exist or is too large
            if not os.path.exists(file_path):
                return
                
            file_size = os.path.getsize(file_path)
            max_size = self.config.get('max_file_size_mb', 500) * 1024 * 1024
            
            if file_size > max_size:
                self.logger.debug(f"Skipping large file: {file_path}")
                return
            
            # Perform scan
            result = self.scanner.scan_file(file_path)
            
            # Update cache
            self.update_cache(file_path, result)
            
            # Handle threats
            if not result.get('is_safe', True):
                self.handle_threat_detection(result)
                
        except Exception as e:
            self.logger.error(f"Error scanning {file_path}: {e}")
            
    def is_recently_scanned(self, file_path: str) -> bool:
        """Check if file was recently scanned"""
        if file_path in self.scan_cache:
            cache_entry = self.scan_cache[file_path]
            cache_time = datetime.fromisoformat(cache_entry['scan_time'])
            
            if datetime.now() - cache_time < timedelta(seconds=self.cache_ttl):
                # Check if file has changed
                current_hash = self.calculate_quick_hash(file_path)
                if current_hash == cache_entry.get('file_hash'):
                    return True
                    
        return False
    
    def calculate_quick_hash(self, file_path: str) -> str:
        """Calculate quick hash for cache comparison"""
        try:
            # Read first and last 1KB for quick hash
            with open(file_path, 'rb') as f:
                first_kb = f.read(1024)
                f.seek(-1024, 2)
                last_kb = f.read(1024)
                
            return hashlib.md5(first_kb + last_kb).hexdigest()
        except Exception:
            return ""
            
    def update_cache(self, file_path: str, scan_result: Dict[str, Any]):
        """Update scan cache"""
        self.scan_cache[file_path] = {
            'scan_time': datetime.now().isoformat(),
            'file_hash': self.calculate_quick_hash(file_path),
            'is_safe': scan_result.get('is_safe', True)
        }
        
        # Clean old cache entries
        self.clean_cache()
        
    def clean_cache(self):
        """Remove old cache entries"""
        current_time = datetime.now()
        expired_keys = []
        
        for file_path, cache_entry in self.scan_cache.items():
            cache_time = datetime.fromisoformat(cache_entry['scan_time'])
            if current_time - cache_time > timedelta(seconds=self.cache_ttl):
                expired_keys.append(file_path)
                
        for key in expired_keys:
            del self.scan_cache[key]
            
    def handle_threat_detection(self, scan_result: Dict[str, Any]):
        """Handle detected threats"""
        threat_info = {
            'timestamp': datetime.now().isoformat(),
            'file_path': scan_result['file_path'],
            'threats': scan_result['threats'],
            'actions': scan_result.get('actions_taken', [])
        }
        
        self.threat_log.append(threat_info)
        
        # Notify user (in real app, this would show a system notification)
        self.logger.warning(f"Threat detected: {scan_result['file_path']}")
        
        # Log to file
        self.log_threat(threat_info)
        
    def log_threat(self, threat_info: Dict[str, Any]):
        """Log threat to file"""
        log_file = "data/logs/threats.json"
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        try:
            # Read existing logs
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    logs = json.load(f)
            else:
                logs = []
                
            # Add new threat
            logs.append(threat_info)
            
            # Keep only last 1000 entries
            logs = logs[-1000:]
            
            # Write back
            with open(log_file, 'w') as f:
                json.dump(logs, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Error logging threat: {e}")


class ProcessMonitor:
    """Monitor running processes for suspicious behavior"""
    
    def __init__(self):
        self.is_active = False
        self.monitor_thread = None
        self.suspicious_processes = set()
        self.logger = logging.getLogger(__name__)
        self.process_whitelist = self.load_process_whitelist()
        
    def load_process_whitelist(self) -> Set[str]:
        """Load trusted process whitelist"""
        whitelist = {
            'systemd', 'init', 'kernel', 'sshd', 'bash', 'sh',
            'python', 'python3', 'node', 'chrome', 'firefox',
            'explorer.exe', 'svchost.exe', 'system', 'csrss.exe',
        }
        return whitelist
    
    def start(self):
        """Start process monitoring"""
        if self.is_active:
            return
            
        self.is_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop(self):
        """Stop process monitoring"""
        self.is_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
            
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.is_active:
            try:
                self.check_processes()
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                self.logger.error(f"Process monitoring error: {e}")
                
    def check_processes(self):
        """Check running processes for suspicious behavior"""
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                # Skip whitelisted processes
                if proc.info['name'] in self.process_whitelist:
                    continue
                    
                # Check for suspicious patterns
                if self.is_suspicious_process(proc):
                    self.handle_suspicious_process(proc)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
    def is_suspicious_process(self, proc) -> bool:
        """Check if process shows suspicious behavior"""
        try:
            # Check for suspicious command line arguments
            cmdline = ' '.join(proc.info.get('cmdline', []))
            suspicious_args = [
                'powershell -enc', 'cmd /c', 'wmic', 'vssadmin',
                'bcdedit', 'wbadmin', 'shadowcopy', 'cipher /w',
            ]
            
            for pattern in suspicious_args:
                if pattern.lower() in cmdline.lower():
                    return True
            
            # Check for process hollowing indicators
            if proc.memory_info().vms > 1000000000:  # > 1GB memory
                if proc.info['name'] in ['notepad.exe', 'calc.exe']:
                    return True
            
            # Check for unsigned or suspicious executables
            exe_path = proc.info.get('exe', '')
            if exe_path and os.path.exists(exe_path):
                if self.is_suspicious_executable(exe_path):
                    return True
                    
        except Exception:
            pass
            
        return False
    
    def is_suspicious_executable(self, exe_path: str) -> bool:
        """Check if executable is suspicious"""
        suspicious_locations = [
            '/tmp', '/var/tmp', os.environ.get('TEMP', ''),
            os.path.expanduser('~/Downloads'),
        ]
        
        for location in suspicious_locations:
            if location and exe_path.startswith(location):
                return True
                
        return False
    
    def handle_suspicious_process(self, proc):
        """Handle suspicious process detection"""
        if proc.pid not in self.suspicious_processes:
            self.suspicious_processes.add(proc.pid)
            self.logger.warning(f"Suspicious process detected: {proc.info['name']} (PID: {proc.pid})")
            
            # In a real implementation, we might:
            # - Terminate the process
            # - Alert the user
            # - Log for further analysis


class BehaviorAnalyzer:
    """Analyze system behavior for anomalies"""
    
    def __init__(self):
        self.baseline = {}
        self.anomalies = []
        self.logger = logging.getLogger(__name__)
        
    def establish_baseline(self):
        """Establish baseline system behavior"""
        self.baseline = {
            'cpu_usage': psutil.cpu_percent(interval=1),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_io': psutil.disk_io_counters(),
            'network_io': psutil.net_io_counters(),
            'process_count': len(psutil.pids()),
        }
        
    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect behavioral anomalies"""
        anomalies = []
        
        current = {
            'cpu_usage': psutil.cpu_percent(interval=1),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_io': psutil.disk_io_counters(),
            'network_io': psutil.net_io_counters(),
            'process_count': len(psutil.pids()),
        }
        
        # Check for CPU spike (potential cryptominer)
        if current['cpu_usage'] > self.baseline.get('cpu_usage', 50) + 40:
            anomalies.append({
                'type': 'cpu_spike',
                'severity': 'medium',
                'description': f"Unusual CPU usage: {current['cpu_usage']}%"
            })
        
        # Check for memory spike (potential memory leak or malware)
        if current['memory_usage'] > self.baseline.get('memory_usage', 50) + 30:
            anomalies.append({
                'type': 'memory_spike',
                'severity': 'medium',
                'description': f"Unusual memory usage: {current['memory_usage']}%"
            })
        
        # Check for excessive disk I/O (potential ransomware)
        if self.baseline.get('disk_io'):
            disk_write_increase = (
                current['disk_io'].write_bytes - 
                self.baseline['disk_io'].write_bytes
            ) / 1024 / 1024  # Convert to MB
            
            if disk_write_increase > 1000:  # > 1GB written
                anomalies.append({
                    'type': 'excessive_disk_write',
                    'severity': 'high',
                    'description': f"Excessive disk writes: {disk_write_increase:.2f} MB"
                })
        
        # Check for network anomalies (potential data exfiltration)
        if self.baseline.get('network_io'):
            network_sent_increase = (
                current['network_io'].bytes_sent - 
                self.baseline['network_io'].bytes_sent
            ) / 1024 / 1024  # Convert to MB
            
            if network_sent_increase > 100:  # > 100MB sent
                anomalies.append({
                    'type': 'excessive_network_upload',
                    'severity': 'high',
                    'description': f"Excessive network upload: {network_sent_increase:.2f} MB"
                })
        
        # Check for process proliferation (potential worm/fork bomb)
        process_increase = current['process_count'] - self.baseline.get('process_count', 100)
        if process_increase > 50:
            anomalies.append({
                'type': 'process_proliferation',
                'severity': 'high',
                'description': f"Unusual process creation: {process_increase} new processes"
            })
        
        return anomalies