"""
Network Security and Firewall Module
Provides network protection, firewall capabilities, and intrusion detection
"""
import socket
import struct
import threading
import time
import json
import logging
from typing import Dict, List, Set, Any, Tuple, Optional
from datetime import datetime, timedelta
from collections import defaultdict, deque
import ipaddress
import hashlib

class NetworkSecurityManager:
    """Main network security manager"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.firewall = Firewall(config)
        self.ids = IntrusionDetectionSystem()
        self.ips = IntrusionPreventionSystem()
        self.dns_filter = DNSFilter()
        self.port_scanner = PortScanDetector()
        self.ddos_protector = DDoSProtection()
        self.ssl_inspector = SSLInspector()
        self.is_active = False
        
    def start(self):
        """Start network security monitoring"""
        if self.is_active:
            return
            
        self.firewall.start()
        self.ids.start()
        self.port_scanner.start()
        self.ddos_protector.start()
        self.is_active = True
        
        self.logger.info("Network security started")
        
    def stop(self):
        """Stop network security monitoring"""
        if not self.is_active:
            return
            
        self.firewall.stop()
        self.ids.stop()
        self.port_scanner.stop()
        self.ddos_protector.stop()
        self.is_active = False
        
        self.logger.info("Network security stopped")


class Firewall:
    """Network firewall implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.rules = FirewallRules()
        self.connection_tracker = ConnectionTracker()
        self.blocked_ips = set()
        self.allowed_ips = set()
        self.monitor_thread = None
        self.is_active = False
        
        # Load default rules
        self.load_default_rules()
        
    def load_default_rules(self):
        """Load default firewall rules"""
        # Block common malware ports
        for port in self.config.get('blocked_ports', []):
            self.rules.add_rule('block', port=port)
            
        # Allow common services
        allowed_ports = [80, 443, 22, 21, 25, 110, 143, 993, 995]
        for port in allowed_ports:
            self.rules.add_rule('allow', port=port)
            
        # Block suspicious IP ranges
        suspicious_ranges = [
            '10.0.0.0/8',     # Private range (depends on context)
            '192.168.0.0/16', # Private range (depends on context)
            '224.0.0.0/4',    # Multicast
        ]
        
        # Allow local connections
        self.allowed_ips.add('127.0.0.1')
        self.allowed_ips.add('::1')
        
    def start(self):
        """Start firewall monitoring"""
        if self.is_active:
            return
            
        self.is_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_connections)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop(self):
        """Stop firewall monitoring"""
        self.is_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
            
    def _monitor_connections(self):
        """Monitor network connections"""
        while self.is_active:
            try:
                # Check active connections
                connections = self.get_network_connections()
                
                for conn in connections:
                    if not self.check_connection(conn):
                        self.block_connection(conn)
                        
                time.sleep(1)
            except Exception as e:
                self.logger.error(f"Firewall monitoring error: {e}")
                
    def get_network_connections(self) -> List[Dict[str, Any]]:
        """Get list of network connections"""
        # Simplified - actual implementation would use netstat or psutil
        connections = []
        
        try:
            import psutil
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED':
                    connections.append({
                        'local_addr': conn.laddr,
                        'remote_addr': conn.raddr,
                        'status': conn.status,
                        'pid': conn.pid
                    })
        except ImportError:
            pass
            
        return connections
    
    def check_connection(self, conn: Dict[str, Any]) -> bool:
        """Check if connection is allowed"""
        if not conn.get('remote_addr'):
            return True
            
        remote_ip = conn['remote_addr'].ip if hasattr(conn['remote_addr'], 'ip') else conn['remote_addr'][0]
        remote_port = conn['remote_addr'].port if hasattr(conn['remote_addr'], 'port') else conn['remote_addr'][1]
        
        # Check if IP is blocked
        if remote_ip in self.blocked_ips:
            self.logger.warning(f"Blocked connection to {remote_ip}")
            return False
            
        # Check if IP is explicitly allowed
        if remote_ip in self.allowed_ips:
            return True
            
        # Check firewall rules
        if not self.rules.is_allowed(remote_ip, remote_port):
            self.logger.warning(f"Connection blocked by rule: {remote_ip}:{remote_port}")
            return False
            
        # Track connection
        self.connection_tracker.track(conn)
        
        return True
    
    def block_connection(self, conn: Dict[str, Any]):
        """Block a network connection"""
        # In real implementation, would use iptables or Windows Firewall API
        self.logger.warning(f"Blocking connection: {conn}")
        
        if conn.get('remote_addr'):
            remote_ip = conn['remote_addr'].ip if hasattr(conn['remote_addr'], 'ip') else conn['remote_addr'][0]
            self.blocked_ips.add(remote_ip)
    
    def add_blocked_ip(self, ip: str):
        """Add IP to blocklist"""
        self.blocked_ips.add(ip)
        self.logger.info(f"Added {ip} to blocklist")
        
    def remove_blocked_ip(self, ip: str):
        """Remove IP from blocklist"""
        self.blocked_ips.discard(ip)
        self.logger.info(f"Removed {ip} from blocklist")


class FirewallRules:
    """Manage firewall rules"""
    
    def __init__(self):
        self.rules = []
        
    def add_rule(self, action: str, ip: str = None, port: int = None, 
                protocol: str = None):
        """Add a firewall rule"""
        rule = {
            'action': action,  # 'allow' or 'block'
            'ip': ip,
            'port': port,
            'protocol': protocol,
            'created': datetime.now().isoformat()
        }
        self.rules.append(rule)
        
    def is_allowed(self, ip: str, port: int, protocol: str = 'tcp') -> bool:
        """Check if connection is allowed by rules"""
        for rule in self.rules:
            if self._match_rule(rule, ip, port, protocol):
                return rule['action'] == 'allow'
                
        # Default allow if no rule matches
        return True
    
    def _match_rule(self, rule: Dict[str, Any], ip: str, port: int, 
                   protocol: str) -> bool:
        """Check if rule matches connection"""
        if rule['ip'] and not self._match_ip(rule['ip'], ip):
            return False
            
        if rule['port'] and rule['port'] != port:
            return False
            
        if rule['protocol'] and rule['protocol'] != protocol:
            return False
            
        return True
    
    def _match_ip(self, rule_ip: str, target_ip: str) -> bool:
        """Check if IP matches rule (supports CIDR)"""
        try:
            if '/' in rule_ip:
                # CIDR notation
                network = ipaddress.ip_network(rule_ip)
                return ipaddress.ip_address(target_ip) in network
            else:
                return rule_ip == target_ip
        except ValueError:
            return False


class ConnectionTracker:
    """Track network connections for analysis"""
    
    def __init__(self):
        self.connections = defaultdict(list)
        self.connection_counts = defaultdict(int)
        
    def track(self, conn: Dict[str, Any]):
        """Track a connection"""
        if conn.get('remote_addr'):
            remote_ip = conn['remote_addr'].ip if hasattr(conn['remote_addr'], 'ip') else conn['remote_addr'][0]
            
            self.connections[remote_ip].append({
                'timestamp': datetime.now().isoformat(),
                'port': conn['remote_addr'].port if hasattr(conn['remote_addr'], 'port') else conn['remote_addr'][1],
                'pid': conn.get('pid')
            })
            
            self.connection_counts[remote_ip] += 1
            
            # Keep only recent connections (last hour)
            cutoff = datetime.now() - timedelta(hours=1)
            self.connections[remote_ip] = [
                c for c in self.connections[remote_ip]
                if datetime.fromisoformat(c['timestamp']) > cutoff
            ]
    
    def get_connection_stats(self, ip: str) -> Dict[str, Any]:
        """Get connection statistics for an IP"""
        return {
            'total_connections': self.connection_counts.get(ip, 0),
            'recent_connections': len(self.connections.get(ip, [])),
            'connections': self.connections.get(ip, [])
        }


class IntrusionDetectionSystem:
    """IDS for detecting network intrusions"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.signatures = self.load_signatures()
        self.alerts = []
        self.monitor_thread = None
        self.is_active = False
        
    def load_signatures(self) -> List[Dict[str, Any]]:
        """Load IDS signatures"""
        signatures = [
            {
                'name': 'SQL Injection',
                'pattern': r'(union|select|insert|update|delete|drop)\s+(from|into|table)',
                'severity': 'high'
            },
            {
                'name': 'XSS Attack',
                'pattern': r'<script[^>]*>.*?</script>',
                'severity': 'medium'
            },
            {
                'name': 'Command Injection',
                'pattern': r'(;|\||&&)\s*(ls|cat|rm|wget|curl|nc|bash|sh)',
                'severity': 'critical'
            },
            {
                'name': 'Directory Traversal',
                'pattern': r'\.\./|\.\.\\',
                'severity': 'medium'
            },
            {
                'name': 'Buffer Overflow',
                'pattern': r'(\x90{100,}|\x41{100,})',  # NOP sled or A's
                'severity': 'critical'
            }
        ]
        return signatures
    
    def start(self):
        """Start IDS monitoring"""
        if self.is_active:
            return
            
        self.is_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_traffic)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop(self):
        """Stop IDS monitoring"""
        self.is_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
            
    def _monitor_traffic(self):
        """Monitor network traffic for intrusions"""
        while self.is_active:
            try:
                # In real implementation, would capture and analyze packets
                time.sleep(5)
            except Exception as e:
                self.logger.error(f"IDS monitoring error: {e}")
                
    def analyze_packet(self, packet_data: bytes) -> Optional[Dict[str, Any]]:
        """Analyze packet for intrusion signatures"""
        try:
            data_str = packet_data.decode('utf-8', errors='ignore')
            
            for signature in self.signatures:
                import re
                if re.search(signature['pattern'], data_str, re.IGNORECASE):
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'signature': signature['name'],
                        'severity': signature['severity'],
                        'data_sample': data_str[:100]
                    }
                    self.alerts.append(alert)
                    self.logger.warning(f"IDS Alert: {signature['name']}")
                    return alert
                    
        except Exception as e:
            self.logger.debug(f"Packet analysis error: {e}")
            
        return None


class IntrusionPreventionSystem:
    """IPS for preventing detected intrusions"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.blocked_sources = set()
        self.prevention_rules = []
        
    def block_intrusion(self, source_ip: str, reason: str):
        """Block an intrusion attempt"""
        self.blocked_sources.add(source_ip)
        self.logger.warning(f"IPS blocked {source_ip}: {reason}")
        
        # Log the block
        self.log_prevention({
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip,
            'reason': reason,
            'action': 'blocked'
        })
        
    def log_prevention(self, event: Dict[str, Any]):
        """Log prevention event"""
        log_file = "data/logs/ips_events.json"
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    logs = json.load(f)
            else:
                logs = []
                
            logs.append(event)
            logs = logs[-1000:]  # Keep last 1000 events
            
            with open(log_file, 'w') as f:
                json.dump(logs, f, indent=2)
        except Exception as e:
            self.logger.error(f"IPS logging error: {e}")


class PortScanDetector:
    """Detect port scanning attempts"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.scan_tracker = defaultdict(lambda: deque(maxlen=100))
        self.monitor_thread = None
        self.is_active = False
        
    def start(self):
        """Start port scan detection"""
        if self.is_active:
            return
            
        self.is_active = True
        self.monitor_thread = threading.Thread(target=self._detect_scans)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop(self):
        """Stop port scan detection"""
        self.is_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
            
    def _detect_scans(self):
        """Detect port scanning patterns"""
        while self.is_active:
            try:
                # Check for scanning patterns
                for ip, ports in self.scan_tracker.items():
                    if self.is_port_scan(ports):
                        self.handle_port_scan(ip)
                        
                time.sleep(10)
            except Exception as e:
                self.logger.error(f"Port scan detection error: {e}")
                
    def track_connection(self, source_ip: str, dest_port: int):
        """Track connection attempt"""
        self.scan_tracker[source_ip].append({
            'port': dest_port,
            'timestamp': time.time()
        })
        
    def is_port_scan(self, port_attempts: deque) -> bool:
        """Check if connection pattern indicates port scanning"""
        if len(port_attempts) < 10:
            return False
            
        # Check for rapid connections to different ports
        recent_attempts = [p for p in port_attempts 
                         if time.time() - p['timestamp'] < 60]
        
        if len(recent_attempts) > 20:
            unique_ports = len(set(p['port'] for p in recent_attempts))
            if unique_ports > 15:
                return True
                
        return False
    
    def handle_port_scan(self, source_ip: str):
        """Handle detected port scan"""
        self.logger.warning(f"Port scan detected from {source_ip}")
        
        # Clear tracking for this IP
        del self.scan_tracker[source_ip]


class DDoSProtection:
    """DDoS attack protection"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.connection_limits = defaultdict(int)
        self.request_tracker = defaultdict(lambda: deque(maxlen=1000))
        self.monitor_thread = None
        self.is_active = False
        
    def start(self):
        """Start DDoS protection"""
        if self.is_active:
            return
            
        self.is_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_traffic)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop(self):
        """Stop DDoS protection"""
        self.is_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
            
    def _monitor_traffic(self):
        """Monitor traffic for DDoS patterns"""
        while self.is_active:
            try:
                self.check_ddos_patterns()
                time.sleep(5)
            except Exception as e:
                self.logger.error(f"DDoS monitoring error: {e}")
                
    def track_request(self, source_ip: str):
        """Track incoming request"""
        self.request_tracker[source_ip].append(time.time())
        self.connection_limits[source_ip] += 1
        
    def check_ddos_patterns(self):
        """Check for DDoS attack patterns"""
        current_time = time.time()
        
        for ip, timestamps in self.request_tracker.items():
            # Count recent requests (last minute)
            recent_requests = sum(1 for t in timestamps if current_time - t < 60)
            
            # Check for excessive requests
            if recent_requests > 100:  # More than 100 requests per minute
                self.handle_ddos_attack(ip, recent_requests)
                
    def handle_ddos_attack(self, source_ip: str, request_count: int):
        """Handle detected DDoS attack"""
        self.logger.critical(f"DDoS attack detected from {source_ip}: {request_count} requests/min")
        
        # Clear tracking
        del self.request_tracker[source_ip]
        del self.connection_limits[source_ip]


class DNSFilter:
    """DNS filtering for malicious domains"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.blocked_domains = self.load_blocked_domains()
        self.domain_cache = {}
        
    def load_blocked_domains(self) -> Set[str]:
        """Load list of blocked domains"""
        blocked = {
            'malware.com', 'phishing.net', 'exploit-kit.org',
            'c2server.com', 'ransomware.net', 'trojan.org'
        }
        return blocked
    
    def check_domain(self, domain: str) -> bool:
        """Check if domain is safe"""
        # Check cache
        if domain in self.domain_cache:
            return self.domain_cache[domain]
            
        # Check blocklist
        if domain in self.blocked_domains:
            self.logger.warning(f"Blocked DNS query for malicious domain: {domain}")
            self.domain_cache[domain] = False
            return False
            
        # Check for suspicious patterns
        if self.is_suspicious_domain(domain):
            self.logger.warning(f"Suspicious domain detected: {domain}")
            self.domain_cache[domain] = False
            return False
            
        self.domain_cache[domain] = True
        return True
    
    def is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain appears suspicious"""
        suspicious_patterns = [
            r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}',  # IP-like domain
            r'[a-z0-9]{32,}',  # Long random string (possible DGA)
            r'(xn--)',  # Punycode (possible homograph attack)
        ]
        
        import re
        for pattern in suspicious_patterns:
            if re.search(pattern, domain):
                return True
                
        # Check for excessive subdomains
        if domain.count('.') > 4:
            return True
            
        return False


class SSLInspector:
    """SSL/TLS traffic inspection"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.certificate_cache = {}
        
    def inspect_certificate(self, cert_data: bytes) -> Dict[str, Any]:
        """Inspect SSL certificate"""
        cert_hash = hashlib.sha256(cert_data).hexdigest()
        
        # Check cache
        if cert_hash in self.certificate_cache:
            return self.certificate_cache[cert_hash]
            
        result = {
            'valid': True,
            'issues': [],
            'hash': cert_hash
        }
        
        # Basic certificate checks
        # In real implementation, would parse and validate certificate
        
        self.certificate_cache[cert_hash] = result
        return result
    
    def check_ssl_connection(self, host: str, port: int = 443) -> bool:
        """Check SSL connection security"""
        try:
            # In real implementation, would establish SSL connection and verify
            return True
        except Exception as e:
            self.logger.error(f"SSL inspection error for {host}:{port}: {e}")
            return False