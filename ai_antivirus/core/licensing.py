"""
Enterprise Licensing and Activation System
Handles product licensing, activation, and subscription management
"""
import os
import json
import hashlib
import hmac
import base64
import uuid
import requests
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
import logging
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import sqlite3

class LicensingSystem:
    """Complete licensing and activation management"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.license_server = "https://license.ai-antivirus.com/api/v2"
        self.product_id = "AIAV-PRO-2024"
        
        # License storage
        self.license_file = Path.home() / ".ai-antivirus" / "license.dat"
        self.license_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Current license
        self.current_license = None
        self.is_activated = False
        self.license_type = "trial"  # trial, basic, pro, enterprise
        
        # Hardware ID for activation
        self.hardware_id = self.generate_hardware_id()
        
        # Initialize database
        self.init_database()
        
        # Load existing license
        self.load_license()
    
    def init_database(self):
        """Initialize licensing database"""
        self.db_path = "data/licensing.db"
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS licenses (
                license_key TEXT PRIMARY KEY,
                product_id TEXT,
                license_type TEXT,
                activation_date DATE,
                expiry_date DATE,
                hardware_id TEXT,
                features TEXT,
                status TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activation_history (
                activation_id TEXT PRIMARY KEY,
                license_key TEXT,
                hardware_id TEXT,
                activation_time DATE,
                ip_address TEXT,
                status TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def generate_hardware_id(self) -> str:
        """Generate unique hardware ID for activation"""
        import platform
        import subprocess
        
        components = []
        
        # Machine name
        components.append(platform.node())
        
        # Processor
        components.append(platform.processor())
        
        # Platform
        components.append(platform.platform())
        
        # MAC address
        try:
            import uuid
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) 
                          for i in range(0,48,8)][::-1])
            components.append(mac)
        except:
            pass
        
        # Windows: Get motherboard serial
        if platform.system() == "Windows":
            try:
                result = subprocess.run(
                    ["wmic", "baseboard", "get", "serialnumber"],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    serial = result.stdout.split('\n')[1].strip()
                    components.append(serial)
            except:
                pass
        
        # Linux: Get machine-id
        elif platform.system() == "Linux":
            try:
                with open('/etc/machine-id', 'r') as f:
                    components.append(f.read().strip())
            except:
                pass
        
        # macOS: Get hardware UUID
        elif platform.system() == "Darwin":
            try:
                result = subprocess.run(
                    ["system_profiler", "SPHardwareDataType"],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'Hardware UUID' in line:
                            uuid_str = line.split(':')[1].strip()
                            components.append(uuid_str)
                            break
            except:
                pass
        
        # Generate hash of components
        hw_string = '|'.join(components)
        hw_id = hashlib.sha256(hw_string.encode()).hexdigest()
        
        return hw_id
    
    def activate_license(self, license_key: str) -> Tuple[bool, str]:
        """Activate product with license key"""
        try:
            # Validate license key format
            if not self.validate_key_format(license_key):
                return False, "Invalid license key format"
            
            # Check if already activated with this key
            if self.is_key_activated(license_key):
                return False, "License key already activated"
            
            # Online activation
            activation_result = self.online_activation(license_key)
            
            if activation_result['success']:
                # Save license
                self.save_license(activation_result['license'])
                self.current_license = activation_result['license']
                self.is_activated = True
                self.license_type = activation_result['license']['type']
                
                # Record activation
                self.record_activation(license_key, activation_result)
                
                return True, "License activated successfully"
            else:
                # Try offline activation
                offline_result = self.offline_activation(license_key)
                if offline_result['success']:
                    self.save_license(offline_result['license'])
                    self.current_license = offline_result['license']
                    self.is_activated = True
                    return True, "License activated offline"
                else:
                    return False, offline_result.get('error', 'Activation failed')
                    
        except Exception as e:
            self.logger.error(f"Activation error: {e}")
            return False, str(e)
    
    def validate_key_format(self, license_key: str) -> bool:
        """Validate license key format"""
        # Format: XXXX-XXXX-XXXX-XXXX-XXXX
        parts = license_key.split('-')
        
        if len(parts) != 5:
            return False
        
        for part in parts:
            if len(part) != 4 or not part.isalnum():
                return False
        
        return True
    
    def is_key_activated(self, license_key: str) -> bool:
        """Check if license key is already activated"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT status FROM licenses
            WHERE license_key = ? AND status = 'active'
        ''', (license_key,))
        
        result = cursor.fetchone()
        conn.close()
        
        return result is not None
    
    def online_activation(self, license_key: str) -> Dict[str, Any]:
        """Activate license online"""
        try:
            # Prepare activation request
            activation_data = {
                'license_key': license_key,
                'hardware_id': self.hardware_id,
                'product_id': self.product_id,
                'version': '2.0.0',
                'os': platform.system(),
                'timestamp': datetime.now().isoformat()
            }
            
            # Sign request
            signature = self.sign_request(activation_data)
            activation_data['signature'] = signature
            
            # Send activation request (simulated)
            # In production, would make actual API call
            response = self.simulate_server_response(license_key)
            
            if response['status'] == 'success':
                license_data = {
                    'key': license_key,
                    'type': response['license_type'],
                    'expiry': response['expiry_date'],
                    'features': response['features'],
                    'hardware_id': self.hardware_id,
                    'activation_date': datetime.now().isoformat()
                }
                
                return {
                    'success': True,
                    'license': license_data
                }
            else:
                return {
                    'success': False,
                    'error': response.get('message', 'Activation failed')
                }
                
        except Exception as e:
            self.logger.error(f"Online activation error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def offline_activation(self, license_key: str) -> Dict[str, Any]:
        """Offline license activation"""
        try:
            # Verify offline license key
            if self.verify_offline_key(license_key):
                # Extract license info from key
                license_info = self.decode_offline_key(license_key)
                
                return {
                    'success': True,
                    'license': license_info
                }
            else:
                return {
                    'success': False,
                    'error': 'Invalid offline license key'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def simulate_server_response(self, license_key: str) -> Dict[str, Any]:
        """Simulate license server response"""
        # In production, this would be an actual API call
        
        # Different license types based on key prefix
        if license_key.startswith('TRIA'):
            return {
                'status': 'success',
                'license_type': 'trial',
                'expiry_date': (datetime.now() + timedelta(days=30)).isoformat(),
                'features': ['basic_scan', 'real_time'],
                'max_devices': 1
            }
        elif license_key.startswith('BASI'):
            return {
                'status': 'success',
                'license_type': 'basic',
                'expiry_date': (datetime.now() + timedelta(days=365)).isoformat(),
                'features': ['basic_scan', 'real_time', 'web_protection'],
                'max_devices': 3
            }
        elif license_key.startswith('PROM'):
            return {
                'status': 'success',
                'license_type': 'pro',
                'expiry_date': (datetime.now() + timedelta(days=365)).isoformat(),
                'features': [
                    'basic_scan', 'real_time', 'web_protection',
                    'email_protection', 'ransomware_shield', 'firewall',
                    'sandbox', 'vpn'
                ],
                'max_devices': 5
            }
        elif license_key.startswith('ENTR'):
            return {
                'status': 'success',
                'license_type': 'enterprise',
                'expiry_date': (datetime.now() + timedelta(days=365)).isoformat(),
                'features': ['all'],
                'max_devices': 'unlimited'
            }
        else:
            return {
                'status': 'error',
                'message': 'Invalid license key'
            }
    
    def sign_request(self, data: Dict[str, Any]) -> str:
        """Sign activation request"""
        # Create signature using HMAC
        secret_key = b"AI-ANTIVIRUS-SECRET-2024"
        
        message = json.dumps(data, sort_keys=True).encode()
        signature = hmac.new(secret_key, message, hashlib.sha256).hexdigest()
        
        return signature
    
    def verify_offline_key(self, license_key: str) -> bool:
        """Verify offline license key"""
        # Check key checksum
        parts = license_key.split('-')
        if len(parts) != 5:
            return False
        
        # Last part is checksum
        key_data = '-'.join(parts[:-1])
        checksum = parts[-1]
        
        calculated = hashlib.md5(key_data.encode()).hexdigest()[:4].upper()
        
        return calculated == checksum
    
    def decode_offline_key(self, license_key: str) -> Dict[str, Any]:
        """Decode offline license key"""
        # Extract information encoded in key
        parts = license_key.split('-')
        
        # Determine type from first part
        type_map = {
            'TRIA': 'trial',
            'BASI': 'basic',
            'PROM': 'pro',
            'ENTR': 'enterprise'
        }
        
        license_type = type_map.get(parts[0], 'trial')
        
        return {
            'key': license_key,
            'type': license_type,
            'expiry': (datetime.now() + timedelta(days=365)).isoformat(),
            'features': self.get_features_for_type(license_type),
            'hardware_id': self.hardware_id,
            'activation_date': datetime.now().isoformat()
        }
    
    def get_features_for_type(self, license_type: str) -> list:
        """Get features for license type"""
        features_map = {
            'trial': ['basic_scan', 'real_time'],
            'basic': ['basic_scan', 'real_time', 'web_protection'],
            'pro': [
                'basic_scan', 'real_time', 'web_protection',
                'email_protection', 'ransomware_shield', 'firewall',
                'sandbox', 'cloud_backup'
            ],
            'enterprise': ['all']
        }
        
        return features_map.get(license_type, ['basic_scan'])
    
    def save_license(self, license_data: Dict[str, Any]):
        """Save license to encrypted file"""
        try:
            # Encrypt license data
            key = self.derive_encryption_key()
            fernet = Fernet(key)
            
            encrypted = fernet.encrypt(json.dumps(license_data).encode())
            
            # Save to file
            with open(self.license_file, 'wb') as f:
                f.write(encrypted)
            
            # Save to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO licenses
                (license_key, product_id, license_type, activation_date,
                 expiry_date, hardware_id, features, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                license_data['key'],
                self.product_id,
                license_data['type'],
                license_data['activation_date'],
                license_data['expiry'],
                license_data['hardware_id'],
                json.dumps(license_data['features']),
                'active'
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to save license: {e}")
    
    def load_license(self) -> bool:
        """Load and validate existing license"""
        try:
            if not self.license_file.exists():
                return False
            
            # Decrypt license file
            key = self.derive_encryption_key()
            fernet = Fernet(key)
            
            with open(self.license_file, 'rb') as f:
                encrypted = f.read()
            
            decrypted = fernet.decrypt(encrypted)
            license_data = json.loads(decrypted)
            
            # Validate license
            if self.validate_license(license_data):
                self.current_license = license_data
                self.is_activated = True
                self.license_type = license_data['type']
                return True
            else:
                # License invalid, remove it
                self.license_file.unlink()
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to load license: {e}")
            return False
    
    def validate_license(self, license_data: Dict[str, Any]) -> bool:
        """Validate loaded license"""
        try:
            # Check hardware ID
            if license_data.get('hardware_id') != self.hardware_id:
                self.logger.warning("Hardware ID mismatch")
                return False
            
            # Check expiry
            expiry = datetime.fromisoformat(license_data['expiry'])
            if expiry < datetime.now():
                self.logger.warning("License expired")
                return False
            
            # Verify signature if present
            if 'signature' in license_data:
                if not self.verify_license_signature(license_data):
                    self.logger.warning("Invalid license signature")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"License validation error: {e}")
            return False
    
    def verify_license_signature(self, license_data: Dict[str, Any]) -> bool:
        """Verify license signature"""
        # In production, would use public key cryptography
        signature = license_data.get('signature')
        
        # Remove signature from data for verification
        data_copy = license_data.copy()
        del data_copy['signature']
        
        expected = self.sign_request(data_copy)
        
        return signature == expected
    
    def derive_encryption_key(self) -> bytes:
        """Derive encryption key from hardware ID"""
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'AI-ANTIVIRUS-SALT',
            iterations=100000
        )
        
        key = base64.urlsafe_b64encode(
            kdf.derive(self.hardware_id.encode())
        )
        
        return key
    
    def record_activation(self, license_key: str, activation_result: Dict[str, Any]):
        """Record activation in history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            activation_id = str(uuid.uuid4())
            
            cursor.execute('''
                INSERT INTO activation_history
                (activation_id, license_key, hardware_id, activation_time,
                 ip_address, status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                activation_id,
                license_key,
                self.hardware_id,
                datetime.now().isoformat(),
                self.get_public_ip(),
                'success' if activation_result['success'] else 'failed'
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to record activation: {e}")
    
    def get_public_ip(self) -> str:
        """Get public IP address"""
        try:
            response = requests.get('https://api.ipify.org', timeout=5)
            return response.text
        except:
            return 'unknown'
    
    def check_license_status(self) -> Dict[str, Any]:
        """Check current license status"""
        if not self.is_activated or not self.current_license:
            return {
                'activated': False,
                'type': 'none',
                'status': 'not_activated'
            }
        
        expiry = datetime.fromisoformat(self.current_license['expiry'])
        days_left = (expiry - datetime.now()).days
        
        return {
            'activated': True,
            'type': self.license_type,
            'status': 'active' if days_left > 0 else 'expired',
            'expiry': expiry.isoformat(),
            'days_left': max(0, days_left),
            'features': self.current_license.get('features', [])
        }
    
    def is_feature_enabled(self, feature: str) -> bool:
        """Check if a feature is enabled in current license"""
        if not self.is_activated or not self.current_license:
            # Allow basic features in trial mode
            return feature in ['basic_scan', 'real_time']
        
        features = self.current_license.get('features', [])
        
        return 'all' in features or feature in features
    
    def generate_trial_key(self) -> str:
        """Generate a trial license key"""
        # Format: TRIA-XXXX-XXXX-XXXX-CHKS
        import random
        import string
        
        parts = ['TRIA']
        
        for _ in range(3):
            part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
            parts.append(part)
        
        # Calculate checksum
        key_data = '-'.join(parts)
        checksum = hashlib.md5(key_data.encode()).hexdigest()[:4].upper()
        parts.append(checksum)
        
        return '-'.join(parts)
    
    def deactivate_license(self) -> bool:
        """Deactivate current license"""
        try:
            if self.current_license:
                # Notify server of deactivation (if online)
                self.notify_deactivation()
                
                # Remove local license
                if self.license_file.exists():
                    self.license_file.unlink()
                
                # Update database
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE licenses
                    SET status = 'deactivated'
                    WHERE license_key = ?
                ''', (self.current_license['key'],))
                
                conn.commit()
                conn.close()
                
                self.current_license = None
                self.is_activated = False
                self.license_type = 'trial'
                
                return True
                
        except Exception as e:
            self.logger.error(f"Deactivation error: {e}")
            
        return False
    
    def notify_deactivation(self):
        """Notify license server of deactivation"""
        # In production, would make API call
        pass
    
    def transfer_license(self, new_hardware_id: str) -> bool:
        """Transfer license to new hardware"""
        # In production, would require server validation
        if self.current_license:
            self.current_license['hardware_id'] = new_hardware_id
            self.hardware_id = new_hardware_id
            self.save_license(self.current_license)
            return True
        return False