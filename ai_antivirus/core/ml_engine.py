"""
Machine Learning Engine for Threat Detection
"""
import os
import hashlib
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
from typing import List, Dict, Any, Tuple
import logging
from datetime import datetime
import json

class AIThreatDetector:
    """Advanced AI-based threat detection engine"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_extractors = {}
        self.threat_database = {}
        self.logger = logging.getLogger(__name__)
        self.confidence_threshold = 0.85
        self.initialize_models()
        
    def initialize_models(self):
        """Initialize multiple ML models for ensemble detection"""
        # Random Forest for general malware detection
        self.models['random_forest'] = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42
        )
        
        # Gradient Boosting for advanced threats
        self.models['gradient_boost'] = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=10,
            random_state=42
        )
        
        # Neural Network for complex pattern recognition
        self.models['neural_network'] = MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),
            activation='relu',
            solver='adam',
            max_iter=1000,
            random_state=42
        )
        
        # Initialize scalers for each model
        for model_name in self.models.keys():
            self.scalers[model_name] = StandardScaler()
    
    def extract_features(self, file_path: str) -> Dict[str, Any]:
        """Extract features from a file for ML analysis"""
        features = {}
        
        try:
            # File metadata features
            stat_info = os.stat(file_path)
            features['file_size'] = stat_info.st_size
            features['creation_time'] = stat_info.st_ctime
            features['modification_time'] = stat_info.st_mtime
            features['access_time'] = stat_info.st_atime
            
            # File content features
            with open(file_path, 'rb') as f:
                content = f.read()
                
                # Entropy calculation (high entropy might indicate encryption/packing)
                features['entropy'] = self.calculate_entropy(content)
                
                # Hash signatures
                features['md5'] = hashlib.md5(content).hexdigest()
                features['sha256'] = hashlib.sha256(content).hexdigest()
                
                # Byte frequency analysis
                byte_freq = self.analyze_byte_frequency(content)
                features.update(byte_freq)
                
                # String analysis
                strings = self.extract_strings(content)
                features['string_count'] = len(strings)
                features['suspicious_strings'] = self.check_suspicious_strings(strings)
                
                # PE header analysis (for Windows executables)
                if file_path.endswith(('.exe', '.dll', '.sys')):
                    pe_features = self.analyze_pe_header(content)
                    features.update(pe_features)
                
                # Script analysis
                if file_path.endswith(('.js', '.vbs', '.ps1', '.py', '.sh')):
                    script_features = self.analyze_script(content)
                    features.update(script_features)
                    
        except Exception as e:
            self.logger.error(f"Feature extraction error: {e}")
            
        return features
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
            
        entropy = 0
        data_len = len(data)
        
        # Count byte occurrences
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
                
        return entropy
    
    def analyze_byte_frequency(self, data: bytes) -> Dict[str, float]:
        """Analyze byte frequency distribution"""
        byte_freq = {}
        data_len = len(data)
        
        if data_len == 0:
            return {}
        
        # Count specific byte patterns
        null_bytes = data.count(b'\x00')
        printable = sum(1 for b in data if 32 <= b <= 126)
        
        byte_freq['null_byte_ratio'] = null_bytes / data_len
        byte_freq['printable_ratio'] = printable / data_len
        byte_freq['non_printable_ratio'] = 1 - (printable / data_len)
        
        return byte_freq
    
    def extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract readable strings from binary data"""
        strings = []
        current_string = []
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII range
                current_string.append(chr(byte))
            else:
                if len(current_string) >= min_length:
                    strings.append(''.join(current_string))
                current_string = []
        
        if len(current_string) >= min_length:
            strings.append(''.join(current_string))
            
        return strings
    
    def check_suspicious_strings(self, strings: List[str]) -> int:
        """Check for suspicious strings commonly found in malware"""
        suspicious_patterns = [
            'cmd.exe', 'powershell', 'wscript', 'cscript',
            'reg add', 'reg delete', 'schtasks', 'netsh',
            'bcdedit', 'vssadmin', 'wmic', 'rundll32',
            'CreateRemoteThread', 'VirtualAlloc', 'WriteProcessMemory',
            'SetWindowsHook', 'GetAsyncKeyState', 'GetKeyState',
            'InternetOpen', 'URLDownloadToFile', 'ShellExecute',
            'WinExec', 'CreateProcess', 'OpenProcess',
            'HKEY_', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'http://', 'https://', 'ftp://', 'tor2web',
            'bitcoin', 'monero', 'wallet', 'ransom',
            'encrypt', 'decrypt', 'locked', 'payment',
            'debug', 'crack', 'patch', 'keygen',
        ]
        
        count = 0
        for string in strings:
            for pattern in suspicious_patterns:
                if pattern.lower() in string.lower():
                    count += 1
                    
        return count
    
    def analyze_pe_header(self, data: bytes) -> Dict[str, Any]:
        """Analyze PE header for Windows executables"""
        features = {}
        
        try:
            # Check for PE signature
            if len(data) > 0x3c:
                pe_offset = int.from_bytes(data[0x3c:0x40], 'little')
                if len(data) > pe_offset + 4:
                    pe_signature = data[pe_offset:pe_offset+4]
                    features['is_pe'] = pe_signature == b'PE\x00\x00'
                    
                    if features['is_pe']:
                        # Extract more PE features
                        features['has_debug_info'] = b'debug' in data.lower()
                        features['is_packed'] = self.check_packing(data)
                        features['import_count'] = data.count(b'.dll')
                        
        except Exception:
            features['is_pe'] = False
            
        return features
    
    def check_packing(self, data: bytes) -> bool:
        """Check if executable is packed/compressed"""
        # High entropy often indicates packing
        entropy = self.calculate_entropy(data)
        
        # Common packer signatures
        packer_signatures = [
            b'UPX0', b'UPX1', b'UPX!',
            b'PEC2', b'PECompact',
            b'ASPack', b'ASProtect',
            b'Themida', b'VMProtect',
            b'PELock', b'Petite',
        ]
        
        for signature in packer_signatures:
            if signature in data:
                return True
                
        return entropy > 7.5  # High entropy threshold
    
    def analyze_script(self, data: bytes) -> Dict[str, Any]:
        """Analyze script files for malicious patterns"""
        features = {}
        
        try:
            text = data.decode('utf-8', errors='ignore')
            
            # Check for obfuscation
            features['is_obfuscated'] = self.check_obfuscation(text)
            
            # Count dangerous functions
            dangerous_functions = [
                'eval', 'exec', 'compile', '__import__',
                'subprocess', 'os.system', 'shell',
                'ActiveXObject', 'WScript.Shell',
                'powershell', 'Invoke-Expression',
                'DownloadString', 'DownloadFile',
            ]
            
            features['dangerous_function_count'] = sum(
                1 for func in dangerous_functions if func in text
            )
            
            # Check for base64 encoding
            features['has_base64'] = 'base64' in text or 'b64decode' in text
            
            # Check for network operations
            features['has_network_ops'] = any(
                keyword in text for keyword in 
                ['urllib', 'requests', 'socket', 'http', 'ftp']
            )
            
        except Exception:
            pass
            
        return features
    
    def check_obfuscation(self, text: str) -> bool:
        """Check if code is obfuscated"""
        indicators = [
            # Long base64 strings
            len(text) > 1000 and text.count('=') > 50,
            # Hex encoding
            '\\x' in text and text.count('\\x') > 20,
            # Unicode escapes
            '\\u' in text and text.count('\\u') > 20,
            # Excessive string concatenation
            text.count('+') > 100,
            # Variable names with random characters
            any(len(word) > 30 for word in text.split()),
        ]
        
        return any(indicators)
    
    def predict_threat(self, file_path: str) -> Tuple[bool, float, str]:
        """
        Predict if a file is a threat using ensemble ML models
        Returns: (is_threat, confidence, threat_type)
        """
        try:
            # Extract features
            features = self.extract_features(file_path)
            
            # Prepare feature vector
            feature_vector = self.prepare_feature_vector(features)
            
            # Get predictions from all models
            predictions = []
            confidences = []
            
            for model_name, model in self.models.items():
                if hasattr(model, 'predict_proba'):
                    # Scale features
                    scaled_features = self.scalers[model_name].transform([feature_vector])
                    
                    # Get prediction
                    pred_proba = model.predict_proba(scaled_features)[0]
                    threat_confidence = pred_proba[1] if len(pred_proba) > 1 else pred_proba[0]
                    
                    predictions.append(threat_confidence > self.confidence_threshold)
                    confidences.append(threat_confidence)
            
            # Ensemble decision (majority voting with confidence weighting)
            avg_confidence = np.mean(confidences)
            is_threat = sum(predictions) > len(predictions) / 2
            
            # Determine threat type
            threat_type = self.classify_threat_type(features, avg_confidence)
            
            return is_threat, avg_confidence, threat_type
            
        except Exception as e:
            self.logger.error(f"Prediction error: {e}")
            return False, 0.0, "unknown"
    
    def prepare_feature_vector(self, features: Dict[str, Any]) -> np.ndarray:
        """Convert features dictionary to numerical vector"""
        # Define feature order
        numerical_features = [
            'file_size', 'entropy', 'string_count', 'suspicious_strings',
            'null_byte_ratio', 'printable_ratio', 'non_printable_ratio',
            'dangerous_function_count', 'import_count'
        ]
        
        vector = []
        for feature_name in numerical_features:
            value = features.get(feature_name, 0)
            if isinstance(value, bool):
                value = int(value)
            elif not isinstance(value, (int, float)):
                value = 0
            vector.append(value)
            
        return np.array(vector)
    
    def classify_threat_type(self, features: Dict[str, Any], confidence: float) -> str:
        """Classify the type of threat based on features"""
        if features.get('is_packed', False):
            return "packed_malware"
        elif features.get('has_network_ops', False):
            return "network_trojan"
        elif features.get('is_obfuscated', False):
            return "obfuscated_malware"
        elif features.get('dangerous_function_count', 0) > 5:
            return "potentially_unwanted"
        elif confidence > 0.9:
            return "high_risk_malware"
        elif confidence > 0.7:
            return "suspicious_file"
        else:
            return "low_risk"
    
    def train_model(self, training_data: List[Tuple[str, bool]]):
        """Train the ML models with new data"""
        X = []
        y = []
        
        for file_path, is_malware in training_data:
            features = self.extract_features(file_path)
            feature_vector = self.prepare_feature_vector(features)
            X.append(feature_vector)
            y.append(int(is_malware))
        
        X = np.array(X)
        y = np.array(y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        # Train each model
        for model_name, model in self.models.items():
            # Scale features
            X_train_scaled = self.scalers[model_name].fit_transform(X_train)
            X_test_scaled = self.scalers[model_name].transform(X_test)
            
            # Train
            model.fit(X_train_scaled, y_train)
            
            # Evaluate
            accuracy = model.score(X_test_scaled, y_test)
            self.logger.info(f"{model_name} accuracy: {accuracy:.2%}")
    
    def save_models(self, path: str):
        """Save trained models to disk"""
        for model_name, model in self.models.items():
            model_path = os.path.join(path, f"{model_name}_model.pkl")
            joblib.dump(model, model_path)
            
            scaler_path = os.path.join(path, f"{model_name}_scaler.pkl")
            joblib.dump(self.scalers[model_name], scaler_path)
    
    def load_models(self, path: str):
        """Load trained models from disk"""
        for model_name in self.models.keys():
            model_path = os.path.join(path, f"{model_name}_model.pkl")
            if os.path.exists(model_path):
                self.models[model_name] = joblib.load(model_path)
                
            scaler_path = os.path.join(path, f"{model_name}_scaler.pkl")
            if os.path.exists(scaler_path):
                self.scalers[model_name] = joblib.load(scaler_path)