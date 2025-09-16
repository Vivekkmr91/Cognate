"""
AI Antivirus Configuration Settings
"""
import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = DATA_DIR / "logs"
QUARANTINE_DIR = DATA_DIR / "quarantine"
MODELS_DIR = DATA_DIR / "models"
SIGNATURES_DIR = DATA_DIR / "signatures"
WHITELIST_DIR = DATA_DIR / "whitelist"

# Create directories if they don't exist
for directory in [DATA_DIR, LOGS_DIR, QUARANTINE_DIR, MODELS_DIR, SIGNATURES_DIR, WHITELIST_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Scanning Configuration
SCAN_CONFIG = {
    "real_time_protection": True,
    "deep_scan_enabled": True,
    "heuristic_analysis": True,
    "behavior_monitoring": True,
    "ml_detection": True,
    "cloud_lookup": True,
    "max_file_size_mb": 500,
    "scan_archives": True,
    "scan_emails": True,
    "scan_network": True,
    "auto_quarantine": True,
    "scan_memory": True,
    "rootkit_scan": True,
    "scan_registry": True,  # Windows only
}

# Machine Learning Configuration
ML_CONFIG = {
    "model_version": "2.0.0",
    "confidence_threshold": 0.85,
    "update_frequency_days": 1,
    "batch_size": 32,
    "max_features": 1000,
    "use_ensemble": True,
    "online_learning": True,
}

# Network Protection
NETWORK_CONFIG = {
    "firewall_enabled": True,
    "ids_enabled": True,  # Intrusion Detection System
    "ips_enabled": True,  # Intrusion Prevention System
    "dns_filtering": True,
    "ssl_inspection": True,
    "port_scan_detection": True,
    "ddos_protection": True,
    "vpn_protection": True,
    "blocked_ports": [135, 137, 139, 445],  # Common malware ports
    "max_connections": 1000,
}

# Data Leak Prevention
DLP_CONFIG = {
    "enabled": True,
    "monitor_clipboard": True,
    "monitor_usb": True,
    "monitor_network_shares": True,
    "monitor_cloud_upload": True,
    "sensitive_data_patterns": [
        r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
        r"\b\d{16}\b",  # Credit card
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
        r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+",  # Passwords
    ],
    "protected_file_types": [".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx"],
}

# Ransomware Protection
RANSOMWARE_CONFIG = {
    "enabled": True,
    "honeypot_enabled": True,
    "behavior_blocking": True,
    "file_backup": True,
    "shadow_copy_protection": True,
    "process_injection_detection": True,
    "suspicious_extensions": [".locked", ".encrypted", ".crypto", ".enc", ".cipher"],
}

# Update Configuration
UPDATE_CONFIG = {
    "auto_update": True,
    "update_check_interval_hours": 6,
    "definition_update_url": "https://api.ai-antivirus.com/definitions",
    "model_update_url": "https://api.ai-antivirus.com/models",
    "beta_channel": False,
}

# Performance Settings
PERFORMANCE_CONFIG = {
    "cpu_limit_percent": 50,
    "memory_limit_mb": 512,
    "scan_priority": "normal",  # low, normal, high
    "multi_threading": True,
    "max_threads": 4,
    "cache_enabled": True,
    "cache_size_mb": 100,
}

# Notification Settings
NOTIFICATION_CONFIG = {
    "desktop_alerts": True,
    "email_alerts": False,
    "threat_found": True,
    "scan_complete": True,
    "update_available": True,
    "license_expiry": True,
    "system_performance": True,
}

# Logging Configuration
LOGGING_CONFIG = {
    "level": "INFO",
    "max_log_size_mb": 100,
    "log_rotation_count": 5,
    "detailed_logging": True,
    "event_logging": True,
    "threat_logging": True,
    "network_logging": True,
}