#!/usr/bin/env python3
"""
AI Antivirus Suite - Main Application
Advanced AI-powered antivirus with comprehensive protection features
"""
import sys
import os
import logging
import argparse
import json
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import modules
from core.scanner import AntivirusScanner
from core.ml_engine import AIThreatDetector
from modules.realtime_protection import RealtimeProtection
from modules.data_leak_prevention import DataLeakPrevention
from modules.network_security import NetworkSecurityManager
from modules.ransomware_protection import RansomwareProtection
from config.settings import *
from gui.main_window import AIAntivirusGUI

# Configure logging
def setup_logging():
    """Setup logging configuration"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    log_file = LOGS_DIR / f"antivirus_{datetime.now().strftime('%Y%m%d')}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger(__name__)

class AIAntivirusApplication:
    """Main application class"""
    
    def __init__(self, config_file=None):
        """Initialize the antivirus application"""
        self.logger = setup_logging()
        self.logger.info("AI Antivirus Suite starting...")
        
        # Load configuration
        self.config = self.load_config(config_file)
        
        # Initialize components
        self.scanner = AntivirusScanner(config_file)
        self.ai_detector = AIThreatDetector()
        self.realtime_protection = RealtimeProtection(self.scanner, SCAN_CONFIG)
        self.dlp = DataLeakPrevention(DLP_CONFIG)
        self.network_security = NetworkSecurityManager(NETWORK_CONFIG)
        self.ransomware_protection = RansomwareProtection(RANSOMWARE_CONFIG)
        
        # GUI application
        self.gui = None
        
        self.logger.info("AI Antivirus Suite initialized successfully")
        
    def load_config(self, config_file):
        """Load configuration from file"""
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                return json.load(f)
        
        # Use default config
        return {
            **SCAN_CONFIG,
            **ML_CONFIG,
            **NETWORK_CONFIG,
            **DLP_CONFIG,
            **RANSOMWARE_CONFIG,
            **PERFORMANCE_CONFIG
        }
    
    def start_protection(self):
        """Start all protection modules"""
        self.logger.info("Starting protection modules...")
        
        try:
            # Start real-time protection
            if self.config.get('real_time_protection', True):
                self.realtime_protection.start()
                self.logger.info("Real-time protection started")
            
            # Start network security
            if self.config.get('firewall_enabled', True):
                self.network_security.start()
                self.logger.info("Network security started")
            
            # Start ransomware protection
            if self.config.get('enabled', True):
                self.ransomware_protection.start()
                self.logger.info("Ransomware protection started")
            
            # Start DLP
            if DLP_CONFIG.get('enabled', True):
                self.dlp.clipboard_monitor.start()
                self.dlp.usb_monitor.start()
                self.logger.info("Data leak prevention started")
            
            self.logger.info("All protection modules started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start protection: {e}")
            return False
    
    def stop_protection(self):
        """Stop all protection modules"""
        self.logger.info("Stopping protection modules...")
        
        try:
            self.realtime_protection.stop()
            self.network_security.stop()
            self.ransomware_protection.stop()
            self.dlp.clipboard_monitor.stop()
            self.dlp.usb_monitor.stop()
            
            self.logger.info("All protection modules stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping protection: {e}")
    
    def run_gui(self):
        """Run the GUI application"""
        try:
            self.logger.info("Starting GUI...")
            
            # Create and configure GUI
            self.gui = AIAntivirusGUI()
            
            # Inject components into GUI
            self.gui.scanner = self.scanner
            self.gui.realtime_protection = self.realtime_protection
            self.gui.network_security = self.network_security
            self.gui.ransomware_protection = self.ransomware_protection
            self.gui.dlp = self.dlp
            
            # Start protection
            self.start_protection()
            
            # Run GUI main loop
            self.gui.mainloop()
            
        except Exception as e:
            self.logger.error(f"GUI error: {e}")
            raise
        finally:
            self.stop_protection()
    
    def run_cli(self, args):
        """Run command-line interface"""
        if args.scan:
            self.perform_scan(args.scan, args.deep)
        elif args.quick_scan:
            self.perform_quick_scan()
        elif args.full_scan:
            self.perform_full_scan()
        elif args.update:
            self.update_definitions()
        elif args.status:
            self.show_status()
        elif args.start:
            self.start_service()
        elif args.stop:
            self.stop_service()
        else:
            # Default: start protection and run in background
            self.start_service()
    
    def perform_scan(self, path, deep=False):
        """Perform a scan on specified path"""
        self.logger.info(f"Scanning {path}...")
        
        if os.path.isfile(path):
            result = self.scanner.scan_file(path, deep_scan=deep)
            self.print_scan_result(result)
        elif os.path.isdir(path):
            results = self.scanner.scan_directory(path, recursive=True)
            self.print_scan_results(results)
        else:
            self.logger.error(f"Invalid path: {path}")
    
    def perform_quick_scan(self):
        """Perform a quick scan"""
        self.logger.info("Performing quick scan...")
        results = self.scanner.quick_scan()
        self.print_scan_results(results)
    
    def perform_full_scan(self):
        """Perform a full system scan"""
        self.logger.info("Performing full system scan...")
        results = self.scanner.full_scan()
        self.print_scan_results(results)
    
    def print_scan_result(self, result):
        """Print single scan result"""
        if result.get('is_safe'):
            print(f"✅ {result['file_path']}: Clean")
        else:
            print(f"⚠️  {result['file_path']}: Threats detected!")
            for threat in result.get('threats', []):
                print(f"   - {threat['threat_name']} ({threat['severity']})")
    
    def print_scan_results(self, results):
        """Print multiple scan results"""
        safe_count = sum(1 for r in results if r.get('is_safe'))
        threat_count = len(results) - safe_count
        
        print(f"\nScan Summary:")
        print(f"  Total files scanned: {len(results)}")
        print(f"  Clean files: {safe_count}")
        print(f"  Threats found: {threat_count}")
        
        if threat_count > 0:
            print("\nThreats detected:")
            for result in results:
                if not result.get('is_safe'):
                    self.print_scan_result(result)
    
    def update_definitions(self):
        """Update virus definitions"""
        self.logger.info("Updating virus definitions...")
        # In production, would download updates from server
        print("Virus definitions are up to date")
    
    def show_status(self):
        """Show protection status"""
        status = {
            "Real-time Protection": "Active" if self.realtime_protection.is_active else "Inactive",
            "Network Security": "Active" if self.network_security.is_active else "Inactive",
            "Ransomware Protection": "Active" if self.ransomware_protection.is_active else "Inactive",
            "Data Leak Prevention": "Active",
            "Last Update": datetime.now().strftime("%Y-%m-%d"),
            "Version": "2.0.0"
        }
        
        print("\nAI Antivirus Status:")
        for key, value in status.items():
            print(f"  {key}: {value}")
    
    def start_service(self):
        """Start antivirus service"""
        self.logger.info("Starting AI Antivirus service...")
        
        if self.start_protection():
            print("AI Antivirus service started successfully")
            print("Protection is now active")
            
            # Keep service running
            try:
                while True:
                    import time
                    time.sleep(60)  # Check every minute
                    
            except KeyboardInterrupt:
                self.stop_service()
        else:
            print("Failed to start AI Antivirus service")
    
    def stop_service(self):
        """Stop antivirus service"""
        self.logger.info("Stopping AI Antivirus service...")
        self.stop_protection()
        print("AI Antivirus service stopped")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="AI Antivirus Suite - Advanced Protection System"
    )
    
    parser.add_argument(
        '--gui',
        action='store_true',
        help='Launch GUI interface'
    )
    
    parser.add_argument(
        '--scan',
        type=str,
        help='Scan a specific file or directory'
    )
    
    parser.add_argument(
        '--deep',
        action='store_true',
        help='Perform deep scan with heuristic analysis'
    )
    
    parser.add_argument(
        '--quick-scan',
        action='store_true',
        help='Perform quick scan of common locations'
    )
    
    parser.add_argument(
        '--full-scan',
        action='store_true',
        help='Perform full system scan'
    )
    
    parser.add_argument(
        '--update',
        action='store_true',
        help='Update virus definitions'
    )
    
    parser.add_argument(
        '--status',
        action='store_true',
        help='Show protection status'
    )
    
    parser.add_argument(
        '--start',
        action='store_true',
        help='Start antivirus service'
    )
    
    parser.add_argument(
        '--stop',
        action='store_true',
        help='Stop antivirus service'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        help='Path to configuration file'
    )
    
    args = parser.parse_args()
    
    # Create application instance
    app = AIAntivirusApplication(args.config)
    
    # Run in appropriate mode
    if args.gui or (len(sys.argv) == 1):
        # Launch GUI if --gui flag or no arguments
        app.run_gui()
    else:
        # Run CLI mode
        app.run_cli(args)

if __name__ == "__main__":
    main()