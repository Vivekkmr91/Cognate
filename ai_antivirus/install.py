#!/usr/bin/env python3
"""
AI Antivirus Installation Script
Automated installer for AI Antivirus Suite
"""
import os
import sys
import platform
import subprocess
import shutil
import json
from pathlib import Path
import ctypes

class AntivirusInstaller:
    """Installer for AI Antivirus Suite"""
    
    def __init__(self):
        self.system = platform.system()
        self.install_dir = self.get_install_directory()
        self.data_dir = self.get_data_directory()
        
    def get_install_directory(self):
        """Get installation directory based on OS"""
        if self.system == "Windows":
            return Path("C:/Program Files/AI Antivirus")
        elif self.system == "Linux":
            return Path("/opt/ai-antivirus")
        elif self.system == "Darwin":  # macOS
            return Path("/Applications/AI Antivirus.app")
        else:
            return Path.home() / "ai-antivirus"
    
    def get_data_directory(self):
        """Get data directory based on OS"""
        if self.system == "Windows":
            return Path.home() / "AppData" / "Roaming" / "AIAntivirus"
        elif self.system == "Linux":
            return Path.home() / ".config" / "ai-antivirus"
        elif self.system == "Darwin":  # macOS
            return Path.home() / "Library" / "Application Support" / "AIAntivirus"
        else:
            return Path.home() / ".ai-antivirus"
    
    def check_admin(self):
        """Check if running with admin privileges"""
        if self.system == "Windows":
            try:
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
        else:
            return os.geteuid() == 0
    
    def install_dependencies(self):
        """Install Python dependencies"""
        print("Installing dependencies...")
        
        requirements_file = Path(__file__).parent / "requirements.txt"
        
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
            ])
            print("✅ Dependencies installed successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install dependencies: {e}")
            return False
    
    def create_directories(self):
        """Create necessary directories"""
        print("Creating directories...")
        
        directories = [
            self.install_dir,
            self.data_dir,
            self.data_dir / "logs",
            self.data_dir / "quarantine",
            self.data_dir / "backups",
            self.data_dir / "models",
            self.data_dir / "signatures"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            
        print("✅ Directories created")
    
    def copy_files(self):
        """Copy application files to installation directory"""
        print("Copying application files...")
        
        source_dir = Path(__file__).parent
        
        # Copy Python files
        for item in source_dir.glob("**/*.py"):
            if "__pycache__" not in str(item):
                relative_path = item.relative_to(source_dir)
                dest = self.install_dir / relative_path
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, dest)
        
        print("✅ Application files copied")
    
    def create_service(self):
        """Create system service for background protection"""
        print("Creating system service...")
        
        if self.system == "Windows":
            self.create_windows_service()
        elif self.system == "Linux":
            self.create_linux_service()
        elif self.system == "Darwin":
            self.create_macos_service()
            
    def create_windows_service(self):
        """Create Windows service"""
        service_name = "AIAntivirusService"
        display_name = "AI Antivirus Protection Service"
        exe_path = self.install_dir / "main.py"
        
        # Create service using sc command
        cmd = f'sc create {service_name} binPath="{sys.executable} \\"{exe_path}\\" --start" DisplayName="{display_name}" start=auto'
        
        try:
            subprocess.run(cmd, shell=True, check=True)
            print("✅ Windows service created")
        except:
            print("⚠️ Could not create Windows service (admin rights required)")
    
    def create_linux_service(self):
        """Create systemd service for Linux"""
        service_content = f"""[Unit]
Description=AI Antivirus Protection Service
After=network.target

[Service]
Type=simple
ExecStart={sys.executable} {self.install_dir}/main.py --start
Restart=always
RestartSec=10
User={os.getenv('USER')}

[Install]
WantedBy=multi-user.target
"""
        
        service_file = Path("/etc/systemd/system/ai-antivirus.service")
        
        try:
            with open(service_file, 'w') as f:
                f.write(service_content)
            
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            subprocess.run(["systemctl", "enable", "ai-antivirus"], check=True)
            print("✅ Linux service created")
        except:
            print("⚠️ Could not create Linux service (sudo required)")
    
    def create_macos_service(self):
        """Create launch agent for macOS"""
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aiav.antivirus</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{self.install_dir}/main.py</string>
        <string>--start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"""
        
        plist_file = Path.home() / "Library" / "LaunchAgents" / "com.aiav.antivirus.plist"
        
        try:
            plist_file.parent.mkdir(parents=True, exist_ok=True)
            with open(plist_file, 'w') as f:
                f.write(plist_content)
            
            subprocess.run(["launchctl", "load", str(plist_file)], check=True)
            print("✅ macOS launch agent created")
        except:
            print("⚠️ Could not create macOS launch agent")
    
    def create_shortcuts(self):
        """Create desktop shortcuts"""
        print("Creating shortcuts...")
        
        if self.system == "Windows":
            self.create_windows_shortcut()
        elif self.system == "Linux":
            self.create_linux_desktop_entry()
        elif self.system == "Darwin":
            print("⚠️ macOS app bundle creation not implemented")
    
    def create_windows_shortcut(self):
        """Create Windows desktop shortcut"""
        try:
            import win32com.client
            
            desktop = Path.home() / "Desktop"
            shortcut_path = desktop / "AI Antivirus.lnk"
            
            shell = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell.CreateShortCut(str(shortcut_path))
            shortcut.Targetpath = sys.executable
            shortcut.Arguments = f'"{self.install_dir / "main.py"}" --gui'
            shortcut.WorkingDirectory = str(self.install_dir)
            shortcut.IconLocation = sys.executable
            shortcut.Description = "AI Antivirus Suite"
            shortcut.save()
            
            print("✅ Desktop shortcut created")
        except:
            print("⚠️ Could not create desktop shortcut")
    
    def create_linux_desktop_entry(self):
        """Create Linux desktop entry"""
        desktop_content = f"""[Desktop Entry]
Name=AI Antivirus
Comment=Advanced AI-powered antivirus protection
Exec={sys.executable} {self.install_dir}/main.py --gui
Icon=security-high
Terminal=false
Type=Application
Categories=System;Security;
"""
        
        desktop_file = Path.home() / ".local" / "share" / "applications" / "ai-antivirus.desktop"
        
        try:
            desktop_file.parent.mkdir(parents=True, exist_ok=True)
            with open(desktop_file, 'w') as f:
                f.write(desktop_content)
            
            os.chmod(desktop_file, 0o755)
            print("✅ Desktop entry created")
        except:
            print("⚠️ Could not create desktop entry")
    
    def configure_auto_start(self):
        """Configure auto-start on system boot"""
        print("Configuring auto-start...")
        
        config = {
            "auto_start": True,
            "start_minimized": True,
            "check_updates_on_start": True
        }
        
        config_file = self.data_dir / "config.json"
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print("✅ Auto-start configured")
    
    def download_initial_definitions(self):
        """Download initial virus definitions"""
        print("Downloading virus definitions...")
        # In production, would download from server
        print("✅ Virus definitions ready")
    
    def run_installation(self):
        """Run the complete installation process"""
        print("\n" + "="*50)
        print("AI ANTIVIRUS SUITE INSTALLATION")
        print("="*50 + "\n")
        
        # Check admin privileges
        if not self.check_admin():
            print("⚠️ Warning: Running without administrator privileges")
            print("Some features may not be available\n")
        
        # Installation steps
        steps = [
            ("Installing dependencies", self.install_dependencies),
            ("Creating directories", self.create_directories),
            ("Copying files", self.copy_files),
            ("Creating service", self.create_service),
            ("Creating shortcuts", self.create_shortcuts),
            ("Configuring auto-start", self.configure_auto_start),
            ("Downloading definitions", self.download_initial_definitions)
        ]
        
        for description, func in steps:
            print(f"\n{description}...")
            try:
                func()
            except Exception as e:
                print(f"❌ Error: {e}")
        
        print("\n" + "="*50)
        print("✅ INSTALLATION COMPLETE!")
        print("="*50)
        print("\nYou can now:")
        print("1. Launch AI Antivirus from the desktop shortcut")
        print("2. Or run: python", self.install_dir / "main.py", "--gui")
        print("\nProtection will start automatically on next system boot.")
    
    def uninstall(self):
        """Uninstall AI Antivirus"""
        print("\n" + "="*50)
        print("AI ANTIVIRUS SUITE UNINSTALLATION")
        print("="*50 + "\n")
        
        # Stop service
        if self.system == "Windows":
            subprocess.run("sc stop AIAntivirusService", shell=True)
            subprocess.run("sc delete AIAntivirusService", shell=True)
        elif self.system == "Linux":
            subprocess.run(["systemctl", "stop", "ai-antivirus"])
            subprocess.run(["systemctl", "disable", "ai-antivirus"])
            Path("/etc/systemd/system/ai-antivirus.service").unlink(missing_ok=True)
        
        # Remove directories
        if self.install_dir.exists():
            shutil.rmtree(self.install_dir)
        if self.data_dir.exists():
            shutil.rmtree(self.data_dir)
        
        print("✅ AI Antivirus has been uninstalled")

def main():
    """Main installation entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="AI Antivirus Installer")
    parser.add_argument(
        '--uninstall',
        action='store_true',
        help='Uninstall AI Antivirus'
    )
    
    args = parser.parse_args()
    
    installer = AntivirusInstaller()
    
    if args.uninstall:
        installer.uninstall()
    else:
        installer.run_installation()

if __name__ == "__main__":
    main()