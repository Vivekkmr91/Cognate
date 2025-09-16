"""
Kernel-Level Protection Driver Interface
Provides deep system integration for rootkit detection and kernel protection
"""
import os
import sys
import ctypes
import struct
import platform
import subprocess
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
import hashlib
import json
from datetime import datetime

class KernelProtection:
    """Kernel-level protection interface"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.system = platform.system()
        self.is_driver_loaded = False
        self.kernel_callbacks = []
        self.ssdt_hooks = {}
        self.idt_hooks = {}
        
        # Initialize based on OS
        if self.system == "Windows":
            self.driver_path = "drivers/aiav_minifilter.sys"
            self.init_windows_driver()
        elif self.system == "Linux":
            self.driver_path = "drivers/aiav_module.ko"
            self.init_linux_module()
        else:
            self.logger.warning("Kernel protection not available for this OS")
    
    def init_windows_driver(self):
        """Initialize Windows kernel driver"""
        try:
            # Check if running with admin privileges
            if not ctypes.windll.shell32.IsUserAnAdmin():
                self.logger.error("Admin privileges required for kernel driver")
                return False
            
            # Load Windows Driver Model (WDM) interface
            self.kernel32 = ctypes.windll.kernel32
            self.ntdll = ctypes.windll.ntdll
            
            # Setup minifilter driver for file system monitoring
            self.setup_minifilter()
            
            # Setup SSDT hooking detection
            self.setup_ssdt_monitor()
            
            # Setup IDT monitoring
            self.setup_idt_monitor()
            
            self.is_driver_loaded = True
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Windows driver: {e}")
            return False
    
    def init_linux_module(self):
        """Initialize Linux kernel module"""
        try:
            # Check if running as root
            if os.geteuid() != 0:
                self.logger.error("Root privileges required for kernel module")
                return False
            
            # Load kernel module
            result = subprocess.run(
                ["insmod", self.driver_path],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                self.is_driver_loaded = True
                self.setup_linux_hooks()
                return True
            else:
                self.logger.error(f"Failed to load kernel module: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to initialize Linux module: {e}")
            return False
    
    def setup_minifilter(self):
        """Setup Windows minifilter driver for file system protection"""
        # Minifilter callbacks for file operations
        self.file_callbacks = {
            'IRP_MJ_CREATE': self.on_file_create,
            'IRP_MJ_READ': self.on_file_read,
            'IRP_MJ_WRITE': self.on_file_write,
            'IRP_MJ_DELETE': self.on_file_delete,
            'IRP_MJ_SET_INFORMATION': self.on_file_rename
        }
        
        # Register with Filter Manager
        self.register_minifilter_callbacks()
    
    def setup_ssdt_monitor(self):
        """Monitor System Service Descriptor Table for rootkit hooks"""
        try:
            # Get SSDT base address
            ssdt_base = self.get_ssdt_base()
            
            # Calculate checksums for SSDT entries
            for i in range(0x200):  # Monitor first 512 system calls
                addr = ssdt_base + (i * 8)  # 64-bit pointers
                original_value = self.read_kernel_memory(addr, 8)
                self.ssdt_hooks[i] = {
                    'address': addr,
                    'original': original_value,
                    'checksum': hashlib.sha256(original_value).hexdigest()
                }
            
            self.logger.info("SSDT monitoring initialized")
            
        except Exception as e:
            self.logger.error(f"SSDT monitoring setup failed: {e}")
    
    def setup_idt_monitor(self):
        """Monitor Interrupt Descriptor Table for rootkit hooks"""
        try:
            # Get IDT base address
            idt_base = self.get_idt_base()
            
            # Monitor critical interrupts
            critical_interrupts = [0x01, 0x03, 0x0E, 0x80]  # Debug, Breakpoint, Page Fault, System Call
            
            for interrupt in critical_interrupts:
                addr = idt_base + (interrupt * 16)  # IDT entry size
                original_value = self.read_kernel_memory(addr, 16)
                self.idt_hooks[interrupt] = {
                    'address': addr,
                    'original': original_value,
                    'checksum': hashlib.sha256(original_value).hexdigest()
                }
            
            self.logger.info("IDT monitoring initialized")
            
        except Exception as e:
            self.logger.error(f"IDT monitoring setup failed: {e}")
    
    def scan_for_rootkits(self) -> List[Dict[str, Any]]:
        """Comprehensive rootkit scanning"""
        rootkits = []
        
        # Check for SSDT hooks
        ssdt_hooks = self.check_ssdt_hooks()
        if ssdt_hooks:
            rootkits.extend(ssdt_hooks)
        
        # Check for IDT hooks
        idt_hooks = self.check_idt_hooks()
        if idt_hooks:
            rootkits.extend(idt_hooks)
        
        # Check for hidden processes
        hidden_procs = self.find_hidden_processes()
        if hidden_procs:
            rootkits.extend(hidden_procs)
        
        # Check for kernel object manipulation
        kernel_tampering = self.check_kernel_tampering()
        if kernel_tampering:
            rootkits.extend(kernel_tampering)
        
        # Check for driver signing bypass
        unsigned_drivers = self.check_unsigned_drivers()
        if unsigned_drivers:
            rootkits.extend(unsigned_drivers)
        
        return rootkits
    
    def check_ssdt_hooks(self) -> List[Dict[str, Any]]:
        """Check for SSDT hooking"""
        hooks = []
        
        for syscall_id, info in self.ssdt_hooks.items():
            current_value = self.read_kernel_memory(info['address'], 8)
            current_checksum = hashlib.sha256(current_value).hexdigest()
            
            if current_checksum != info['checksum']:
                hooks.append({
                    'type': 'ssdt_hook',
                    'syscall_id': syscall_id,
                    'address': hex(info['address']),
                    'severity': 'critical',
                    'description': f'SSDT entry {syscall_id} has been modified'
                })
        
        return hooks
    
    def check_idt_hooks(self) -> List[Dict[str, Any]]:
        """Check for IDT hooking"""
        hooks = []
        
        for interrupt, info in self.idt_hooks.items():
            current_value = self.read_kernel_memory(info['address'], 16)
            current_checksum = hashlib.sha256(current_value).hexdigest()
            
            if current_checksum != info['checksum']:
                hooks.append({
                    'type': 'idt_hook',
                    'interrupt': hex(interrupt),
                    'address': hex(info['address']),
                    'severity': 'critical',
                    'description': f'IDT entry {hex(interrupt)} has been modified'
                })
        
        return hooks
    
    def find_hidden_processes(self) -> List[Dict[str, Any]]:
        """Find processes hidden by rootkits"""
        hidden = []
        
        # Cross-reference different process enumeration methods
        usermode_procs = self.get_usermode_processes()
        kernel_procs = self.get_kernel_processes()
        
        # Find discrepancies
        kernel_pids = set(p['pid'] for p in kernel_procs)
        usermode_pids = set(p['pid'] for p in usermode_procs)
        
        hidden_pids = kernel_pids - usermode_pids
        
        for pid in hidden_pids:
            proc_info = next((p for p in kernel_procs if p['pid'] == pid), None)
            if proc_info:
                hidden.append({
                    'type': 'hidden_process',
                    'pid': pid,
                    'name': proc_info.get('name', 'unknown'),
                    'severity': 'critical',
                    'description': f'Hidden process detected: PID {pid}'
                })
        
        return hidden
    
    def check_kernel_tampering(self) -> List[Dict[str, Any]]:
        """Check for kernel structure tampering"""
        tampering = []
        
        # Check critical kernel structures
        structures = [
            'PsLoadedModuleList',
            'PsActiveProcessHead',
            'ObTypeIndexTable',
            'KiServiceTable'
        ]
        
        for struct_name in structures:
            if self.is_structure_tampered(struct_name):
                tampering.append({
                    'type': 'kernel_tampering',
                    'structure': struct_name,
                    'severity': 'critical',
                    'description': f'Kernel structure {struct_name} has been tampered'
                })
        
        return tampering
    
    def check_unsigned_drivers(self) -> List[Dict[str, Any]]:
        """Check for unsigned or suspicious drivers"""
        suspicious = []
        
        drivers = self.enumerate_drivers()
        
        for driver in drivers:
            if not driver.get('signed', False):
                suspicious.append({
                    'type': 'unsigned_driver',
                    'name': driver['name'],
                    'path': driver['path'],
                    'severity': 'high',
                    'description': f'Unsigned driver: {driver["name"]}'
                })
            elif self.is_driver_suspicious(driver):
                suspicious.append({
                    'type': 'suspicious_driver',
                    'name': driver['name'],
                    'path': driver['path'],
                    'severity': 'medium',
                    'description': f'Suspicious driver detected: {driver["name"]}'
                })
        
        return suspicious
    
    def protect_process(self, pid: int):
        """Protect a process from termination"""
        if self.system == "Windows":
            # Set process as critical
            PROCESS_SET_INFORMATION = 0x0200
            ProcessBreakOnTermination = 29
            
            try:
                handle = self.kernel32.OpenProcess(PROCESS_SET_INFORMATION, False, pid)
                if handle:
                    is_critical = ctypes.c_ulong(1)
                    self.ntdll.NtSetInformationProcess(
                        handle,
                        ProcessBreakOnTermination,
                        ctypes.byref(is_critical),
                        ctypes.sizeof(is_critical)
                    )
                    self.kernel32.CloseHandle(handle)
                    return True
            except Exception as e:
                self.logger.error(f"Failed to protect process {pid}: {e}")
                
        return False
    
    def block_driver_loading(self, driver_path: str):
        """Block a specific driver from loading"""
        # Add to driver blocklist in kernel
        blocklist_path = "/sys/kernel/security/aiav/driver_blocklist"
        
        try:
            with open(blocklist_path, 'a') as f:
                f.write(f"{driver_path}\n")
            return True
        except Exception as e:
            self.logger.error(f"Failed to block driver: {e}")
            return False
    
    # Callback functions for minifilter
    def on_file_create(self, file_path: str, process_id: int) -> bool:
        """Handle file creation attempts"""
        # Check if process is allowed to create files
        if self.is_process_malicious(process_id):
            self.logger.warning(f"Blocked file creation by PID {process_id}: {file_path}")
            return False  # Block operation
        return True  # Allow operation
    
    def on_file_read(self, file_path: str, process_id: int) -> bool:
        """Handle file read attempts"""
        # Check for sensitive file access
        if self.is_sensitive_file(file_path) and not self.is_process_trusted(process_id):
            self.logger.warning(f"Blocked sensitive file read by PID {process_id}: {file_path}")
            return False
        return True
    
    def on_file_write(self, file_path: str, process_id: int) -> bool:
        """Handle file write attempts"""
        # Check for ransomware behavior
        if self.is_ransomware_behavior(file_path, process_id):
            self.logger.critical(f"Blocked ransomware write by PID {process_id}: {file_path}")
            return False
        return True
    
    def on_file_delete(self, file_path: str, process_id: int) -> bool:
        """Handle file deletion attempts"""
        # Protect critical system files
        if self.is_critical_file(file_path):
            self.logger.warning(f"Blocked critical file deletion by PID {process_id}: {file_path}")
            return False
        return True
    
    def on_file_rename(self, old_path: str, new_path: str, process_id: int) -> bool:
        """Handle file rename attempts"""
        # Check for suspicious extensions (ransomware)
        suspicious_extensions = ['.locked', '.encrypted', '.enc', '.crypto']
        
        if any(new_path.endswith(ext) for ext in suspicious_extensions):
            self.logger.critical(f"Blocked suspicious rename by PID {process_id}: {old_path} -> {new_path}")
            return False
        return True
    
    # Helper methods
    def read_kernel_memory(self, address: int, size: int) -> bytes:
        """Read kernel memory (requires driver)"""
        # This would use the loaded driver to read kernel memory
        # Placeholder implementation
        return b'\x00' * size
    
    def get_ssdt_base(self) -> int:
        """Get SSDT base address"""
        # Platform-specific implementation
        if self.system == "Windows":
            # Would use kernel driver to get KeServiceDescriptorTable
            return 0xFFFFF80000000000  # Placeholder
        return 0
    
    def get_idt_base(self) -> int:
        """Get IDT base address"""
        # Would read from IDTR register via driver
        return 0xFFFFF80000001000  # Placeholder
    
    def get_usermode_processes(self) -> List[Dict[str, Any]]:
        """Get process list from usermode"""
        import psutil
        return [{'pid': p.pid, 'name': p.name()} for p in psutil.process_iter()]
    
    def get_kernel_processes(self) -> List[Dict[str, Any]]:
        """Get process list from kernel"""
        # Would enumerate EPROCESS list via driver
        return self.get_usermode_processes()  # Placeholder
    
    def is_structure_tampered(self, structure_name: str) -> bool:
        """Check if kernel structure is tampered"""
        # Would verify structure integrity via driver
        return False  # Placeholder
    
    def enumerate_drivers(self) -> List[Dict[str, Any]]:
        """Enumerate loaded drivers"""
        drivers = []
        
        if self.system == "Windows":
            # Would use WMI or kernel driver
            pass
        elif self.system == "Linux":
            # Parse /proc/modules
            try:
                with open('/proc/modules', 'r') as f:
                    for line in f:
                        parts = line.split()
                        drivers.append({
                            'name': parts[0],
                            'size': int(parts[1]),
                            'path': f'/lib/modules/{parts[0]}.ko',
                            'signed': True  # Would check signature
                        })
            except Exception:
                pass
        
        return drivers
    
    def is_driver_suspicious(self, driver: Dict[str, Any]) -> bool:
        """Check if driver is suspicious"""
        suspicious_names = ['rootkit', 'hide', 'stealth', 'hack', 'evil']
        driver_name = driver['name'].lower()
        
        return any(sus in driver_name for sus in suspicious_names)
    
    def is_process_malicious(self, pid: int) -> bool:
        """Check if process is malicious"""
        # Would check against threat database
        return False  # Placeholder
    
    def is_process_trusted(self, pid: int) -> bool:
        """Check if process is trusted"""
        # Would verify digital signature
        return True  # Placeholder
    
    def is_sensitive_file(self, file_path: str) -> bool:
        """Check if file contains sensitive data"""
        sensitive_paths = [
            'passwords', 'wallet', 'private', 'secret',
            'confidential', 'ssn', 'credit'
        ]
        
        return any(s in file_path.lower() for s in sensitive_paths)
    
    def is_critical_file(self, file_path: str) -> bool:
        """Check if file is critical system file"""
        critical_paths = [
            'System32', 'system32',
            'Windows\\System',
            '/etc/', '/bin/', '/sbin/',
            '/usr/bin/', '/usr/sbin/'
        ]
        
        return any(c in file_path for c in critical_paths)
    
    def is_ransomware_behavior(self, file_path: str, pid: int) -> bool:
        """Detect ransomware behavior patterns"""
        # Would track file operations per process
        return False  # Placeholder
    
    def register_minifilter_callbacks(self):
        """Register minifilter callbacks with Windows Filter Manager"""
        # Would use FilterRegisterCallbacks API
        pass
    
    def setup_linux_hooks(self):
        """Setup Linux kernel hooks"""
        # Would register kprobes or use LSM hooks
        pass