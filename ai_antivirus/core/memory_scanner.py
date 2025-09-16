"""
Advanced Memory Scanner for Fileless Malware Detection
Scans process memory for injected code, shellcode, and memory-based threats
"""
import os
import sys
import ctypes
import struct
import psutil
import re
import hashlib
import yara
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime
import logging
from pathlib import Path

class MemoryScanner:
    """Advanced memory scanning for fileless malware"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.yara_rules = self.load_yara_rules()
        self.shellcode_patterns = self.load_shellcode_patterns()
        self.process_cache = {}
        self.scanned_regions = set()
        
        # Platform-specific initialization
        if sys.platform == "win32":
            self.init_windows()
        else:
            self.init_linux()
    
    def init_windows(self):
        """Initialize Windows-specific memory access"""
        self.kernel32 = ctypes.windll.kernel32
        self.ntdll = ctypes.windll.ntdll
        self.psapi = ctypes.windll.psapi
        
        # Process access rights
        self.PROCESS_VM_READ = 0x0010
        self.PROCESS_QUERY_INFORMATION = 0x0400
        self.MEM_COMMIT = 0x1000
        self.PAGE_READWRITE = 0x04
        self.PAGE_EXECUTE_READWRITE = 0x40
        
    def init_linux(self):
        """Initialize Linux-specific memory access"""
        self.libc = ctypes.CDLL("libc.so.6")
        
    def load_yara_rules(self) -> Optional[yara.Rules]:
        """Load YARA rules for memory scanning"""
        try:
            rules_path = Path("data/yara_rules/memory_rules.yar")
            if rules_path.exists():
                return yara.compile(filepath=str(rules_path))
            else:
                # Compile default rules
                default_rules = """
                rule Shellcode_Patterns {
                    strings:
                        $mz = "MZ"
                        $pe = "PE" 
                        $shell1 = { 31 c0 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? }
                        $shell2 = { 55 8b ec 83 ec ?? 53 56 57 }
                        $shell3 = { 64 a1 30 00 00 00 }
                        $shell4 = { ff 75 ?? ff 75 ?? ff 75 ?? }
                    condition:
                        any of them
                }
                
                rule Process_Hollowing {
                    strings:
                        $api1 = "NtUnmapViewOfSection"
                        $api2 = "VirtualAllocEx"
                        $api3 = "WriteProcessMemory"
                        $api4 = "SetThreadContext"
                        $api5 = "ResumeThread"
                    condition:
                        3 of them
                }
                
                rule Reflective_DLL {
                    strings:
                        $s1 = "ReflectiveLoader"
                        $s2 = { 4D 5A 90 00 03 00 00 00 }
                        $s3 = "kernel32.dll"
                        $s4 = "LoadLibraryA"
                    condition:
                        $s1 or ($s2 and $s3 and $s4)
                }
                
                rule Meterpreter_Payload {
                    strings:
                        $s1 = "metsrv.dll"
                        $s2 = "ReflectiveLoader"
                        $s3 = { 4D 65 74 65 72 70 72 65 74 65 72 }
                    condition:
                        any of them
                }
                
                rule CobaltStrike_Beacon {
                    strings:
                        $s1 = "beacon.dll"
                        $s2 = "%s.%s%s"
                        $s3 = "ReflectiveLoader"
                        $config = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
                    condition:
                        2 of them
                }
                """
                return yara.compile(source=default_rules)
        except Exception as e:
            self.logger.error(f"Failed to load YARA rules: {e}")
            return None
    
    def load_shellcode_patterns(self) -> List[bytes]:
        """Load common shellcode patterns"""
        patterns = [
            # Common x86/x64 shellcode patterns
            b'\x31\xc0\x50\x68',  # xor eax,eax; push eax; push
            b'\x31\xdb\x53\x68',  # xor ebx,ebx; push ebx; push
            b'\x31\xc9\x51\x68',  # xor ecx,ecx; push ecx; push
            b'\x55\x8b\xec\x83',  # push ebp; mov ebp,esp; sub
            b'\x64\xa1\x30\x00',  # mov eax,fs:[30]
            b'\x65\x48\x8b\x04',  # mov rax,gs:[...]
            b'\xfc\x48\x83\xe4',  # cld; and rsp,...
            b'\x60\x89\xe5\x31',  # pushad; mov ebp,esp; xor
            b'\xeb\x3c\x5b\x31',  # jmp; pop ebx; xor
            b'\xe8\xff\xff\xff',  # call $+5
            
            # Metasploit patterns
            b'\x6a\x00\x53\xff',  # push 0; push ebx; call
            b'\xb8\x90\x01\x00',  # mov eax, 0x190
            
            # WinExec shellcode
            b'WinExec\x00',
            b'cmd.exe\x00',
            
            # Egg hunter
            b'\x66\x81\xca\xff',  # or dx,0x0fff
            b'\x42\x52\x6a\x02',  # inc edx; push edx; push 2
        ]
        
        return patterns
    
    def scan_all_processes(self) -> List[Dict[str, Any]]:
        """Scan all running processes for memory threats"""
        results = []
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                
                # Skip system processes on Windows
                if name.lower() in ['system', 'registry', 'smss.exe']:
                    continue
                
                # Scan process memory
                threats = self.scan_process_memory(pid, name)
                
                if threats:
                    results.append({
                        'pid': pid,
                        'name': name,
                        'threats': threats,
                        'severity': self.calculate_severity(threats)
                    })
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                self.logger.debug(f"Error scanning process {proc.info['pid']}: {e}")
        
        return results
    
    def scan_process_memory(self, pid: int, process_name: str = "") -> List[Dict[str, Any]]:
        """Scan a specific process memory for threats"""
        threats = []
        
        try:
            # Open process
            if sys.platform == "win32":
                process_handle = self.open_windows_process(pid)
                if not process_handle:
                    return threats
            else:
                # Linux memory reading via /proc/pid/mem
                mem_path = f"/proc/{pid}/mem"
                maps_path = f"/proc/{pid}/maps"
                
                if not os.path.exists(mem_path):
                    return threats
            
            # Get memory regions
            memory_regions = self.get_memory_regions(pid)
            
            for region in memory_regions:
                # Check if region is suspicious
                if self.is_suspicious_region(region):
                    # Read memory from region
                    memory_data = self.read_memory_region(pid, region)
                    
                    if memory_data:
                        # Scan for threats
                        region_threats = self.analyze_memory_region(
                            memory_data, 
                            region, 
                            pid, 
                            process_name
                        )
                        
                        if region_threats:
                            threats.extend(region_threats)
            
            # Check for process hollowing
            if self.detect_process_hollowing(pid):
                threats.append({
                    'type': 'process_hollowing',
                    'description': 'Process appears to be hollowed',
                    'severity': 'critical'
                })
            
            # Check for injected threads
            injected = self.detect_injected_threads(pid)
            if injected:
                threats.extend(injected)
                
        except Exception as e:
            self.logger.debug(f"Error scanning process {pid}: {e}")
        
        return threats
    
    def open_windows_process(self, pid: int):
        """Open Windows process for memory reading"""
        try:
            return self.kernel32.OpenProcess(
                self.PROCESS_VM_READ | self.PROCESS_QUERY_INFORMATION,
                False,
                pid
            )
        except:
            return None
    
    def get_memory_regions(self, pid: int) -> List[Dict[str, Any]]:
        """Get memory regions of a process"""
        regions = []
        
        if sys.platform == "win32":
            # Windows implementation
            regions = self.get_windows_memory_regions(pid)
        else:
            # Linux implementation
            regions = self.get_linux_memory_regions(pid)
        
        return regions
    
    def get_windows_memory_regions(self, pid: int) -> List[Dict[str, Any]]:
        """Get memory regions for Windows process"""
        regions = []
        
        try:
            process_handle = self.open_windows_process(pid)
            if not process_handle:
                return regions
            
            # MEMORY_BASIC_INFORMATION structure
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", ctypes.c_ulong),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", ctypes.c_ulong),
                    ("Protect", ctypes.c_ulong),
                    ("Type", ctypes.c_ulong)
                ]
            
            mbi = MEMORY_BASIC_INFORMATION()
            address = 0
            
            while address < 0x7FFFFFFF0000:  # User space limit
                result = self.kernel32.VirtualQueryEx(
                    process_handle,
                    ctypes.c_void_p(address),
                    ctypes.byref(mbi),
                    ctypes.sizeof(mbi)
                )
                
                if result == 0:
                    break
                
                if mbi.State == self.MEM_COMMIT:
                    regions.append({
                        'base': mbi.BaseAddress,
                        'size': mbi.RegionSize,
                        'protection': mbi.Protect,
                        'type': mbi.Type
                    })
                
                address += mbi.RegionSize
            
            self.kernel32.CloseHandle(process_handle)
            
        except Exception as e:
            self.logger.debug(f"Error getting Windows memory regions: {e}")
        
        return regions
    
    def get_linux_memory_regions(self, pid: int) -> List[Dict[str, Any]]:
        """Get memory regions for Linux process"""
        regions = []
        
        try:
            maps_path = f"/proc/{pid}/maps"
            with open(maps_path, 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 6:
                        addr_range = parts[0].split('-')
                        start = int(addr_range[0], 16)
                        end = int(addr_range[1], 16)
                        perms = parts[1]
                        
                        regions.append({
                            'base': start,
                            'size': end - start,
                            'permissions': perms,
                            'path': parts[5] if len(parts) > 5 else ''
                        })
        except Exception as e:
            self.logger.debug(f"Error getting Linux memory regions: {e}")
        
        return regions
    
    def is_suspicious_region(self, region: Dict[str, Any]) -> bool:
        """Check if memory region is suspicious"""
        # Check for executable and writable regions (RWX)
        if sys.platform == "win32":
            if region.get('protection') == self.PAGE_EXECUTE_READWRITE:
                return True
        else:
            perms = region.get('permissions', '')
            if 'rwx' in perms:
                return True
        
        # Check for large uncommitted regions
        if region.get('size', 0) > 10 * 1024 * 1024:  # > 10MB
            return True
        
        # Check for regions without backing file (potential injection)
        if not region.get('path') and region.get('size', 0) > 4096:
            return True
        
        return False
    
    def read_memory_region(self, pid: int, region: Dict[str, Any]) -> Optional[bytes]:
        """Read memory from a specific region"""
        try:
            if sys.platform == "win32":
                return self.read_windows_memory(pid, region)
            else:
                return self.read_linux_memory(pid, region)
        except Exception as e:
            self.logger.debug(f"Error reading memory region: {e}")
            return None
    
    def read_windows_memory(self, pid: int, region: Dict[str, Any]) -> Optional[bytes]:
        """Read memory from Windows process"""
        try:
            process_handle = self.open_windows_process(pid)
            if not process_handle:
                return None
            
            buffer = ctypes.create_string_buffer(region['size'])
            bytes_read = ctypes.c_size_t()
            
            success = self.kernel32.ReadProcessMemory(
                process_handle,
                ctypes.c_void_p(region['base']),
                buffer,
                region['size'],
                ctypes.byref(bytes_read)
            )
            
            self.kernel32.CloseHandle(process_handle)
            
            if success:
                return buffer.raw[:bytes_read.value]
                
        except Exception as e:
            self.logger.debug(f"Error reading Windows memory: {e}")
        
        return None
    
    def read_linux_memory(self, pid: int, region: Dict[str, Any]) -> Optional[bytes]:
        """Read memory from Linux process"""
        try:
            mem_path = f"/proc/{pid}/mem"
            with open(mem_path, 'rb') as f:
                f.seek(region['base'])
                return f.read(min(region['size'], 1024 * 1024))  # Max 1MB per region
        except Exception as e:
            self.logger.debug(f"Error reading Linux memory: {e}")
            return None
    
    def analyze_memory_region(self, memory_data: bytes, region: Dict[str, Any], 
                            pid: int, process_name: str) -> List[Dict[str, Any]]:
        """Analyze memory region for threats"""
        threats = []
        
        # YARA scanning
        if self.yara_rules:
            try:
                matches = self.yara_rules.match(data=memory_data)
                for match in matches:
                    threats.append({
                        'type': 'yara_match',
                        'rule': match.rule,
                        'description': f'YARA rule {match.rule} matched',
                        'severity': 'high',
                        'offset': match.strings[0][0] if match.strings else 0
                    })
            except Exception as e:
                self.logger.debug(f"YARA scanning error: {e}")
        
        # Shellcode pattern detection
        for pattern in self.shellcode_patterns:
            if pattern in memory_data:
                offset = memory_data.find(pattern)
                threats.append({
                    'type': 'shellcode',
                    'pattern': pattern.hex(),
                    'description': 'Shellcode pattern detected',
                    'severity': 'critical',
                    'offset': offset
                })
        
        # Check for PE files in memory (process hollowing)
        if b'MZ' in memory_data:
            mz_offset = memory_data.find(b'MZ')
            if mz_offset >= 0 and len(memory_data) > mz_offset + 0x3c:
                pe_offset_bytes = memory_data[mz_offset + 0x3c:mz_offset + 0x40]
                if len(pe_offset_bytes) == 4:
                    pe_offset = struct.unpack('<I', pe_offset_bytes)[0]
                    if len(memory_data) > mz_offset + pe_offset + 2:
                        if memory_data[mz_offset + pe_offset:mz_offset + pe_offset + 2] == b'PE':
                            threats.append({
                                'type': 'pe_in_memory',
                                'description': 'Executable file found in memory (possible injection)',
                                'severity': 'critical',
                                'offset': mz_offset
                            })
        
        # Check for encoded/encrypted payloads
        entropy = self.calculate_entropy(memory_data[:1024])  # Check first 1KB
        if entropy > 7.5:  # High entropy indicates encryption/packing
            threats.append({
                'type': 'high_entropy',
                'entropy': entropy,
                'description': 'High entropy region detected (possible encrypted payload)',
                'severity': 'medium'
            })
        
        # Check for suspicious API strings
        suspicious_apis = [
            b'VirtualAllocEx', b'WriteProcessMemory', b'CreateRemoteThread',
            b'SetWindowsHookEx', b'NtQueueApcThread', b'RtlCreateUserThread',
            b'ZwMapViewOfSection', b'NtUnmapViewOfSection', b'OpenProcess',
            b'ReadProcessMemory', b'CreateToolhelp32Snapshot'
        ]
        
        found_apis = []
        for api in suspicious_apis:
            if api in memory_data:
                found_apis.append(api.decode('utf-8', errors='ignore'))
        
        if len(found_apis) >= 3:
            threats.append({
                'type': 'suspicious_apis',
                'apis': found_apis,
                'description': f'Multiple injection APIs found: {", ".join(found_apis)}',
                'severity': 'high'
            })
        
        # Check for known malware signatures
        malware_sigs = self.check_malware_signatures(memory_data)
        if malware_sigs:
            threats.extend(malware_sigs)
        
        return threats
    
    def detect_process_hollowing(self, pid: int) -> bool:
        """Detect process hollowing technique"""
        try:
            process = psutil.Process(pid)
            
            # Check if process image path matches what's in memory
            exe_path = process.exe()
            
            # Read PE header from file
            with open(exe_path, 'rb') as f:
                file_header = f.read(1024)
            
            # Read PE header from memory
            regions = self.get_memory_regions(pid)
            if regions:
                # First region should be image base
                memory_header = self.read_memory_region(pid, regions[0])
                
                if memory_header and file_header:
                    # Compare headers
                    if memory_header[:1024] != file_header:
                        return True  # Headers don't match - possible hollowing
                        
        except Exception as e:
            self.logger.debug(f"Error detecting process hollowing: {e}")
        
        return False
    
    def detect_injected_threads(self, pid: int) -> List[Dict[str, Any]]:
        """Detect injected threads in a process"""
        threats = []
        
        try:
            if sys.platform == "win32":
                # Check thread start addresses
                threads = self.enumerate_threads(pid)
                
                for thread in threads:
                    start_addr = thread.get('start_address')
                    if start_addr:
                        # Check if start address is outside process image
                        if not self.is_address_in_module(pid, start_addr):
                            threats.append({
                                'type': 'injected_thread',
                                'thread_id': thread['tid'],
                                'start_address': hex(start_addr),
                                'description': 'Thread with suspicious start address',
                                'severity': 'high'
                            })
        except Exception as e:
            self.logger.debug(f"Error detecting injected threads: {e}")
        
        return threats
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0.0
        data_len = len(data)
        
        # Count byte frequencies
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy
        import math
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def check_malware_signatures(self, memory_data: bytes) -> List[Dict[str, Any]]:
        """Check for known malware signatures"""
        signatures = []
        
        # Metasploit Meterpreter
        if b'metsrv.dll' in memory_data or b'\x4d\x65\x74\x65\x72\x70\x72\x65\x74\x65\x72' in memory_data:
            signatures.append({
                'type': 'malware_signature',
                'family': 'Meterpreter',
                'description': 'Metasploit Meterpreter payload detected',
                'severity': 'critical'
            })
        
        # Cobalt Strike Beacon
        if b'beacon.dll' in memory_data or b'beacon.x64.dll' in memory_data:
            signatures.append({
                'type': 'malware_signature',
                'family': 'CobaltStrike',
                'description': 'Cobalt Strike Beacon detected',
                'severity': 'critical'
            })
        
        # Mimikatz
        if b'mimikatz' in memory_data.lower() or b'sekurlsa::' in memory_data:
            signatures.append({
                'type': 'malware_signature',
                'family': 'Mimikatz',
                'description': 'Mimikatz credential dumper detected',
                'severity': 'critical'
            })
        
        return signatures
    
    def calculate_severity(self, threats: List[Dict[str, Any]]) -> str:
        """Calculate overall severity from threats"""
        if any(t.get('severity') == 'critical' for t in threats):
            return 'critical'
        elif any(t.get('severity') == 'high' for t in threats):
            return 'high'
        elif any(t.get('severity') == 'medium' for t in threats):
            return 'medium'
        else:
            return 'low'
    
    def enumerate_threads(self, pid: int) -> List[Dict[str, Any]]:
        """Enumerate threads of a process"""
        threads = []
        
        # Placeholder - would use CreateToolhelp32Snapshot on Windows
        # or parse /proc/pid/task on Linux
        
        return threads
    
    def is_address_in_module(self, pid: int, address: int) -> bool:
        """Check if address belongs to a loaded module"""
        # Placeholder - would enumerate process modules
        # and check if address falls within module bounds
        return True