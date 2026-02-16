#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BlueStacks Free Fire Memory Patcher for Windows
Auto-detects BlueStacks and applies memory patches to Free Fire
"""

import os
import sys
import time
import ctypes
import subprocess
import tempfile
from ctypes import wintypes

# ==========================================
# CONFIGURATION
# ==========================================
PATCHES = [
    {
        "name": "Fast GUN",
        "offset": 0x2d72bc8,
        "modify": "20 00 80 D2 C0 03 5F D6",
        "original": "E9 23 BD 6D F4 4F 01 A9"
    },
    {
        "name": "AmmoInClip",
        "offset": 0x32f0210,
        "modify": "1F 20 03 D5",
        "original": "F6 57 BD A9 F4 4F 01 A9"
    },
    {
        "name": "No Recoil",
        "offset": 0x40fee84,
        "modify": "00 00 00 00 C0 03 5F D6",
        "original": "E8 0F 1D FC F4 4F 01 A9"
    },
    {
        "name": "Gold Body location",
        "offset": 0x2e27b08,
        "modify": "20 00 80 D2 C0 03 5F D6",
        "original": "F4 4F BE A9 FD 7B 01 A9"
    },
    {
        "name": "HD Map",
        "offset": 0x8300480,
        "modify": "20 00 80 D2 C0 03 5F D6",
        "original": "00 C0 43 39 C0 03 5F D6"
    },
    {
        "name": "Camera Hack 360",
        "offset": 0x2d8602c,
        "modify": "20 00 80 D2 C0 03 5F D6",
        "original": "F4 4F BE A9 FD 7B 01 A9"
    },
    {
        "name": "Fast Blood Wrap",
        "offset": 0x40fe5e0,
        "modify": "00 00 00 00 C0 03 5F D6",
        "original": "F4 4F BE A9 FD 7B 01 A9"
    },
    {
        "name": "Silent Aim 360",
        "offset": 0x2d633ec,
        "modify": "1F 20 03 D5",
        "original": "FF C3 04 D1 EF 3B 0A 6D"
    }
]

# Windows API Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

# ==========================================
# WINDOWS API SETUP
# ==========================================
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = wintypes.BOOL

# ==========================================
# UTILITY FUNCTIONS
# ==========================================
def print_banner():
    """Display banner"""
    print("="*60)
    print("     BLUESTACKS FREE FIRE MEMORY PATCHER")
    print("     For Windows + BlueStacks")
    print("="*60)
    print()

def install_dependencies():
    """Install required Python packages"""
    required = ['psutil']
    for package in required:
        try:
            __import__(package)
        except ImportError:
            print(f"[*] Installing {package}...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package, "--quiet"])
                print(f"[+] {package} installed")
            except:
                print(f"[-] Failed to install {package}. Please install manually: pip install {package}")
                return False
    return True

def write_log(message):
    """Write to log file"""
    log_file = os.path.join(tempfile.gettempdir(), "freefire_patch_log.txt")
    try:
        with open(log_file, "a", encoding='utf-8') as f:
            timestamp = time.strftime('%H:%M:%S')
            f.write(f"[{timestamp}] {message}\n")
    except:
        pass

def find_bluestacks_pid():
    """Find BlueStacks process ID"""
    try:
        import psutil
        bs_processes = ["HD-Player.exe", "BlueStacks.exe", "BlueStacks Service.exe"]
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] in bs_processes:
                    print(f"[+] Found BlueStacks: {proc.info['name']} (PID: {proc.info['pid']})")
                    return proc.info['pid']
            except:
                continue
    except Exception as e:
        print(f"[-] Error finding BlueStacks: {e}")
    
    return None

def find_freefire_pid():
    """Find Free Fire process"""
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'].lower()
                if any(x in name for x in ['freefire', 'ff', 'free fire']):
                    print(f"[+] Found Free Fire process: {proc.info['name']} (PID: {proc.info['pid']})")
                    return proc.info['pid']
            except:
                continue
    except:
        pass
    return None

def get_module_base(pid, module_name=""):
    """Get base address of process"""
    try:
        import psutil
        process = psutil.Process(pid)
        for mmap in process.memory_maps():
            if module_name.lower() in mmap.path.lower() or 'lib' in mmap.path.lower():
                return int(mmap.addr.split('-')[0], 16)
    except:
        pass
    return 0x40000000  # Default fallback

def read_memory(pid, address, size):
    """Read memory from process"""
    h_process = OpenProcess(PROCESS_VM_READ, False, pid)
    if not h_process:
        return None
    
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    
    success = ReadProcessMemory(h_process, address, buffer, size, ctypes.byref(bytes_read))
    CloseHandle(h_process)
    
    if success and bytes_read.value == size:
        return buffer.raw.hex().upper()
    return None

def write_memory(pid, address, hex_str):
    """Write memory to process"""
    data = bytes.fromhex(hex_str.replace(" ", ""))
    size = len(data)
    
    h_process = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, False, pid)
    if not h_process:
        return False
    
    buffer = ctypes.create_string_buffer(data)
    bytes_written = ctypes.c_size_t(0)
    
    success = WriteProcessMemory(h_process, address, buffer, size, ctypes.byref(bytes_written))
    CloseHandle(h_process)
    
    return success and bytes_written.value == size

# ==========================================
# MAIN FUNCTION
# ==========================================
def main():
    print_banner()
    
    # Step 1: Install dependencies
    print("[*] Checking dependencies...")
    if not install_dependencies():
        input("\nPress Enter to exit...")
        return
    
    # Step 2: Find BlueStacks
    print("\n[*] Looking for BlueStacks...")
    bs_pid = find_bluestacks_pid()
    if not bs_pid:
        print("[-] BlueStacks not found. Please start BlueStacks first.")
        input("\nPress Enter to exit...")
        return
    
    # Step 3: Wait for Free Fire
    print("\n[*] Waiting for Free Fire to start...")
    print("[!] Please launch Free Fire in BlueStacks now")
    
    ff_pid = None
    for i in range(60):  # Wait up to 60 seconds
        ff_pid = find_freefire_pid()
        if ff_pid:
            break
        print(f"[*] Waiting... ({i+1}/60)")
        time.sleep(1)
    
    if not ff_pid:
        print("[-] Free Fire not detected. Please make sure it's running.")
        input("\nPress Enter to exit...")
        return
    
    print(f"[+] Free Fire detected with PID: {ff_pid}")
    
    # Step 4: Get base address
    print("\n[*] Getting process base address...")
    base_addr = get_module_base(ff_pid, "libil2cpp")
    print(f"[+] Base address: {hex(base_addr)}")
    
    # Step 5: Apply patches
    print("\n[*] Applying memory patches...")
    successful = 0
    
    for patch in PATCHES:
        target = base_addr + patch['offset']
        print(f"\n[*] Patching: {patch['name']}")
        print(f"    Target: {hex(target)}")
        
        if write_memory(ff_pid, target, patch['modify']):
            # Verify patch
            current = read_memory(ff_pid, target, len(patch['modify'].replace(" ", ""))//2)
            if current == patch['modify'].replace(" ", "").upper():
                print(f"    [✓] Success")
                write_log(f"Patched: {patch['name']} at {hex(target)}")
                successful += 1
            else:
                print(f"    [!] Written but verification failed")
                write_log(f"Verification failed: {patch['name']}")
        else:
            print(f"    [✗] Failed")
            write_log(f"Failed: {patch['name']}")
    
    # Final report
    print(f"\n{'='*60}")
    print(f"PATCHING COMPLETE: {successful}/{len(PATCHES)} successful")
    print("="*60)
    print("\n[✓] You can now play Free Fire in BlueStacks!")
    print("[!] Close this window or press Ctrl+C to stop monitoring")
    
    # Step 6: Monitor mode (keep patches applied)
    print("\n[*] Starting monitor mode (re-applies patches if needed)...")
    try:
        while True:
            time.sleep(2)
            for patch in PATCHES:
                target = base_addr + patch['offset']
                current = read_memory(ff_pid, target, len(patch['modify'].replace(" ", ""))//2)
                expected = patch['modify'].replace(" ", "").upper()
                
                if current and current != expected:
                    if write_memory(ff_pid, target, patch['modify']):
                        print(f"[!] Re-patched: {patch['name']}")
                        write_log(f"Re-patched: {patch['name']}")
    except KeyboardInterrupt:
        print("\n\n[!] Monitor mode stopped")
    
    write_log("Session ended")
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    try:
        # Check if running on Windows
        if os.name != 'nt':
            print("[-] This script is for Windows only!")
            input("Press Enter to exit...")
            sys.exit(1)
        
        # Request admin privileges
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[!] Administrator privileges required for memory access")
            print("[*] Please run this script as Administrator")
            input("Press Enter to exit...")
            sys.exit(1)
        
        main()
    except Exception as e:
        print(f"\n[!] Error: {e}")
        write_log(f"CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")