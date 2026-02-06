#ifndef brkvm_h
#define brkvm_h

#include <windows.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <cstdint>

#pragma comment(lib, "iphlpapi.lib")

namespace brkvm {
    
    inline bool check_cpuid() {
        int info[4];
        
        __cpuid(info, 1);
        bool hypervisor_bit = (info[2] >> 31) & 1;
        
        if (!hypervisor_bit) {
            return false;
        }
        
        char vendor[13] = {0};
        __cpuid(info, 0x40000000);
        memcpy(vendor, &info[1], 4);
        memcpy(vendor + 4, &info[2], 4);
        memcpy(vendor + 8, &info[3], 4);
        
        const char* vm_vendors[] = {
            "VMwareVMware", "KVMKVMKVM", "Microsoft Hv",
            "XenVMMXenVMM", "prl hyperv", "VBoxVBoxVBox"
        };
        
        for (int i = 0; i < 6; i++) {
            if (strcmp(vendor, vm_vendors[i]) == 0) {
                return true;
            }
        }
        
        return false;
    }
    
    inline bool check_vmware() {
        #if defined(_M_IX86)
        __try {
            __asm {
                push edx
                push ecx
                push ebx
                
                mov eax, 'VMXh'
                mov ebx, 0
                mov ecx, 10
                mov edx, 'VX'
                
                in eax, dx
                
                pop ebx
                pop ecx
                pop edx
            }
            return true;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
        #else
        return false;
        #endif
    }
    
    inline bool check_registry() {
        HKEY key;
        const char* paths[] = {
            "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
            "SOFTWARE\\VMware, Inc.\\VMware Tools"
        };
        
        for (int i = 0; i < 2; i++) {
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, paths[i], 0, KEY_READ, &key) == ERROR_SUCCESS) {
                RegCloseKey(key);
                return true;
            }
        }
        
        return false;
    }
    
    inline bool check_drivers() {
        const char* drivers[] = {
            "\\\\.\\VBoxGuest",
            "\\\\.\\VBoxMiniRdrDN",
            "\\\\.\\vmci"
        };
        
        for (int i = 0; i < 3; i++) {
            HANDLE device = CreateFileA(drivers[i], GENERIC_READ,
                                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                                       NULL, OPEN_EXISTING, 0, NULL);
            
            if (device != INVALID_HANDLE_VALUE) {
                CloseHandle(device);
                return true;
            }
        }
        
        return false;
    }
    
    inline bool check_processes() {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return false;
        }
        
        PROCESSENTRY32W entry;
        entry.dwSize = sizeof(PROCESSENTRY32W);
        
        const wchar_t* processes[] = {
            L"vmtoolsd.exe",
            L"vboxservice.exe",
            L"vboxtray.exe"
        };
        
        if (Process32FirstW(snapshot, &entry)) {
            do {
                for (int i = 0; i < 3; i++) {
                    if (_wcsicmp(entry.szExeFile, processes[i]) == 0) {
                        CloseHandle(snapshot);
                        return true;
                    }
                }
            } while (Process32NextW(snapshot, &entry));
        }
        
        CloseHandle(snapshot);
        return false;
    }
    
    inline bool check_mac() {
        IP_ADAPTER_INFO adapters[16];
        DWORD size = sizeof(adapters);
        
        if (GetAdaptersInfo(adapters, &size) != ERROR_SUCCESS) {
            return false;
        }
        
        const BYTE vm_macs[][3] = {
            {0x00, 0x05, 0x69},
            {0x00, 0x0C, 0x29},
            {0x00, 0x1C, 0x14},
            {0x00, 0x50, 0x56},
            {0x08, 0x00, 0x27}
        };
        
        IP_ADAPTER_INFO* adapter = adapters;
        while (adapter) {
            for (int i = 0; i < 5; i++) {
                if (memcmp(adapter->Address, vm_macs[i], 3) == 0) {
                    return true;
                }
            }
            adapter = adapter->Next;
        }
        
        return false;
    }
    
    inline bool detect() {
        return check_cpuid() ||
               check_vmware() ||
               check_registry() ||
               check_drivers() ||
               check_processes() ||
               check_mac();
    }
}

#endif