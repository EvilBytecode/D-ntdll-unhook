import core.sys.windows.windows;
import core.sys.windows.psapi;
import std.stdio;
import std.string;
import core.stdc.string;
// tried to rewrite from my ntdll unhooker lol.
extern (C) {
    pragma(lib, "psapi");

    int unhook_ntdll() {
        HANDLE process = GetCurrentProcess();
        MODULEINFO mi = MODULEINFO.init;

        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        GetModuleInformation(process, ntdll, &mi, cast(uint)MODULEINFO.sizeof);
        LPVOID ntdllsigmabase = cast(LPVOID)mi.lpBaseOfDll;

        HANDLE ntdllpath = CreateFileA("c:\\windows\\system32\\ntdll.dll", 
            GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

        HANDLE ntdllmap = CreateFileMappingA(ntdllpath, NULL, 
            PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);

        LPVOID ntdllmapaddr = MapViewOfFile(ntdllmap, FILE_MAP_READ, 0, 0, 0);

        PIMAGE_DOS_HEADER hookedDosHeader = cast(PIMAGE_DOS_HEADER)ntdllsigmabase;
        PIMAGE_NT_HEADERS hookedNtHeader = cast(PIMAGE_NT_HEADERS)(
            cast(DWORD_PTR)ntdllsigmabase + hookedDosHeader.e_lfanew);

        foreach (i; 0 .. hookedNtHeader.FileHeader.NumberOfSections) {
            PIMAGE_SECTION_HEADER hooksecheader = cast(PIMAGE_SECTION_HEADER)(
                cast(DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + 
                cast(DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i);

            if (hooksecheader.Name[0 .. 5] == ".text") {
                DWORD oldprotect = 0;
                bool isprotected = VirtualProtect(
                    cast(LPVOID)(cast(DWORD_PTR)ntdllsigmabase + 
                    cast(DWORD_PTR)hooksecheader.VirtualAddress), 
                    hooksecheader.Misc.VirtualSize, 
                    PAGE_EXECUTE_READWRITE, 
                    &oldprotect) != 0;

                core.stdc.string.memcpy(
                    cast(LPVOID)(cast(DWORD_PTR)ntdllsigmabase + 
                    cast(DWORD_PTR)hooksecheader.VirtualAddress), 
                    cast(LPVOID)(cast(DWORD_PTR)ntdllmapaddr + 
                    cast(DWORD_PTR)hooksecheader.VirtualAddress), 
                    hooksecheader.Misc.VirtualSize);

                isprotected = VirtualProtect(
                    cast(LPVOID)(cast(DWORD_PTR)ntdllsigmabase + 
                    cast(DWORD_PTR)hooksecheader.VirtualAddress), 
                    hooksecheader.Misc.VirtualSize, 
                    oldprotect, 
                    &oldprotect) != 0;
            }
        }
        //cleanup the mess :imp:
        CloseHandle(process);
        CloseHandle(ntdllpath);
        CloseHandle(ntdllmap);

        return 0;
    }
}

void main() {
    int ret = unhook_ntdll();
    if (ret != 0) {
        writeln("[-] [noob] [sigma error] [failed 2 ] unhook ntdll.dll");
    } else {
        writeln("[+] [sigma sucessfully] ntdll.dll unhooked successfully");
    }
    
        readln();
}
