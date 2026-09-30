#include <Windows.h>
#include <TlHelp32.h>
#include <bcrypt.h>

#include <peconv.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <vector>

struct ModuleInfo
{
    uint64_t base = 0;
    size_t size = 0;
    std::wstring name;
    std::wstring path;
};

struct ExportEntry
{
    std::string dllName;
    std::string funcName;
    uint16_t ordinal = 0;
    bool hasName = false;
};

struct ImportMatch
{
    std::string requestedDll;
    bool dllNameValid = false;
    size_t totalThunks = 0;
    size_t resolvedThunks = 0;
    std::vector<std::string> sampleResolved;
};

static std::string narrow(const std::wstring& w)
{
    if (w.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string s(static_cast<size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), len, nullptr, nullptr);
    return s;
}

static std::wstring widen(const std::string& s)
{
    return std::wstring(s.begin(), s.end());
}

static bool compute_sha256_hex(const std::vector<BYTE>& data, std::string& hexOut)
{
    hexOut.clear();

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
        return false;
    }

    bool ok = false;
    DWORD hashObjLen = 0, hashLen = 0, cbData = 0;

    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&hashObjLen),
            sizeof(hashObjLen), &cbData, 0) >= 0 &&
        BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLen),
            sizeof(hashLen), &cbData, 0) >= 0) {

        std::vector<BYTE> hashObj(hashObjLen);
        BCRYPT_HASH_HANDLE hHash = nullptr;

        if (BCryptCreateHash(hAlg, &hHash, hashObj.data(), hashObjLen, nullptr, 0, 0) >= 0) {
            PUCHAR pData = data.empty() ? nullptr : const_cast<PUCHAR>(data.data());
            if (BCryptHashData(hHash, pData, static_cast<ULONG>(data.size()), 0) >= 0) {
                std::vector<BYTE> hash(hashLen);
                if (BCryptFinishHash(hHash, hash.data(), hashLen, 0) >= 0) {
                    static const char hexDigits[] = "0123456789abcdef";
                    hexOut.resize(static_cast<size_t>(hashLen) * 2);
                    for (DWORD i = 0; i < hashLen; ++i) {
                        hexOut[i * 2] = hexDigits[(hash[i] >> 4) & 0xF];
                        hexOut[i * 2 + 1] = hexDigits[hash[i] & 0xF];
                    }
                    ok = true;
                }
            }
            BCryptDestroyHash(hHash);
        }
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static bool enable_debug_privilege()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }
    bool ok = false;
    LUID luid{};
    if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr) != FALSE
            && GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(token);
    return ok;
}

static bool enum_modules(DWORD pid, std::vector<ModuleInfo>& out)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (!Module32FirstW(snap, &me)) {
        CloseHandle(snap);
        return false;
    }
    do {
        ModuleInfo m;
        m.base = reinterpret_cast<uint64_t>(me.modBaseAddr);
        m.size = me.modBaseSize;
        m.name = me.szModule;
        m.path = me.szExePath;
        out.push_back(std::move(m));
    } while (Module32NextW(snap, &me));

    CloseHandle(snap);
    return !out.empty();
}

static bool read_remote_module(HANDLE proc, uint64_t remoteBase, size_t size, std::vector<BYTE>& out)
{
    if (size == 0) return false;
    out.assign(size, 0);

    size_t offset = 0;
    while (offset < size) {
        BYTE* addr = reinterpret_cast<BYTE*>(remoteBase + offset);
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(proc, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            offset += 0x1000;
            continue;
        }

        uint64_t regionEnd = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
        uint64_t availableEnd = (std::min)(static_cast<uint64_t>(size), regionEnd - remoteBase);
        if (availableEnd <= offset) {
            offset += 0x1000;
            continue;
        }
        size_t readEnd = static_cast<size_t>(availableEnd);
        size_t chunk = readEnd - offset;

        if (mbi.State == MEM_COMMIT) {
            SIZE_T bytesRead = 0;
            ReadProcessMemory(proc, addr, out.data() + offset, chunk, &bytesRead);
        }
        offset = readEnd;
    }
    return true;
}

static IMAGE_NT_HEADERS* get_nt_headers(BYTE* base, size_t size)
{
    if (!base || size < sizeof(IMAGE_DOS_HEADER)) return nullptr;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    if (dos->e_lfanew < 0) return nullptr;

    size_t ntOffset = static_cast<size_t>(dos->e_lfanew);
    if (ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > size) return nullptr;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + ntOffset);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    return nt;
}

static IMAGE_DATA_DIRECTORY* get_data_directory(BYTE* base, size_t size, DWORD dirIndex)
{
    IMAGE_NT_HEADERS* nt = get_nt_headers(base, size);
    if (!nt) return nullptr;

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        auto* opt = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(&nt->OptionalHeader);
        if (dirIndex >= opt->NumberOfRvaAndSizes) return nullptr;
        return &opt->DataDirectory[dirIndex];
    }
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        auto* opt = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(&nt->OptionalHeader);
        if (dirIndex >= opt->NumberOfRvaAndSizes) return nullptr;
        return &opt->DataDirectory[dirIndex];
    }
    return nullptr;
}

static void build_exports_map(const std::vector<ModuleInfo>& modules, std::map<uint64_t, ExportEntry>& exportsByVa)
{
    for (const auto& m : modules) {
        if (m.path.empty()) continue;

        HMODULE h = LoadLibraryExW(m.path.c_str(), nullptr, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
        if (!h) {
            std::wcout << L"  exports skipped : " << m.name
                       << L" (LoadLibraryExW failed, error " << GetLastError() << L")\n";
            continue;
        }

        BYTE* local = reinterpret_cast<BYTE*>(reinterpret_cast<uintptr_t>(h) & ~static_cast<uintptr_t>(3));

        IMAGE_NT_HEADERS* headerNt = get_nt_headers(local, 0x1000);
        size_t localSize = 0;
        if (headerNt) {
            localSize = (headerNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                ? static_cast<size_t>(reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(&headerNt->OptionalHeader)->SizeOfImage)
                : static_cast<size_t>(reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(&headerNt->OptionalHeader)->SizeOfImage);
        }

        size_t added = 0;
        if (localSize != 0) {
            IMAGE_DATA_DIRECTORY* dir = get_data_directory(local, localSize, IMAGE_DIRECTORY_ENTRY_EXPORT);
            if (dir && dir->VirtualAddress != 0 && dir->VirtualAddress < localSize) {
                auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(local + dir->VirtualAddress);
                if (exp->NumberOfFunctions < 1000000 && exp->NumberOfNames < 1000000) {
                    auto* functions = reinterpret_cast<DWORD*>(local + exp->AddressOfFunctions);
                    auto* names = reinterpret_cast<DWORD*>(local + exp->AddressOfNames);
                    auto* nameOrds = reinterpret_cast<WORD*>(local + exp->AddressOfNameOrdinals);

                    std::map<DWORD, std::string> ordToName;
                    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
                        const char* namePtr = reinterpret_cast<const char*>(local + names[i]);
                        ordToName[nameOrds[i]] = namePtr;
                    }
                    for (DWORD i = 0; i < exp->NumberOfFunctions; ++i) {
                        DWORD rva = functions[i];
                        if (rva == 0) continue;
                        ExportEntry e;
                        e.dllName = narrow(m.name);
                        e.ordinal = static_cast<uint16_t>(exp->Base + i);
                        auto it = ordToName.find(i);
                        if (it != ordToName.end()) {
                            e.funcName = it->second;
                            e.hasName = true;
                        }
                        exportsByVa[m.base + rva] = e;
                        ++added;
                    }
                }
            }
        }

        std::wcout << L"  exports mapped  : " << m.name
                   << L" base=0x" << std::hex << std::setw(16) << std::setfill(L'0') << m.base << std::dec
                   << L" funcs=" << added << L"\n";
        FreeLibrary(h);
    }
}

static void resolve_imports(std::vector<BYTE>& image, bool is64,
    const std::map<uint64_t, ExportEntry>& exportsByVa, std::vector<ImportMatch>& report)
{
    IMAGE_DATA_DIRECTORY* impDir = get_data_directory(image.data(), image.size(), IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!impDir || impDir->VirtualAddress == 0) return;

    size_t offset = impDir->VirtualAddress;
    while (offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= image.size()) {
        auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image.data() + offset);
        if (desc->OriginalFirstThunk == 0 && desc->FirstThunk == 0) break;

        ImportMatch entry;
        if (desc->Name != 0 && desc->Name < image.size()) {
            entry.requestedDll = reinterpret_cast<char*>(image.data() + desc->Name);
            entry.dllNameValid = !entry.requestedDll.empty();
        }

        size_t thunkOffset = desc->FirstThunk;
        if (is64) {
            while (thunkOffset + sizeof(uint64_t) <= image.size()) {
                auto* slot = reinterpret_cast<uint64_t*>(image.data() + thunkOffset);
                if (*slot == 0) break;
                ++entry.totalThunks;
                if ((*slot & IMAGE_ORDINAL_FLAG64) == 0) {
                    auto it = exportsByVa.find(*slot);
                    if (it != exportsByVa.end()) {
                        ++entry.resolvedThunks;
                        if (entry.sampleResolved.size() < 5) {
                            entry.sampleResolved.push_back(it->second.dllName + "!" +
                                (it->second.hasName ? it->second.funcName : ("ord_" + std::to_string(it->second.ordinal))));
                        }
                    }
                }
                thunkOffset += sizeof(uint64_t);
            }
        } else {
            while (thunkOffset + sizeof(uint32_t) <= image.size()) {
                auto* slot = reinterpret_cast<uint32_t*>(image.data() + thunkOffset);
                if (*slot == 0) break;
                ++entry.totalThunks;
                if ((*slot & IMAGE_ORDINAL_FLAG32) == 0) {
                    uint64_t va = *slot;
                    auto it = exportsByVa.find(va);
                    if (it != exportsByVa.end()) {
                        ++entry.resolvedThunks;
                        if (entry.sampleResolved.size() < 5) {
                            entry.sampleResolved.push_back(it->second.dllName + "!" +
                                (it->second.hasName ? it->second.funcName : ("ord_" + std::to_string(it->second.ordinal))));
                        }
                    }
                }
                thunkOffset += sizeof(uint32_t);
            }
        }

        report.push_back(std::move(entry));
        offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
}

static void usage()
{
    std::wcout
        << L"LibPeConvProcessDump.exe --pid <pid> [--module <name>] [--out <path>]\n\n"
        << L"  --pid <pid>       target process id (required)\n"
        << L"  --module <name>   module to dump, e.g. kernel32.dll (default: main exe)\n"
        << L"  --out <path>      output file (default: .\\LibPeConvDump-PID<pid>-<timestamp>.exe)\n";
}

int wmain(int argc, wchar_t* argv[])
{
    std::wstring pidArg, moduleArg, outArg;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--pid" && i + 1 < argc) pidArg = argv[++i];
        else if (a == L"--module" && i + 1 < argc) moduleArg = argv[++i];
        else if (a == L"--out" && i + 1 < argc) outArg = argv[++i];
        else if (a == L"--help" || a == L"/?") {
            usage();
            return 1;
        }
    }

    if (pidArg.empty()) {
        std::wcerr << L"error: --pid is required.\n";
        usage();
        return 2;
    }

    DWORD pid = 0;
    try {
        pid = static_cast<DWORD>(std::stoul(pidArg));
    } catch (...) {
        std::wcerr << L"error: --pid must be numeric.\n";
        return 2;
    }

    if (!enable_debug_privilege()) {
        std::wcout << L"[WARN] Could not enable SeDebugPrivilege "
                      L"(continuing; may fail for protected/elevated processes).\n";
    }

    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!proc) {
        std::wcerr << L"error: OpenProcess failed for PID " << pid << L" (error " << GetLastError() << L").\n";
        return 3;
    }

    std::vector<ModuleInfo> modules;
    if (!enum_modules(pid, modules)) {
        std::wcerr << L"error: could not enumerate modules of PID " << pid
                   << L" (error " << GetLastError() << L"). "
                   << L"Note: a 32-bit build of this tool cannot enumerate a 64-bit process and vice versa.\n";
        CloseHandle(proc);
        return 4;
    }

    ModuleInfo target;
    bool found = false;
    if (!moduleArg.empty()) {
        for (auto& m : modules) {
            if (_wcsicmp(m.name.c_str(), moduleArg.c_str()) == 0) {
                target = m;
                found = true;
                break;
            }
        }
        if (!found) {
            std::wcerr << L"error: module \"" << moduleArg << L"\" not found in target process.\n";
            CloseHandle(proc);
            return 5;
        }
    } else {
        target = modules.front();
        found = true;
    }

    std::wcout << L"Target module   : " << target.name << L"\n";
    std::wcout << L"Base / size     : 0x" << std::hex << std::setw(16) << std::setfill(L'0') << target.base
               << L" / 0x" << std::setw(8) << target.size << std::dec << L"\n";

    std::vector<BYTE> image;
    if (!read_remote_module(proc, target.base, target.size, image)) {
        std::wcerr << L"error: failed to read remote module.\n";
        CloseHandle(proc);
        return 6;
    }

    bool is64 = peconv::is64bit(image.data());

    std::wcout << L"Building exports map from " << modules.size() << L" loaded module(s)...\n";
    std::map<uint64_t, ExportEntry> exportsByVa;
    build_exports_map(modules, exportsByVa);

    std::vector<ImportMatch> report;
    resolve_imports(image, is64, exportsByVa, report);

    std::wcout << L"\nImport resolution report:\n";
    for (const auto& e : report) {
        std::wcout << L"  " << (e.dllNameValid ? widen(e.requestedDll) : std::wstring(L"<erased-name>"))
                   << L" : " << e.resolvedThunks << L"/" << e.totalThunks << L" resolved\n";
        for (const auto& s : e.sampleResolved) {
            std::wcout << L"      -> " << widen(s) << L"\n";
        }
    }

    size_t rawSize = 0;
    BYTE* raw = peconv::pe_virtual_to_raw(image.data(), image.size(), target.base, rawSize, true);
    if (!raw) {
        std::wcerr << L"error: pe_virtual_to_raw failed.\n";
        CloseHandle(proc);
        return 7;
    }

    std::wstring outPath = outArg;
    if (outPath.empty()) {
        SYSTEMTIME st{};
        GetLocalTime(&st);
        wchar_t buf[64];
        swprintf_s(buf, L".\\LibPeConvDump-PID%u-%04u%02u%02u-%02u%02u%02u.exe",
            pid, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        outPath = buf;
    }

    std::vector<BYTE> rawVec(raw, raw + rawSize);

    std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
    if (out) {
        out.write(reinterpret_cast<char*>(rawVec.data()), static_cast<std::streamsize>(rawVec.size()));
    }
    out.close();

    std::string sha256hex;
    compute_sha256_hex(rawVec, sha256hex);

    peconv::free_pe_buffer(raw, rawSize);

    std::wcout << L"\nRESULT: PASS\n";
    std::wcout << L"  Out      : " << outPath << L"\n";
    std::wcout << L"  Size     : " << rawSize << L"\n";
    std::wcout << L"  SHA256   : " << widen(sha256hex) << L"\n";

    CloseHandle(proc);
    return 0;
}
