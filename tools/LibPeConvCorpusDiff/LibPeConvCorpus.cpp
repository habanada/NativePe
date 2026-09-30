#include <Windows.h>
#include <bcrypt.h>

#include <peconv.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

struct Result
{
    std::string file;
    std::string sha256;
    std::string outcome = "FAIL";
    std::string stage = "worker";
    std::string message;
    uint64_t fileSize = 0;
    std::string architecture;
    uint64_t imageBase = 0;
    uint32_t entryPoint = 0;
    size_t sections = 0;
    size_t directories = 0;

    bool mapOk = false;
    uint64_t virtualSize = 0;

    bool importsPresent = false;
    bool importsValid = false;
    bool importsParsed = false;
    size_t imports = 0;

    bool delayImportsPresent = false;
    bool delayImportsValid = false;
    size_t delayImports = 0;

    bool exportsPresent = false;
    bool exportsParsed = false;
    size_t exports = 0;

    bool tlsPresent = false;
    bool tlsParsed = false;
    size_t tlsCallbacks = 0;
    size_t tlsCallbacksValid = 0;
    size_t tlsCallbacksInvalid = 0;
    std::string tlsCallbackDigest;
    std::string tlsCallbackPreview;
    bool tlsCallbackTruncated = false;
    std::string tlsCallbackFirstValidRva;
    std::string tlsCallbackLastValidRva;
    std::string tlsIndexRva;
    std::string tlsRawData;

    bool resourcesPresent = false;
    bool resourcesParsed = false;
    size_t resources = 0;

    bool relocsPresent = false;
    bool relocsValid = false;
    size_t relocFields = 0;

    bool exceptionsPresent = false;
    bool exceptionsParsed = false;
    size_t exceptions = 0;
    std::string exceptionsDigest;

    bool loadConfigPresent = false;
    bool loadConfigParsed = false;
    int loadConfigVersion = 0;
    uint32_t loadConfigSize = 0;
    std::string securityCookieRva;

    bool isDotNet = false;

    bool unmapOk = false;
    uint64_t rawOutputSize = 0;
    bool roundTripChecked = false;
    bool roundTripEqual = false;
    int64_t firstDiff = -1;

    uint64_t libraryElapsedUs = 0;
    uint64_t coreElapsedUs = 0;
    uint64_t workerElapsedUs = 0;
    uint64_t wallElapsedUs = 0;
    uint64_t elapsedMs = 0;
    uint32_t processExitCode = 0;
};

static size_t g_resourceCount = 0;

static bool resource_counter(
    BYTE*,
    IMAGE_RESOURCE_DIRECTORY_ENTRY*,
    IMAGE_RESOURCE_DATA_ENTRY*)
{
    ++g_resourceCount;
    return true;
}

static std::string sanitize_field(std::string s)
{
    for (char& c : s) {
        if (c == '\t' || c == '\r' || c == '\n') c = ' ';
    }
    return s;
}

static std::string json_escape(const std::string& s)
{
    std::ostringstream out;
    for (unsigned char c : s) {
        switch (c) {
        case '\\': out << "\\\\"; break;
        case '"': out << "\\\""; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20) {
                out << "\\u"
                    << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<unsigned>(c)
                    << std::dec << std::setfill(' ');
            } else {
                out << c;
            }
        }
    }
    return out.str();
}

static std::string csv_escape(const std::string& s)
{
    bool quote = false;
    for (char c : s) {
        if (c == ',' || c == '"' || c == '\r' || c == '\n') {
            quote = true;
            break;
        }
    }
    if (!quote) return s;

    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += '"';
    return out;
}

static std::string hex64(uint64_t v)
{
    std::ostringstream out;
    out << "0x" << std::uppercase << std::hex
        << std::setw(16) << std::setfill('0') << v;
    return out.str();
}

static std::string hex32(uint32_t v)
{
    std::ostringstream out;
    out << "0x" << std::uppercase << std::hex
        << std::setw(8) << std::setfill('0') << v;
    return out.str();
}

static std::string narrow_path(const fs::path& p)
{
    return p.u8string();
}

static const char* build_configuration()
{
#ifdef CORPUS_RELEASE_BUILD
    return "Release";
#elif defined(_DEBUG)
    return "Debug";
#else
    return "Other";
#endif
}

static bool build_optimized()
{
#ifdef CORPUS_RELEASE_BUILD
    return true;
#else
    return false;
#endif
}

static void append_message(Result& r, const std::string& text)
{
    if (text.empty()) return;
    if (!r.message.empty()) r.message += " | ";
    r.message += text;
}

static void mark_reject(Result& r, const std::string& stage, const std::string& message)
{
    if (r.outcome == "PASS") {
        r.outcome = "REJECT";
        r.stage = stage;
        r.message = message;
    } else if (r.outcome == "REJECT") {
        append_message(r, stage + ": " + message);
    }
}

static fs::path stage_path(const fs::path& resultPath)
{
    return fs::path(resultPath.wstring() + L".stage");
}

static void write_stage_marker(const fs::path& resultPath, const std::string& stage)
{
    std::ofstream out(stage_path(resultPath), std::ios::binary | std::ios::trunc);
    if (out) out << stage;
}

static std::string read_stage_marker(const fs::path& resultPath)
{
    std::ifstream in(stage_path(resultPath), std::ios::binary);
    if (!in) return {};
    std::string stage;
    std::getline(in, stage);
    return stage;
}

static uint64_t elapsed_us(const std::chrono::steady_clock::time_point& started)
{
    const auto value = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started).count());
    return value == 0 ? 1 : value;
}

static bool read_file(const fs::path& path, std::vector<BYTE>& data, std::string& error)
{
    std::error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec) {
        error = "file_size failed";
        return false;
    }
    if (size > static_cast<uint64_t>(SIZE_MAX)) {
        error = "file too large for process address space";
        return false;
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "open failed";
        return false;
    }

    data.resize(static_cast<size_t>(size));
    if (!data.empty()) {
        in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!in) {
            error = "read failed";
            return false;
        }
    }
    return true;
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

static bool is_mz(const std::vector<BYTE>& data)
{
    if (data.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
    return dos->e_magic == IMAGE_DOS_SIGNATURE;
}

struct Layout
{
    uint32_t sizeOfHeaders = 0;
    std::vector<IMAGE_SECTION_HEADER> sections;
};

static bool parse_layout(const std::vector<BYTE>& data, Layout& layout)
{
    if (data.size() < sizeof(IMAGE_DOS_HEADER)) return false;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) return false;

    const size_t ntOff = static_cast<size_t>(dos->e_lfanew);
    const size_t fixedSize = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (ntOff > data.size() || fixedSize > data.size() - ntOff) return false;

    const BYTE* nt = data.data() + ntOff;
    if (*reinterpret_cast<const DWORD*>(nt) != IMAGE_NT_SIGNATURE) return false;

    const auto* fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(nt + sizeof(DWORD));
    const size_t optOff = ntOff + fixedSize;
    if (optOff > data.size() ||
        static_cast<size_t>(fh->SizeOfOptionalHeader) > data.size() - optOff) {
        return false;
    }

    if (fh->SizeOfOptionalHeader < sizeof(WORD)) return false;
    const BYTE* opt = data.data() + optOff;
    const WORD magic = *reinterpret_cast<const WORD*>(opt);

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (fh->SizeOfOptionalHeader <
            offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfHeaders) + sizeof(DWORD)) {
            return false;
        }
        const auto* oh = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(opt);
        layout.sizeOfHeaders = oh->SizeOfHeaders;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (fh->SizeOfOptionalHeader <
            offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders) + sizeof(DWORD)) {
            return false;
        }
        const auto* oh = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(opt);
        layout.sizeOfHeaders = oh->SizeOfHeaders;
    } else {
        return false;
    }

    const size_t secOff = optOff + fh->SizeOfOptionalHeader;
    const size_t secBytes =
        static_cast<size_t>(fh->NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);

    if (secOff > data.size() || secBytes > data.size() - secOff) return false;

    layout.sections.resize(fh->NumberOfSections);
    if (secBytes != 0) {
        memcpy(layout.sections.data(), data.data() + secOff, secBytes);
    }
    return true;
}

static bool range_within(size_t totalSize, uint64_t offset, uint64_t fieldSize)
{
    if (offset > totalSize) return false;
    return fieldSize <= static_cast<uint64_t>(totalSize) - offset;
}

static bool compare_roundtrip(
    const std::vector<BYTE>& original,
    const BYTE* output,
    size_t outputSize,
    Result& r,
    std::string& detail)
{
    Layout layout;
    detail.clear();
    r.roundTripChecked = true;
    r.roundTripEqual = false;
    r.firstDiff = -1;

    if (!parse_layout(original, layout)) {
        r.roundTripChecked = false;
        detail = "original layout unavailable during roundtrip compare";
        return false;
    }

    size_t headerSize = layout.sizeOfHeaders;
    if (headerSize == 0) {
        size_t firstRaw = 0;
        for (const auto& sec : layout.sections) {
            if (sec.PointerToRawData != 0 &&
                (firstRaw == 0 || sec.PointerToRawData < firstRaw)) {
                firstRaw = sec.PointerToRawData;
            }
        }
        headerSize = firstRaw;
    }

    if (headerSize != 0) {
        if (!range_within(original.size(), 0, headerSize)) {
            detail = "original header range is invalid";
            return false;
        }
        if (!range_within(outputSize, 0, headerSize)) {
            std::ostringstream msg;
            msg << "roundtrip header range missing: need=" << hex64(headerSize)
                << " have=" << hex64(outputSize);
            detail = msg.str();
            return false;
        }
        for (size_t i = 0; i < headerSize; ++i) {
            if (original[i] != output[i]) {
                r.firstDiff = static_cast<int64_t>(i);
                std::ostringstream msg;
                msg << "header bytes differ at raw offset " << hex64(i);
                detail = msg.str();
                return false;
            }
        }
    }

    for (size_t i = 0; i < layout.sections.size(); ++i) {
        const auto& sec = layout.sections[i];
        const uint64_t off = sec.PointerToRawData;
        const uint64_t len = sec.SizeOfRawData;
        if (len == 0) continue;
        if (!range_within(original.size(), off, len)) {
            std::ostringstream msg;
            msg << "original section " << i << " raw range invalid";
            detail = msg.str();
            return false;
        }
        if (!range_within(outputSize, off, len)) {
            std::ostringstream msg;
            msg << "roundtrip section " << i << " raw range missing: offset="
                << hex64(off) << " size=" << hex64(len) << " output=" << hex64(outputSize);
            detail = msg.str();
            return false;
        }
        for (uint64_t j = 0; j < len; ++j) {
            if (original[static_cast<size_t>(off + j)] != output[static_cast<size_t>(off + j)]) {
                r.firstDiff = static_cast<int64_t>(off + j);
                std::ostringstream msg;
                msg << "section " << i << " bytes differ at raw offset " << hex64(off + j);
                detail = msg.str();
                return false;
            }
        }
    }

    r.roundTripEqual = true;
    return true;
}

static size_t count_directories(BYTE* module)
{
    size_t count = 0;
    for (DWORD i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
        if (peconv::get_directory_entry(module, i) != nullptr) {
            ++count;
        }
    }
    return count;
}

static bool count_delay_imports(
    BYTE* module,
    size_t moduleSize,
    IMAGE_DELAYLOAD_DESCRIPTOR* first,
    size_t dirSize,
    size_t& count)
{
    count = 0;
    if (!first) return false;

    const size_t maxCount = dirSize / sizeof(IMAGE_DELAYLOAD_DESCRIPTOR);
    const ULONGLONG imageBase = peconv::get_image_base(module);

    for (size_t i = 0; i < maxCount; ++i) {
        IMAGE_DELAYLOAD_DESCRIPTOR* desc = &first[i];

        if (!peconv::validate_ptr(
            module,
            moduleSize,
            desc,
            sizeof(IMAGE_DELAYLOAD_DESCRIPTOR))) {
            return false;
        }

        if (desc->DllNameRVA == 0) {
            return true;
        }

        ULONGLONG nameRva = desc->DllNameRVA;
        if (nameRva > imageBase) {
            nameRva -= imageBase;
        }

        if (nameRva >= moduleSize) {
            return false;
        }

        LPSTR libName = reinterpret_cast<LPSTR>(module + static_cast<size_t>(nameRva));
        if (!peconv::is_valid_string(module, moduleSize, libName)) {
            return false;
        }

        ++count;
    }

    return maxCount == 0;
}

static bool address_to_rva(BYTE* mapped, size_t virtualSize, ULONGLONG address, DWORD& rva)
{
    rva = 0;
    if (address == 0) return true;
    const ULONGLONG imageBase = peconv::get_image_base(mapped);
    if (address >= imageBase) {
        const ULONGLONG delta = address - imageBase;
        if (delta < virtualSize && delta <= MAXDWORD) {
            rva = static_cast<DWORD>(delta);
            return true;
        }
    }
    const ULONGLONG mappedBase = reinterpret_cast<ULONGLONG>(mapped);
    if (address >= mappedBase) {
        const ULONGLONG delta = address - mappedBase;
        if (delta < virtualSize && delta <= MAXDWORD) {
            rva = static_cast<DWORD>(delta);
            return true;
        }
    }
    if (address < virtualSize && address <= MAXDWORD) {
        rva = static_cast<DWORD>(address);
        return true;
    }
    return false;
}

static std::string address_to_rva_text(BYTE* mapped, size_t virtualSize, ULONGLONG address)
{
    DWORD rva = 0;
    return address_to_rva(mapped, virtualSize, address, rva) ? hex32(rva) : "INVALID";
}

static void update_tls_digest_byte(uint64_t& hashA, uint64_t& hashB, BYTE value)
{
    hashA = ((hashA << 5) | (hashA >> 59)) ^ value;
    hashB = ((hashB << 13) | (hashB >> 51)) ^ (static_cast<uint64_t>(value) << 32) ^ value;
}

static void update_tls_digest_token(uint64_t& hashA, uint64_t& hashB, bool valid, DWORD rva)
{
    update_tls_digest_byte(hashA, hashB, valid ? 1 : 0);
    update_tls_digest_byte(hashA, hashB, static_cast<BYTE>(rva));
    update_tls_digest_byte(hashA, hashB, static_cast<BYTE>(rva >> 8));
    update_tls_digest_byte(hashA, hashB, static_cast<BYTE>(rva >> 16));
    update_tls_digest_byte(hashA, hashB, static_cast<BYTE>(rva >> 24));
}

static bool read_tls_details(BYTE* mapped, size_t virtualSize, const std::vector<ULONGLONG>& callbacks, Result& r)
{
    constexpr size_t previewLimit = 64;
    IMAGE_DATA_DIRECTORY* dir = peconv::get_directory_entry(mapped, IMAGE_DIRECTORY_ENTRY_TLS);
    if (!dir) return true;

    ULONGLONG startAddress = 0, endAddress = 0, indexAddress = 0;
    if (peconv::is64bit(mapped)) {
        auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(mapped + dir->VirtualAddress);
        if (!peconv::validate_ptr(mapped, virtualSize, tls, sizeof(*tls))) return false;
        startAddress = tls->StartAddressOfRawData;
        endAddress = tls->EndAddressOfRawData;
        indexAddress = tls->AddressOfIndex;
    } else {
        auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY32*>(mapped + dir->VirtualAddress);
        if (!peconv::validate_ptr(mapped, virtualSize, tls, sizeof(*tls))) return false;
        startAddress = tls->StartAddressOfRawData;
        endAddress = tls->EndAddressOfRawData;
        indexAddress = tls->AddressOfIndex;
    }

    r.tlsIndexRva = address_to_rva_text(mapped, virtualSize, indexAddress);
    r.tlsRawData = address_to_rva_text(mapped, virtualSize, startAddress) + "-" + address_to_rva_text(mapped, virtualSize, endAddress);

    uint64_t hashA = 0xCBF29CE484222325ULL;
    uint64_t hashB = 0x6A09E667F3BCC909ULL;
    bool hasValid = false;
    DWORD firstValid = 0, lastValid = 0;
    std::ostringstream preview;
    for (size_t i = 0; i < callbacks.size(); ++i) {
        DWORD rva = 0;
        const bool valid = address_to_rva(mapped, virtualSize, callbacks[i], rva);
        if (valid) {
            ++r.tlsCallbacksValid;
            if (!hasValid) {
                firstValid = rva;
                hasValid = true;
            }
            lastValid = rva;
        } else {
            ++r.tlsCallbacksInvalid;
            rva = 0;
        }
        update_tls_digest_token(hashA, hashB, valid, rva);
        if (i < previewLimit) {
            if (i != 0) preview << ';';
            if (valid) preview << hex32(rva);
            else preview << "INVALID";
        }
    }
    r.tlsCallbackPreview = preview.str();
    r.tlsCallbackDigest = hex64(hashA).substr(2) + hex64(hashB).substr(2);
    r.tlsCallbackTruncated = callbacks.size() > previewLimit;
    if (hasValid) {
        r.tlsCallbackFirstValidRva = hex32(firstValid);
        r.tlsCallbackLastValidRva = hex32(lastValid);
    }
    return true;
}

struct CorpusRuntimeFunction
{
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindInfoAddress;
};

static bool read_exception_details(BYTE* mapped, size_t virtualSize, Result& r)
{
    IMAGE_DATA_DIRECTORY* dir = peconv::get_directory_entry(mapped, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    if (!dir) return true;
    if (dir->Size == 0 || (dir->Size % sizeof(CorpusRuntimeFunction)) != 0) return false;
    auto* entries = reinterpret_cast<CorpusRuntimeFunction*>(mapped + dir->VirtualAddress);
    if (!peconv::validate_ptr(mapped, virtualSize, entries, dir->Size)) return false;

    r.exceptions = dir->Size / sizeof(CorpusRuntimeFunction);
    uint64_t hash = 0xCBF29CE484222325ULL;
    const BYTE* data = reinterpret_cast<const BYTE*>(entries);
    for (size_t i = 0; i < dir->Size; ++i) hash = ((hash << 5) | (hash >> 59)) ^ data[i];
    std::ostringstream digest;
    digest << std::uppercase << std::hex << std::setw(16) << std::setfill('0') << hash;
    r.exceptionsDigest = digest.str();
    return true;
}

static void read_load_config_details(BYTE* mapped, size_t virtualSize, Result& r)
{
    r.loadConfigPresent = peconv::get_directory_entry(mapped, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) != nullptr;
    if (!r.loadConfigPresent) return;
    BYTE* ptr = peconv::get_load_config_ptr(mapped, virtualSize);
    if (!ptr) return;

    r.loadConfigParsed = true;
    r.loadConfigVersion = static_cast<int>(peconv::get_load_config_version(mapped, virtualSize, ptr));
    if (peconv::validate_ptr(mapped, virtualSize, ptr, sizeof(DWORD))) r.loadConfigSize = *reinterpret_cast<DWORD*>(ptr);

    ULONGLONG cookie = 0;
    if (peconv::is64bit(mapped)) {
        auto* cfg = reinterpret_cast<IMAGE_LOAD_CONFIG_DIRECTORY64*>(ptr);
        if (peconv::validate_ptr(mapped, virtualSize, cfg, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie) + sizeof(cfg->SecurityCookie))) cookie = cfg->SecurityCookie;
    } else {
        auto* cfg = reinterpret_cast<IMAGE_LOAD_CONFIG_DIRECTORY32*>(ptr);
        if (peconv::validate_ptr(mapped, virtualSize, cfg, offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SecurityCookie) + sizeof(cfg->SecurityCookie))) cookie = cfg->SecurityCookie;
    }
    r.securityCookieRva = address_to_rva_text(mapped, virtualSize, cookie);
}

class CountRelocCallback : public peconv::RelocBlockCallback
{
public:
    explicit CountRelocCallback(bool is64bit) : RelocBlockCallback(is64bit) {}
    bool processRelocField(ULONG_PTR) override { ++count; return true; }
    size_t count = 0;
};

static void inspect_features(BYTE* mapped, size_t virtualSize, Result& r, const fs::path& resultPath)
{
    write_stage_marker(resultPath, "directories");
    r.directories = count_directories(mapped);
    r.isDotNet = peconv::is_dot_net(mapped, virtualSize);

    write_stage_marker(resultPath, "imports");
    r.importsPresent =
        peconv::get_directory_entry(mapped, IMAGE_DIRECTORY_ENTRY_IMPORT) != nullptr;

    if (r.importsPresent) {
        r.importsValid = peconv::has_valid_import_table(mapped, virtualSize);
        if (r.importsValid) {
            peconv::ImportsCollection collection;
            r.importsParsed = peconv::collect_imports(
                mapped,
                virtualSize,
                collection);
            if (r.importsParsed) {
                r.imports = collection.size();
            } else {
                mark_reject(r, "imports", "CollectImports returned false");
            }
        } else {
            mark_reject(r, "imports", "import directory is present but malformed");
        }
    }

    write_stage_marker(resultPath, "delay-imports");
    r.delayImportsPresent =
        peconv::get_directory_entry(mapped, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) != nullptr;

    if (r.delayImportsPresent) {
        size_t dirSize = 0;
        IMAGE_DELAYLOAD_DESCRIPTOR* delayed =
            peconv::get_delayed_imps(mapped, virtualSize, dirSize);

        if (delayed != nullptr) {
            r.delayImportsValid =
                count_delay_imports(
                    mapped,
                    virtualSize,
                    delayed,
                    dirSize,
                    r.delayImports);

            if (!r.delayImportsValid) {
                mark_reject(r, "delay-imports", "delay import directory is present but invalid");
            }
        } else {
            mark_reject(r, "delay-imports", "delay import directory is present but invalid");
        }
    }

    write_stage_marker(resultPath, "exports");
    r.exportsPresent =
        peconv::get_directory_entry(mapped, IMAGE_DIRECTORY_ENTRY_EXPORT) != nullptr;

    if (r.exportsPresent) {
        std::vector<std::string> names;
        r.exports = peconv::get_exported_names(mapped, names);
        r.exportsParsed = true;
    }

    write_stage_marker(resultPath, "tls");
    r.tlsPresent =
        peconv::get_directory_entry(mapped, IMAGE_DIRECTORY_ENTRY_TLS) != nullptr;

    if (r.tlsPresent) {
        std::vector<ULONGLONG> callbacks;
        r.tlsCallbacks =
            peconv::list_tls_callbacks(
                mapped,
                virtualSize,
                callbacks,
                nullptr);
        r.tlsParsed = read_tls_details(mapped, virtualSize, callbacks, r);
        if (!r.tlsParsed) mark_reject(r, "tls", "tls directory is present but malformed");
    }

    write_stage_marker(resultPath, "exceptions");
    r.exceptionsPresent = peconv::get_directory_entry(mapped, IMAGE_DIRECTORY_ENTRY_EXCEPTION) != nullptr;
    if (r.exceptionsPresent) {
        r.exceptionsParsed = read_exception_details(mapped, virtualSize, r);
        if (!r.exceptionsParsed) mark_reject(r, "exceptions", "exception directory is present but malformed");
    }

    write_stage_marker(resultPath, "load-config");
    read_load_config_details(mapped, virtualSize, r);
    if (r.loadConfigPresent && !r.loadConfigParsed) mark_reject(r, "load-config", "load config directory is present but malformed");

    write_stage_marker(resultPath, "resources");
    r.resourcesPresent =
        peconv::get_directory_entry(mapped, IMAGE_DIRECTORY_ENTRY_RESOURCE) != nullptr;

    if (r.resourcesPresent) {
        g_resourceCount = 0;
        r.resourcesParsed =
            peconv::parse_resources(mapped, resource_counter);
        r.resources = g_resourceCount;

        if (!r.resourcesParsed) {
            mark_reject(r, "resources", "resource directory is present but parsing failed");
        }
    }

    write_stage_marker(resultPath, "relocations");
    r.relocsPresent =
        peconv::get_directory_entry(mapped, IMAGE_DIRECTORY_ENTRY_BASERELOC) != nullptr;

    if (r.relocsPresent) {
        r.relocsValid =
            peconv::has_valid_relocation_table(mapped, virtualSize);

        if (r.relocsValid) {
            CountRelocCallback counter(peconv::is64bit(mapped));
            if (peconv::process_relocation_table(mapped, virtualSize, &counter)) r.relocFields = counter.count;
        }

        if (!r.relocsValid) {
            mark_reject(r, "relocations", "relocation directory is present but malformed");
        }
    }
}

static void write_worker_result(const fs::path& path, const Result& r)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out
        << sanitize_field(r.outcome) << '\t'
        << sanitize_field(r.stage) << '\t'
        << sanitize_field(r.message) << '\t'
        << r.fileSize << '\t'
        << sanitize_field(r.architecture) << '\t'
        << r.imageBase << '\t'
        << r.entryPoint << '\t'
        << r.sections << '\t'
        << r.directories << '\t'
        << (r.mapOk ? 1 : 0) << '\t'
        << r.virtualSize << '\t'
        << (r.importsPresent ? 1 : 0) << '\t'
        << (r.importsValid ? 1 : 0) << '\t'
        << (r.importsParsed ? 1 : 0) << '\t'
        << r.imports << '\t'
        << (r.delayImportsPresent ? 1 : 0) << '\t'
        << (r.delayImportsValid ? 1 : 0) << '\t'
        << r.delayImports << '\t'
        << (r.exportsPresent ? 1 : 0) << '\t'
        << (r.exportsParsed ? 1 : 0) << '\t'
        << r.exports << '\t'
        << (r.tlsPresent ? 1 : 0) << '\t'
        << (r.tlsParsed ? 1 : 0) << '\t'
        << r.tlsCallbacks << '\t'
        << (r.resourcesPresent ? 1 : 0) << '\t'
        << (r.resourcesParsed ? 1 : 0) << '\t'
        << r.resources << '\t'
        << (r.relocsPresent ? 1 : 0) << '\t'
        << (r.relocsValid ? 1 : 0) << '\t'
        << (r.isDotNet ? 1 : 0) << '\t'
        << (r.unmapOk ? 1 : 0) << '\t'
        << r.rawOutputSize << '\t'
        << (r.roundTripChecked ? 1 : 0) << '\t'
        << (r.roundTripEqual ? 1 : 0) << '\t'
        << r.firstDiff << '\t'
        << r.libraryElapsedUs << '\t'
        << r.coreElapsedUs << '\t'
        << r.workerElapsedUs << '\t'
        << r.elapsedMs << '\t'
        << sanitize_field(r.sha256) << '\t'
        << sanitize_field(r.tlsCallbackPreview) << '\t'
        << sanitize_field(r.tlsIndexRva) << '\t'
        << sanitize_field(r.tlsRawData) << '\t'
        << r.relocFields << '\t'
        << (r.exceptionsPresent ? 1 : 0) << '\t'
        << (r.exceptionsParsed ? 1 : 0) << '\t'
        << r.exceptions << '\t'
        << sanitize_field(r.exceptionsDigest) << '\t'
        << (r.loadConfigPresent ? 1 : 0) << '\t'
        << (r.loadConfigParsed ? 1 : 0) << '\t'
        << r.loadConfigVersion << '\t'
        << r.loadConfigSize << '\t'
        << sanitize_field(r.securityCookieRva) << '\t'
        << r.tlsCallbacksValid << '\t'
        << r.tlsCallbacksInvalid << '\t'
        << sanitize_field(r.tlsCallbackDigest) << '\t'
        << (r.tlsCallbackTruncated ? 1 : 0) << '\t'
        << sanitize_field(r.tlsCallbackFirstValidRva) << '\t'
        << sanitize_field(r.tlsCallbackLastValidRva);
}

static bool parse_u64(const std::string& s, uint64_t& v)
{
    try {
        v = std::stoull(s);
        return true;
    } catch (...) {
        return false;
    }
}

static bool parse_i64(const std::string& s, int64_t& v)
{
    try {
        v = std::stoll(s);
        return true;
    } catch (...) {
        return false;
    }
}

static bool read_worker_result(const fs::path& path, Result& r)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;

    std::string line;
    std::getline(in, line);
    std::vector<std::string> f;

    size_t start = 0;
    while (true) {
        const size_t pos = line.find('\t', start);
        if (pos == std::string::npos) {
            f.push_back(line.substr(start));
            break;
        }
        f.push_back(line.substr(start, pos - start));
        start = pos + 1;
    }

    if (f.size() != 59) return false;

    uint64_t u = 0;
    int64_t si = 0;

    r.outcome = f[0];
    r.stage = f[1];
    r.message = f[2];

    if (!parse_u64(f[3], r.fileSize)) return false;
    r.architecture = f[4];
    if (!parse_u64(f[5], r.imageBase)) return false;
    if (!parse_u64(f[6], u)) return false;
    r.entryPoint = static_cast<uint32_t>(u);
    if (!parse_u64(f[7], u)) return false;
    r.sections = static_cast<size_t>(u);
    if (!parse_u64(f[8], u)) return false;
    r.directories = static_cast<size_t>(u);

    r.mapOk = f[9] == "1";
    if (!parse_u64(f[10], r.virtualSize)) return false;

    r.importsPresent = f[11] == "1";
    r.importsValid = f[12] == "1";
    r.importsParsed = f[13] == "1";
    if (!parse_u64(f[14], u)) return false;
    r.imports = static_cast<size_t>(u);

    r.delayImportsPresent = f[15] == "1";
    r.delayImportsValid = f[16] == "1";
    if (!parse_u64(f[17], u)) return false;
    r.delayImports = static_cast<size_t>(u);

    r.exportsPresent = f[18] == "1";
    r.exportsParsed = f[19] == "1";
    if (!parse_u64(f[20], u)) return false;
    r.exports = static_cast<size_t>(u);

    r.tlsPresent = f[21] == "1";
    r.tlsParsed = f[22] == "1";
    if (!parse_u64(f[23], u)) return false;
    r.tlsCallbacks = static_cast<size_t>(u);

    r.resourcesPresent = f[24] == "1";
    r.resourcesParsed = f[25] == "1";
    if (!parse_u64(f[26], u)) return false;
    r.resources = static_cast<size_t>(u);

    r.relocsPresent = f[27] == "1";
    r.relocsValid = f[28] == "1";
    r.isDotNet = f[29] == "1";

    r.unmapOk = f[30] == "1";
    if (!parse_u64(f[31], r.rawOutputSize)) return false;

    r.roundTripChecked = f[32] == "1";
    r.roundTripEqual = f[33] == "1";
    if (!parse_i64(f[34], si)) return false;
    r.firstDiff = si;
    if (!parse_u64(f[35], r.libraryElapsedUs)) return false;
    if (!parse_u64(f[36], r.coreElapsedUs)) return false;
    if (!parse_u64(f[37], r.workerElapsedUs)) return false;
    if (!parse_u64(f[38], r.elapsedMs)) return false;
    r.sha256 = f[39];
    r.tlsCallbackPreview = f[40];
    r.tlsIndexRva = f[41];
    r.tlsRawData = f[42];
    if (!parse_u64(f[43], u)) return false;
    r.relocFields = static_cast<size_t>(u);
    r.exceptionsPresent = f[44] == "1";
    r.exceptionsParsed = f[45] == "1";
    if (!parse_u64(f[46], u)) return false;
    r.exceptions = static_cast<size_t>(u);
    r.exceptionsDigest = f[47];
    r.loadConfigPresent = f[48] == "1";
    r.loadConfigParsed = f[49] == "1";
    try { r.loadConfigVersion = std::stoi(f[50]); } catch (...) { return false; }
    if (!parse_u64(f[51], u)) return false;
    r.loadConfigSize = static_cast<uint32_t>(u);
    r.securityCookieRva = f[52];
    if (!parse_u64(f[53], u)) return false;
    r.tlsCallbacksValid = static_cast<size_t>(u);
    if (!parse_u64(f[54], u)) return false;
    r.tlsCallbacksInvalid = static_cast<size_t>(u);
    r.tlsCallbackDigest = f[55];
    r.tlsCallbackTruncated = f[56] == "1";
    r.tlsCallbackFirstValidRva = f[57];
    r.tlsCallbackLastValidRva = f[58];

    return true;
}

static int worker_main(const fs::path& file, const fs::path& resultPath)
{
    Result r;
    const auto workerStarted = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point coreStarted{};
    std::chrono::steady_clock::time_point libraryStarted{};
    bool coreTiming = false;
    bool libraryTiming = false;
    std::vector<BYTE> raw;
    std::string error;

    try {
        write_stage_marker(resultPath, "load");
        if (!read_file(file, raw, error)) {
            r.outcome = "FAIL";
            r.stage = "load";
            r.message = error;
        } else {
            r.fileSize = raw.size();
            if (!compute_sha256_hex(raw, r.sha256)) {
                r.sha256.clear();
            }
            coreStarted = std::chrono::steady_clock::now();
            coreTiming = true;

            write_stage_marker(resultPath, "identify");
            if (!is_mz(raw)) {
                r.outcome = "SKIP";
                r.stage = "identify";
                r.message = "not an MZ image";
            } else {
                r.outcome = "PASS";
                r.stage = "map";
                write_stage_marker(resultPath, "map");
                libraryStarted = std::chrono::steady_clock::now();
                libraryTiming = true;

                size_t virtualSize = 0;
                BYTE* mapped = peconv::load_pe_module(
                    raw.data(), raw.size(), virtualSize, false, false);
                r.virtualSize = virtualSize;

                if (!mapped) {
                    r.libraryElapsedUs = elapsed_us(libraryStarted);
                    mark_reject(r, "map", "load_pe_module returned null");
                } else {
                    r.mapOk = true;

                    write_stage_marker(resultPath, "metadata");
                    r.architecture = peconv::is64bit(mapped) ? "PE64" : "PE32";
                    r.imageBase = static_cast<uint64_t>(peconv::get_image_base(mapped));
                    r.entryPoint = peconv::get_entry_point_rva(mapped);
                    r.sections = peconv::get_sections_count(mapped, virtualSize);

                    inspect_features(mapped, virtualSize, r, resultPath);

                    write_stage_marker(resultPath, "roundtrip");
                    const ULONGLONG imageBase = peconv::get_image_base(mapped);
                    size_t rawOutputSize = 0;
                    r.roundTripChecked = true;
                    BYTE* unmapped = peconv::pe_virtual_to_raw(
                        mapped,
                        virtualSize,
                        imageBase,
                        rawOutputSize,
                        true);

                    r.rawOutputSize = rawOutputSize;
                    r.libraryElapsedUs = elapsed_us(libraryStarted);

                    if (!unmapped) {
                        mark_reject(r, "roundtrip", "pe_virtual_to_raw returned null");
                        r.roundTripEqual = false;
                    } else {
                        r.unmapOk = true;
                        write_stage_marker(resultPath, "roundtrip-compare");
                        std::string roundTripDetail;
                        if (!compare_roundtrip(raw, unmapped, rawOutputSize, r, roundTripDetail)) {
                            if (!r.roundTripChecked) {
                                append_message(r, "roundtrip comparison unavailable: " + roundTripDetail);
                            } else {
                                const bool rejectRoundTrip =
                                    r.outcome == "REJECT" ||
                                    roundTripDetail.find("range missing:") != std::string::npos ||
                                    roundTripDetail == "original header range is invalid" ||
                                    (roundTripDetail.rfind("original section ", 0) == 0 &&
                                     roundTripDetail.find(" raw range invalid") != std::string::npos);

                                if (rejectRoundTrip) {
                                    mark_reject(r, "roundtrip", roundTripDetail);
                                } else {
                                    r.outcome = "FAIL";
                                    r.stage = "roundtrip";
                                    r.message = roundTripDetail;
                                }
                            }
                        }
                        write_stage_marker(resultPath, "free-roundtrip");
                        peconv::free_pe_buffer(unmapped, rawOutputSize);
                    }

                    write_stage_marker(resultPath, "free-map");
                    peconv::free_pe_buffer(mapped, virtualSize);
                }

                if (r.outcome == "PASS") {
                    r.stage = "complete";
                    if (r.message.empty()) {
                        r.message = "all library stages passed";
                    } else {
                        r.message = "all library stages passed | " + r.message;
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        r.outcome = "FAIL";
        r.stage = read_stage_marker(resultPath);
        if (r.stage.empty()) r.stage = "exception";
        r.message = e.what();
    }

    if (libraryTiming && r.libraryElapsedUs == 0) {
        r.libraryElapsedUs = elapsed_us(libraryStarted);
    }
    if (coreTiming) {
        r.coreElapsedUs = elapsed_us(coreStarted);
    }
    std::vector<BYTE>().swap(raw);
    r.workerElapsedUs = elapsed_us(workerStarted);
    r.elapsedMs = r.workerElapsedUs / 1000;

    write_worker_result(resultPath, r);
    return 0;
}

static std::wstring quote_arg(const std::wstring& s)
{
    return L"\"" + s + L"\"";
}

static fs::path executable_path()
{
    std::vector<wchar_t> buf(32768);
    const DWORD n = GetModuleFileNameW(
        nullptr,
        buf.data(),
        static_cast<DWORD>(buf.size()));

    if (n == 0 || n >= buf.size()) return {};
    return fs::path(std::wstring(buf.data(), n));
}

static std::string make_timestamp()
{
    SYSTEMTIME st{};
    GetLocalTime(&st);

    char buf[64]{};
    std::snprintf(
        buf,
        sizeof(buf),
        "%04u%02u%02u-%02u%02u%02u-%03u",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond,
        st.wMilliseconds);

    return buf;
}

static bool equal_ci(const std::wstring& a, const std::wstring& b)
{
    return _wcsicmp(a.c_str(), b.c_str()) == 0;
}

static bool is_allowed_relative(
    const fs::path& relative,
    const std::vector<std::wstring>& includeRoots)
{
    if (relative.empty()) return false;
    const auto it = relative.begin();
    if (it == relative.end()) return false;

    const std::wstring first = it->wstring();
    for (const auto& allowed : includeRoots) {
        if (equal_ci(first, allowed)) {
            return true;
        }
    }
    return false;
}

static void enumerate_files(const fs::path& root, std::vector<fs::path>& files)
{
    std::error_code ec;
    fs::recursive_directory_iterator it(
        root,
        fs::directory_options::skip_permission_denied,
        ec);
    const fs::recursive_directory_iterator end;

    while (!ec && it != end) {
        const fs::directory_entry entry = *it;
        const fs::path name = entry.path().filename();

        if (entry.is_directory(ec)) {
            const std::wstring n = name.wstring();
            if (!n.empty() && n[0] == L'.') {
                it.disable_recursion_pending();
            } else if (entry.is_symlink(ec)) {
                it.disable_recursion_pending();
            }
        } else if (entry.is_regular_file(ec)) {
            files.push_back(entry.path());
        }

        it.increment(ec);
        if (ec) ec.clear();
    }
}

static bool load_list(
    const fs::path& root,
    const fs::path& listPath,
    const std::vector<std::wstring>& includeRoots,
    std::vector<fs::path>& files)
{
    std::ifstream in(listPath, std::ios::binary);
    if (!in) return false;

    std::set<std::string> seen;
    std::string line;
    bool firstLine = true;

    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();

        if (firstLine) {
            firstLine = false;
            if (line.size() >= 3 &&
                static_cast<unsigned char>(line[0]) == 0xEF &&
                static_cast<unsigned char>(line[1]) == 0xBB &&
                static_cast<unsigned char>(line[2]) == 0xBF) {
                line.erase(0, 3);
            }
        }

        if (line.empty()) continue;

        fs::path rel = fs::u8path(line);
        if (rel.is_absolute() || rel.has_root_name() || rel.has_root_directory()) {
            continue;
        }
        rel = rel.lexically_normal();
        bool hasParentTraversal = false;
        for (const auto& part : rel) {
            if (part == fs::path(L"..")) {
                hasParentTraversal = true;
                break;
            }
        }
        if (hasParentTraversal || !is_allowed_relative(rel, includeRoots)) {
            continue;
        }

        std::string key = rel.generic_u8string();
        std::transform(
            key.begin(),
            key.end(),
            key.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if (!seen.insert(key).second) {
            continue;
        }

        files.push_back(root / rel);
    }

    return true;
}

static std::string relative_name(const fs::path& root, const fs::path& file)
{
    std::error_code ec;
    fs::path rel = fs::relative(file, root, ec);
    if (ec) rel = file.filename();
    return narrow_path(rel);
}

static Result run_worker(
    const fs::path& root,
    const fs::path& file,
    const fs::path& tempPath,
    DWORD timeoutMs)
{
    Result r;
    r.file = relative_name(root, file);

    std::error_code ec;
    r.fileSize = fs::file_size(file, ec);
    if (ec) r.fileSize = 0;

    const fs::path exe = executable_path();
    std::wstring cmd =
        quote_arg(exe.wstring()) +
        L" --worker " +
        quote_arg(file.wstring()) +
        L" " +
        quote_arg(tempPath.wstring());

    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    std::vector<wchar_t> mutableCmd(cmd.begin(), cmd.end());
    mutableCmd.push_back(L'\0');

    const auto started = std::chrono::steady_clock::now();
    fs::remove(stage_path(tempPath), ec);

    if (!CreateProcessW(
        nullptr,
        mutableCmd.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi)) {
        r.outcome = "FAIL";
        r.stage = "spawn";
        r.message = "CreateProcessW failed";
        r.processExitCode = GetLastError();
        r.wallElapsedUs = elapsed_us(started);
        return r;
    }

    const DWORD wait = WaitForSingleObject(pi.hProcess, timeoutMs);

    if (wait == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 0xEE);
        WaitForSingleObject(pi.hProcess, INFINITE);

        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);

        r.outcome = "TIMEOUT";
        r.stage = read_stage_marker(tempPath);
        if (r.stage.empty()) r.stage = "worker";
        r.message = "worker exceeded timeout";
        r.processExitCode = exitCode;
        r.wallElapsedUs = elapsed_us(started);
    } else {
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        r.processExitCode = exitCode;
        const uint64_t wallElapsedUs = elapsed_us(started);

        Result worker;
        if (read_worker_result(tempPath, worker)) {
            worker.file = r.file;
            worker.processExitCode = exitCode;
            worker.wallElapsedUs = wallElapsedUs;
            r = worker;
        } else {
            r.outcome = (exitCode == 0) ? "FAIL" : "CRASH";
            r.stage = read_stage_marker(tempPath);
            if (r.stage.empty()) r.stage = "worker";
            r.message = (exitCode == 0)
                ? "worker exited without a valid result"
                : "worker terminated before writing a result";
            r.wallElapsedUs = wallElapsedUs;
        }
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    fs::remove(tempPath, ec);
    fs::remove(stage_path(tempPath), ec);
    return r;
}

static void write_reports(
    const fs::path& root,
    const fs::path& resultsDir,
    const std::vector<Result>& results)
{
    fs::create_directories(resultsDir);
    const std::string stamp = make_timestamp();

    const fs::path base = resultsDir / ("LibPeConvCorpus-" + stamp);
    const fs::path logPath = base.string() + ".log";
    const fs::path csvPath = base.string() + ".csv";
    const fs::path jsonPath = base.string() + ".json";

    size_t passed = 0;
    size_t rejected = 0;
    size_t failed = 0;
    size_t crashed = 0;
    size_t timedOut = 0;
    size_t skipped = 0;

    for (const auto& r : results) {
        if (r.outcome == "PASS") ++passed;
        else if (r.outcome == "REJECT") ++rejected;
        else if (r.outcome == "CRASH") ++crashed;
        else if (r.outcome == "TIMEOUT") ++timedOut;
        else if (r.outcome == "SKIP") ++skipped;
        else ++failed;
    }

    {
        std::ofstream log(logPath, std::ios::binary);
        log << "libpeconv Corpus Differential Probe v6\r\n";
        log << "Root=" << narrow_path(root) << "\r\n";
        log << "Generated=" << stamp << "\r\n\r\n";

        for (const auto& r : results) {
            log << r.outcome << "  " << r.file
                << "  stage=" << r.stage
                << "  " << r.message
                << "  imports=" << r.imports
                << " exports=" << r.exports
                << " tls=" << r.tlsCallbacks
                << " resources=" << r.resources
                << " relocs=" << (r.relocsValid ? "valid" : (r.relocsPresent ? "invalid" : "absent"))
                << "\r\n";
        }

        log << "\r\nFiles=" << results.size()
            << "\r\nPassed=" << passed
            << "\r\nRejected=" << rejected
            << "\r\nFailed=" << failed
            << "\r\nCrashed=" << crashed
            << "\r\nTimedOut=" << timedOut
            << "\r\nSkipped=" << skipped
            << "\r\n";
    }

    {
        std::ofstream csv(csvPath, std::ios::binary);
        csv
            << "outcome,file,sha256,stage,message,fileSize,architecture,imageBase,entryPoint,"
               "sections,directories,mapOk,virtualSize,"
               "importsPresent,importsValid,importsParsed,imports,"
               "delayImportsPresent,delayImportsValid,delayImports,"
               "exportsPresent,exportsParsed,exports,"
               "tlsPresent,tlsParsed,tlsCallbacks,tlsCallbacksValid,tlsCallbacksInvalid,tlsCallbackDigest,tlsCallbackPreview,tlsCallbackTruncated,tlsCallbackFirstValidRva,tlsCallbackLastValidRva,tlsIndexRva,tlsRawData,"
               "resourcesPresent,resourcesParsed,resources,"
               "relocsPresent,relocsValid,relocFields,exceptionsPresent,exceptionsParsed,exceptionsCount,exceptionsDigest,loadConfigPresent,loadConfigParsed,loadConfigVersion,loadConfigSize,securityCookieRva,isDotNet,"
               "unmapOk,rawOutputSize,roundTripChecked,roundTripEqual,"
               "firstDiff,libraryElapsedUs,coreElapsedUs,workerElapsedUs,wallElapsedUs,elapsedMs,processExitCode\r\n";

        for (const auto& r : results) {
            csv
                << csv_escape(r.outcome) << ','
                << csv_escape(r.file) << ','
                << csv_escape(r.sha256) << ','
                << csv_escape(r.stage) << ','
                << csv_escape(r.message) << ','
                << r.fileSize << ','
                << csv_escape(r.architecture) << ','
                << csv_escape(hex64(r.imageBase)) << ','
                << csv_escape(hex32(r.entryPoint)) << ','
                << r.sections << ','
                << r.directories << ','
                << (r.mapOk ? "true" : "false") << ','
                << r.virtualSize << ','
                << (r.importsPresent ? "true" : "false") << ','
                << (r.importsValid ? "true" : "false") << ','
                << (r.importsParsed ? "true" : "false") << ','
                << r.imports << ','
                << (r.delayImportsPresent ? "true" : "false") << ','
                << (r.delayImportsValid ? "true" : "false") << ','
                << r.delayImports << ','
                << (r.exportsPresent ? "true" : "false") << ','
                << (r.exportsParsed ? "true" : "false") << ','
                << r.exports << ','
                << (r.tlsPresent ? "true" : "false") << ','
                << (r.tlsParsed ? "true" : "false") << ','
                << r.tlsCallbacks << ','
                << r.tlsCallbacksValid << ','
                << r.tlsCallbacksInvalid << ','
                << csv_escape(r.tlsCallbackDigest) << ','
                << csv_escape(r.tlsCallbackPreview) << ','
                << (r.tlsCallbackTruncated ? "true" : "false") << ','
                << csv_escape(r.tlsCallbackFirstValidRva) << ','
                << csv_escape(r.tlsCallbackLastValidRva) << ','
                << csv_escape(r.tlsIndexRva) << ','
                << csv_escape(r.tlsRawData) << ','
                << (r.resourcesPresent ? "true" : "false") << ','
                << (r.resourcesParsed ? "true" : "false") << ','
                << r.resources << ','
                << (r.relocsPresent ? "true" : "false") << ','
                << (r.relocsValid ? "true" : "false") << ','
                << r.relocFields << ','
                << (r.exceptionsPresent ? "true" : "false") << ','
                << (r.exceptionsParsed ? "true" : "false") << ','
                << r.exceptions << ','
                << csv_escape(r.exceptionsDigest) << ','
                << (r.loadConfigPresent ? "true" : "false") << ','
                << (r.loadConfigParsed ? "true" : "false") << ','
                << r.loadConfigVersion << ','
                << r.loadConfigSize << ','
                << csv_escape(r.securityCookieRva) << ','
                << (r.isDotNet ? "true" : "false") << ','
                << (r.unmapOk ? "true" : "false") << ','
                << r.rawOutputSize << ','
                << (r.roundTripChecked ? "true" : "false") << ','
                << (r.roundTripEqual ? "true" : "false") << ','
                << r.firstDiff << ','
                << r.libraryElapsedUs << ','
                << r.coreElapsedUs << ','
                << r.workerElapsedUs << ','
                << r.wallElapsedUs << ','
                << r.elapsedMs << ','
                << r.processExitCode << "\r\n";
        }
    }

    {
        std::ofstream json(jsonPath, std::ios::binary);
        json << "{\n";
        json << "  \"schemaVersion\": 6,\n";
        json << "  \"harness\": \"libpeconv\",\n";
        json << "  \"buildConfig\": \"" << build_configuration() << "\",\n";
        json << "  \"optimized\": " << (build_optimized() ? "true" : "false") << ",\n";
        json << "  \"processBits\": " << (sizeof(void*) * 8) << ",\n";
        json << "  \"timerUnit\": \"microseconds\",\n";
        json << "  \"timingModel\": \"library=direct load_pe_module through pe_virtual_to_raw return excluding roundtrip compare; core=post-read library probe; worker=worker entry through cleanup; wall=CreateProcess through worker exit\",\n";
        json << "  \"root\": \"" << json_escape(narrow_path(root)) << "\",\n";
        json << "  \"generated\": \"" << stamp << "\",\n";
        json << "  \"results\": [\n";

        for (size_t i = 0; i < results.size(); ++i) {
            const auto& r = results[i];

            json << "    {\n";
            json << "      \"outcome\": \"" << json_escape(r.outcome) << "\",\n";
            json << "      \"file\": \"" << json_escape(r.file) << "\",\n";
            json << "      \"stage\": \"" << json_escape(r.stage) << "\",\n";
            json << "      \"message\": \"" << json_escape(r.message) << "\",\n";
            json << "      \"fileSize\": " << r.fileSize << ",\n";
            json << "      \"architecture\": \"" << json_escape(r.architecture) << "\",\n";
            json << "      \"imageBase\": \"" << hex64(r.imageBase) << "\",\n";
            json << "      \"entryPoint\": \"" << hex32(r.entryPoint) << "\",\n";
            json << "      \"sections\": " << r.sections << ",\n";
            json << "      \"directories\": " << r.directories << ",\n";
            json << "      \"mapOk\": " << (r.mapOk ? "true" : "false") << ",\n";
            json << "      \"virtualSize\": " << r.virtualSize << ",\n";
            json << "      \"importsPresent\": " << (r.importsPresent ? "true" : "false") << ",\n";
            json << "      \"importsValid\": " << (r.importsValid ? "true" : "false") << ",\n";
            json << "      \"importsParsed\": " << (r.importsParsed ? "true" : "false") << ",\n";
            json << "      \"imports\": " << r.imports << ",\n";
            json << "      \"delayImportsPresent\": " << (r.delayImportsPresent ? "true" : "false") << ",\n";
            json << "      \"delayImportsValid\": " << (r.delayImportsValid ? "true" : "false") << ",\n";
            json << "      \"delayImports\": " << r.delayImports << ",\n";
            json << "      \"exportsPresent\": " << (r.exportsPresent ? "true" : "false") << ",\n";
            json << "      \"exportsParsed\": " << (r.exportsParsed ? "true" : "false") << ",\n";
            json << "      \"exports\": " << r.exports << ",\n";
            json << "      \"tlsPresent\": " << (r.tlsPresent ? "true" : "false") << ",\n";
            json << "      \"tlsParsed\": " << (r.tlsParsed ? "true" : "false") << ",\n";
            json << "      \"tlsCallbacks\": " << r.tlsCallbacks << ",\n";
            json << "      \"tlsCallbacksValid\": " << r.tlsCallbacksValid << ",\n";
            json << "      \"tlsCallbacksInvalid\": " << r.tlsCallbacksInvalid << ",\n";
            json << "      \"tlsCallbackDigest\": \"" << json_escape(r.tlsCallbackDigest) << "\",\n";
            json << "      \"tlsCallbackPreview\": \"" << json_escape(r.tlsCallbackPreview) << "\",\n";
            json << "      \"tlsCallbackTruncated\": " << (r.tlsCallbackTruncated ? "true" : "false") << ",\n";
            json << "      \"tlsCallbackFirstValidRva\": \"" << json_escape(r.tlsCallbackFirstValidRva) << "\",\n";
            json << "      \"tlsCallbackLastValidRva\": \"" << json_escape(r.tlsCallbackLastValidRva) << "\",\n";
            json << "      \"tlsIndexRva\": \"" << json_escape(r.tlsIndexRva) << "\",\n";
            json << "      \"tlsRawData\": \"" << json_escape(r.tlsRawData) << "\",\n";
            json << "      \"resourcesPresent\": " << (r.resourcesPresent ? "true" : "false") << ",\n";
            json << "      \"resourcesParsed\": " << (r.resourcesParsed ? "true" : "false") << ",\n";
            json << "      \"resources\": " << r.resources << ",\n";
            json << "      \"relocsPresent\": " << (r.relocsPresent ? "true" : "false") << ",\n";
            json << "      \"relocsValid\": " << (r.relocsValid ? "true" : "false") << ",\n";
            json << "      \"hasRelocs\": " << (r.relocsPresent ? "true" : "false") << ",\n";
            json << "      \"relocFields\": " << r.relocFields << ",\n";
            json << "      \"exceptionsPresent\": " << (r.exceptionsPresent ? "true" : "false") << ",\n";
            json << "      \"exceptionsParsed\": " << (r.exceptionsParsed ? "true" : "false") << ",\n";
            json << "      \"exceptionsCount\": " << r.exceptions << ",\n";
            json << "      \"exceptionsDigest\": \"" << json_escape(r.exceptionsDigest) << "\",\n";
            json << "      \"loadConfigPresent\": " << (r.loadConfigPresent ? "true" : "false") << ",\n";
            json << "      \"loadConfigParsed\": " << (r.loadConfigParsed ? "true" : "false") << ",\n";
            json << "      \"loadConfigVersion\": " << r.loadConfigVersion << ",\n";
            json << "      \"loadConfigSize\": " << r.loadConfigSize << ",\n";
            json << "      \"securityCookieRva\": \"" << json_escape(r.securityCookieRva) << "\",\n";
            json << "      \"isDotNet\": " << (r.isDotNet ? "true" : "false") << ",\n";
            json << "      \"unmapOk\": " << (r.unmapOk ? "true" : "false") << ",\n";
            json << "      \"rawOutputSize\": " << r.rawOutputSize << ",\n";
            json << "      \"roundTripChecked\": " << (r.roundTripChecked ? "true" : "false") << ",\n";
            json << "      \"roundTripEqual\": " << (r.roundTripEqual ? "true" : "false") << ",\n";
            json << "      \"firstDiff\": " << r.firstDiff << ",\n";
            json << "      \"libraryElapsedUs\": " << r.libraryElapsedUs << ",\n";
            json << "      \"coreElapsedUs\": " << r.coreElapsedUs << ",\n";
            json << "      \"workerElapsedUs\": " << r.workerElapsedUs << ",\n";
            json << "      \"wallElapsedUs\": " << r.wallElapsedUs << ",\n";
            json << "      \"elapsedMs\": " << r.elapsedMs << ",\n";
            json << "      \"processExitCode\": " << r.processExitCode << "\n";
            json << "    }" << (i + 1 == results.size() ? "\n" : ",\n");
        }

        json << "  ],\n";
        json << "  \"summary\": {\n";
        json << "    \"files\": " << results.size() << ",\n";
        json << "    \"passed\": " << passed << ",\n";
        json << "    \"rejected\": " << rejected << ",\n";
        json << "    \"failed\": " << failed << ",\n";
        json << "    \"crashed\": " << crashed << ",\n";
        json << "    \"timedOut\": " << timedOut << ",\n";
        json << "    \"skipped\": " << skipped << "\n";
        json << "  }\n";
        json << "}\n";
    }

    std::cout << "LOG : " << narrow_path(logPath) << "\n";
    std::cout << "CSV : " << narrow_path(csvPath) << "\n";
    std::cout << "JSON: " << narrow_path(jsonPath) << "\n";
    std::cout
        << "Files=" << results.size()
        << " Passed=" << passed
        << " Rejected=" << rejected
        << " Failed=" << failed
        << " Crashed=" << crashed
        << " TimedOut=" << timedOut
        << " Skipped=" << skipped
        << "\n";
}

static void usage()
{
    std::cout
        << "LibPeConvCorpus.exe --root <corpus-root> [--list <relative-file-list>]\n"
        << "                     [--results <dir>] [--timeout-ms <ms>] [--max-mb <mb>]\n"
        << "                     [--include-root <name>]...\n";
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc == 4 && std::wstring(argv[1]) == L"--worker") {
        return worker_main(fs::path(argv[2]), fs::path(argv[3]));
    }

    fs::path root;
    fs::path listPath;
    fs::path resultsDir;
    DWORD timeoutMs = 15000;
    uint64_t maxBytes = 512ull * 1024ull * 1024ull;

    std::vector<std::wstring> includeRoots;
    bool customRoots = false;

    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];

        if (arg == L"--root" && i + 1 < argc) {
            root = argv[++i];
        } else if (arg == L"--list" && i + 1 < argc) {
            listPath = argv[++i];
        } else if (arg == L"--results" && i + 1 < argc) {
            resultsDir = argv[++i];
        } else if (arg == L"--timeout-ms" && i + 1 < argc) {
            timeoutMs = static_cast<DWORD>(_wtoi(argv[++i]));
        } else if (arg == L"--max-mb" && i + 1 < argc) {
            maxBytes =
                static_cast<uint64_t>(_wtoi64(argv[++i])) *
                1024ull *
                1024ull;
        } else if (arg == L"--include-root" && i + 1 < argc) {
            if (!customRoots) {
                includeRoots.clear();
                customRoots = true;
            }
            includeRoots.push_back(argv[++i]);
        } else {
            usage();
            return 2;
        }
    }

    if (!customRoots) {
        includeRoots = {
            L"System32",
            L"SysWOW64",
            L"bintests-master",
            L"pocs-master"
        };
    }

    if (root.empty()) {
        usage();
        return 2;
    }

    std::error_code ec;
    root = fs::weakly_canonical(root, ec);
    if (ec || !fs::exists(root)) {
        std::cerr << "Corpus root does not exist.\n";
        return 2;
    }

    if (resultsDir.empty()) {
        resultsDir = fs::current_path() / "results";
    }
    fs::create_directories(resultsDir, ec);

    std::vector<fs::path> files;

    if (!listPath.empty()) {
        if (!load_list(root, listPath, includeRoots, files)) {
            std::cerr << "Could not read file list.\n";
            return 2;
        }
    } else {
        for (const auto& includeRoot : includeRoots) {
            const fs::path source = root / includeRoot;
            if (fs::exists(source, ec) && fs::is_directory(source, ec)) {
                enumerate_files(source, files);
            }
            ec.clear();
        }
        std::sort(files.begin(), files.end());
    }

    const fs::path workersDir = resultsDir / ".workers";
    fs::create_directories(workersDir, ec);

    std::vector<Result> results;
    results.reserve(files.size());

    for (size_t i = 0; i < files.size(); ++i) {
        const fs::path& file = files[i];

        Result r;
        r.file = relative_name(root, file);

        if (!fs::exists(file, ec) || ec) {
            r.outcome = "SKIP";
            r.stage = "input";
            r.message = "file no longer exists";
            results.push_back(r);
            ec.clear();
            continue;
        }

        const uint64_t size = fs::file_size(file, ec);
        if (ec) {
            r.outcome = "FAIL";
            r.stage = "size";
            r.message = "file_size failed";
            results.push_back(r);
            ec.clear();
            continue;
        }

        r.fileSize = size;

        if (size > maxBytes) {
            r.outcome = "SKIP";
            r.stage = "size";
            r.message = "file exceeds --max-mb limit";
            results.push_back(r);
            continue;
        }

        const fs::path tempPath =
            workersDir / ("worker-" + std::to_string(i) + ".tmp");

        r = run_worker(root, file, tempPath, timeoutMs);
        results.push_back(r);

        std::cout
            << "[" << (i + 1) << "/" << files.size() << "] "
            << r.outcome << " "
            << r.file << "\n";
    }

    fs::remove_all(workersDir, ec);
    write_reports(root, resultsDir, results);

    for (const auto& r : results) {
        if (
            r.outcome == "FAIL" ||
            r.outcome == "CRASH" ||
            r.outcome == "TIMEOUT") {
            return 1;
        }
    }

    return 0;
}
