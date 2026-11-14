#pragma once
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace pe {
struct DosHeader {
    uint16_t e_magic{}, e_cblp{}, e_cp{}, e_crlc{}, e_cparhdr{}, e_minalloc{}, e_maxalloc{};
    uint16_t e_ss{}, e_sp{}, e_csum{}, e_ip{}, e_cs{}, e_lfarlc{}, e_ovno{};
    uint16_t e_res[4]{}; uint16_t e_oemid{}; uint16_t e_oeminfo{};
    uint16_t e_res2[10]{}; int32_t e_lfanew{};
};
struct FileHeader {
    uint16_t Machine{}, NumberOfSections{};
    uint32_t TimeDateStamp{}, PointerToSymbolTable{}, NumberOfSymbols{};
    uint16_t SizeOfOptionalHeader{}, Characteristics{};
};
struct DataDirectory { uint32_t rva{}, size{}; };
struct OptionalHeader {
    uint16_t magic{};
    uint8_t majorLinkerVersion{}, minorLinkerVersion{};
    uint32_t sizeOfCode{}, sizeOfInitializedData{}, sizeOfUninitializedData{};
    uint32_t addressOfEntryPoint{}, baseOfCode{}, baseOfData{};
    uint64_t imageBase{};
    uint32_t sectionAlignment{}, fileAlignment{};
    uint16_t majorOSVersion{}, minorOSVersion{}, majorImageVersion{}, minorImageVersion{};
    uint16_t majorSubsystemVersion{}, minorSubsystemVersion{};
    uint32_t win32VersionValue{}, sizeOfImage{}, sizeOfHeaders{}, checksum{};
    uint16_t subsystem{}, dllCharacteristics{};
    uint64_t sizeOfStackReserve{}, sizeOfStackCommit{}, sizeOfHeapReserve{}, sizeOfHeapCommit{};
    uint32_t loaderFlags{}, numberOfRvaAndSizes{};
    std::vector<DataDirectory> directories;
};
struct Section {
    std::string name;
    uint32_t virtualSize{}, virtualAddress{}, sizeOfRawData{}, pointerToRawData{};
    uint32_t pointerToRelocations{}, pointerToLinenumbers{};
    uint16_t numberOfRelocations{}, numberOfLinenumbers{};
    uint32_t characteristics{};
};
struct ImportedFunction {
    std::string name;
    uint16_t hint{}, ordinal{};
    bool byOrdinal{};
};
struct ImportedLibrary {
    std::string name;
    std::vector<ImportedFunction> functions;
};
struct ExportedFunction {
    std::string name;
    uint32_t ordinal{}, rva{};
    bool forwarded{};
    std::string forwarder;
    std::string demangled;
};
class Parser {
public:
    explicit Parser(const std::filesystem::path& path);
    bool parse();
    void print(std::ostream& out) const;
    const std::string& error() const { return error_; }
private:
    std::filesystem::path path_;
    std::vector<uint8_t> data_;
    std::string error_;
    DosHeader dos_{};
    FileHeader file_{};
    OptionalHeader opt_{};
    std::vector<Section> sections_;
    std::vector<ImportedLibrary> imports_;
    std::vector<ExportedFunction> exports_;
    bool is64_{};

    bool parseDos();
    bool parseNt();
    bool parseSections();
    bool parseImports();
    bool parseExports();
    bool readU16(uint64_t off, uint16_t& v) const;
    bool readU32(uint64_t off, uint32_t& v) const;
    bool readU64(uint64_t off, uint64_t& v) const;
    bool readCString(uint64_t off, std::string& s, size_t limit = 4096) const;
    bool readRvaCString(uint32_t rva, std::string& s) const;
    std::optional<uint64_t> rvaToOffset(uint32_t rva) const;
    bool fail(const std::string& message);
};
}
