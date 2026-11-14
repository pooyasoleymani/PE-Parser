#include "pe_parser.hpp"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <utility>

#ifdef __linux__
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace pe {
namespace {
template<class T> T le(const uint8_t* p) {
    T v{};
    for (size_t i=0; i<sizeof(T); ++i)
        v |= static_cast<T>(p[i]) << (8U * i);
    return v;
}
std::string hex(uint64_t n, int width=0) {
    std::ostringstream os; os << "0x" << std::uppercase << std::hex
                            << std::setw(width) << std::setfill('0') << n;
    return os.str();
}
std::string machineName(uint16_t m) {
    switch(m) {
        case 0x014c: return "x86";
        case 0x8664: return "x86-64";
        case 0x01c0: return "ARM";
        case 0xAA64: return "ARM64";
        default: return "Unknown";
    }
}
#ifdef __linux__
// Uses execvp (no shell) so a symbol read from an untrusted PE cannot inject a command.
std::string llvmUndname(const std::string& symbol) {
    int fds[2];
    if (pipe(fds) != 0) return {};
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return {}; }
    if (pid == 0) {
        dup2(fds[1], STDOUT_FILENO);
        close(fds[0]); close(fds[1]);
        char arg0[] = "llvm-undname";
        char* const argv[] = {arg0, const_cast<char*>(symbol.c_str()), nullptr};
        execvp(arg0, argv);
        _exit(127);
    }
    close(fds[1]);
    std::string out; char buf[512]; ssize_t n;
    while ((n=read(fds[0],buf,sizeof(buf))) > 0) {
        if (out.size() < 16384) out.append(buf, static_cast<size_t>(n));
    }
    close(fds[0]); int status=0; waitpid(pid,&status,0);
    if (!WIFEXITED(status) || WEXITSTATUS(status)!=0) return {};
    while (!out.empty() && (out.back()=='\n' || out.back()=='\r')) out.pop_back();
    return out;
}
#else
std::string llvmUndname(const std::string&) { return {}; }
#endif
}
Parser::Parser(const std::filesystem::path& p): path_(p) {}
bool Parser::fail(const std::string& m) { error_=m; return false; }
bool Parser::readU16(uint64_t o,uint16_t& v) const {
    if (o>data_.size() || data_.size()-static_cast<size_t>(o)<2) return false;
    v=le<uint16_t>(&data_[static_cast<size_t>(o)]); return true;
}
bool Parser::readU32(uint64_t o,uint32_t& v) const {
    if (o>data_.size() || data_.size()-static_cast<size_t>(o)<4) return false;
    v=le<uint32_t>(&data_[static_cast<size_t>(o)]); return true;
}
bool Parser::readU64(uint64_t o,uint64_t& v) const {
    if (o>data_.size() || data_.size()-static_cast<size_t>(o)<8) return false;
    v=le<uint64_t>(&data_[static_cast<size_t>(o)]); return true;
}
bool Parser::readCString(uint64_t o,std::string& s,size_t limit) const {
    if (o>=data_.size()) return false;
    s.clear(); size_t pos=static_cast<size_t>(o);
    size_t end=std::min(data_.size(), pos+std::min(limit,data_.size()-pos));
    for (;pos<end;++pos) {
        if (data_[pos]==0) return true;
        s.push_back(static_cast<char>(data_[pos]));
    }
    return false;
}
std::optional<uint64_t> Parser::rvaToOffset(uint32_t rva) const {
    if (rva < opt_.sizeOfHeaders && rva < data_.size()) return rva;
    for (const auto& s:sections_) {
        if (rva < s.virtualAddress) continue;
        uint64_t delta=static_cast<uint64_t>(rva)-s.virtualAddress;
        // An RVA in zero-filled virtual tail has no corresponding file bytes.
        if (delta >= s.sizeOfRawData) continue;
        uint64_t off=static_cast<uint64_t>(s.pointerToRawData)+delta;
        if (off < data_.size()) return off;
    }
    return std::nullopt;
}
bool Parser::readRvaCString(uint32_t rva,std::string& s) const {
    auto off=rvaToOffset(rva); return off && readCString(*off,s);
}
bool Parser::parseDos() {
    if (data_.size()<64) return fail("File is shorter than IMAGE_DOS_HEADER");
    uint16_t* fields[] = {&dos_.e_magic,&dos_.e_cblp,&dos_.e_cp,&dos_.e_crlc,
        &dos_.e_cparhdr,&dos_.e_minalloc,&dos_.e_maxalloc,&dos_.e_ss,&dos_.e_sp,
        &dos_.e_csum,&dos_.e_ip,&dos_.e_cs,&dos_.e_lfarlc,&dos_.e_ovno};
    for (size_t i=0;i<14;++i)
        if (!readU16(static_cast<uint64_t>(i)*2,*fields[i])) return fail("Truncated DOS Header");
    for (size_t i=0;i<4;++i) if(!readU16(28+i*2,dos_.e_res[i])) return fail("Truncated DOS reserved fields");
    if(!readU16(36,dos_.e_oemid)||!readU16(38,dos_.e_oeminfo)) return fail("Truncated DOS OEM fields");
    for (size_t i=0;i<10;++i) if(!readU16(40+i*2,dos_.e_res2[i])) return fail("Truncated DOS reserved fields");
    if (dos_.e_magic!=0x5A4D) return fail("Invalid DOS signature (expected MZ)");
    uint32_t raw=0; if (!readU32(0x3c,raw)) return fail("Cannot read e_lfanew");
    dos_.e_lfanew=static_cast<int32_t>(raw);
    if (raw>data_.size() || data_.size()-raw<24) return fail("e_lfanew points outside the file");
    return true;
}
bool Parser::parseNt() {
    const uint64_t nt=static_cast<uint32_t>(dos_.e_lfanew);
    uint32_t sig=0;
    if (!readU32(nt,sig) || sig!=0x00004550) return fail("Invalid PE signature");
    uint64_t fh=nt+4;
    if (!readU16(fh,file_.Machine)||!readU16(fh+2,file_.NumberOfSections)||
       !readU32(fh+4,file_.TimeDateStamp)||!readU32(fh+8,file_.PointerToSymbolTable)||
       !readU32(fh+12,file_.NumberOfSymbols)||!readU16(fh+16,file_.SizeOfOptionalHeader)||
       !readU16(fh+18,file_.Characteristics)) return fail("Truncated COFF File Header");
    if (file_.NumberOfSections>4096) return fail("Unreasonable section count");
    uint64_t oo=fh+20;
    uint64_t optEnd=oo+file_.SizeOfOptionalHeader;
    if (optEnd>data_.size() || file_.SizeOfOptionalHeader<2) return fail("Invalid Optional Header size");
    if (!readU16(oo,opt_.magic)) return fail("Cannot read Optional Header magic");
    if (opt_.magic==0x10b) is64_=false;
    else if (opt_.magic==0x20b) is64_=true;
    else return fail("Unsupported Optional Header magic");
    auto u16=[&](uint64_t x,uint16_t& v){return x+2<=optEnd && readU16(x,v);};
    auto u32=[&](uint64_t x,uint32_t& v){return x+4<=optEnd && readU32(x,v);};
    auto u64=[&](uint64_t x,uint64_t& v){return x+8<=optEnd && readU64(x,v);};
    uint16_t tmp16=0;
    if (!u16(oo+2,tmp16)) return fail("Truncated Optional Header");
    opt_.majorLinkerVersion=static_cast<uint8_t>(data_[static_cast<size_t>(oo+2)]);
    opt_.minorLinkerVersion=static_cast<uint8_t>(data_[static_cast<size_t>(oo+3)]);
    if (!u32(oo+4,opt_.sizeOfCode)||!u32(oo+8,opt_.sizeOfInitializedData)||
       !u32(oo+12,opt_.sizeOfUninitializedData)||!u32(oo+16,opt_.addressOfEntryPoint)||
       !u32(oo+20,opt_.baseOfCode)) return fail("Truncated Optional Header common fields");
    uint64_t p=oo+24;
    if (is64_) {
        if (!u64(p,opt_.imageBase)) return fail("Truncated PE32+ ImageBase");
        p+=8;
    } else {
        if (!u32(p,opt_.baseOfData)) return fail("Truncated PE32 BaseOfData");
        p+=4;
        uint32_t ib=0;
        if(!u32(p,ib)) return fail("Truncated PE32 ImageBase");
        opt_.imageBase=ib; p+=4;
    }
    if (!u32(p,opt_.sectionAlignment)||!u32(p+4,opt_.fileAlignment)||
       !u16(p+8,opt_.majorOSVersion)||!u16(p+10,opt_.minorOSVersion)||
       !u16(p+12,opt_.majorImageVersion)||!u16(p+14,opt_.minorImageVersion)||
       !u16(p+16,opt_.majorSubsystemVersion)||!u16(p+18,opt_.minorSubsystemVersion)||
       !u32(p+20,opt_.win32VersionValue)||!u32(p+24,opt_.sizeOfImage)||
       !u32(p+28,opt_.sizeOfHeaders)||!u32(p+32,opt_.checksum)||
       !u16(p+36,opt_.subsystem)||!u16(p+38,opt_.dllCharacteristics))
        return fail("Truncated Optional Header fields");
    p+=40;
    if (is64_) {
        if(!u64(p,opt_.sizeOfStackReserve)||!u64(p+8,opt_.sizeOfStackCommit)||
           !u64(p+16,opt_.sizeOfHeapReserve)||!u64(p+24,opt_.sizeOfHeapCommit)||
           !u32(p+32,opt_.loaderFlags)||!u32(p+36,opt_.numberOfRvaAndSizes))
            return fail("Truncated PE32+ Optional Header tail");
        p+=40;
    } else {
        uint32_t a=0,b=0,c=0,d=0;
        if(!u32(p,a)||!u32(p+4,b)||!u32(p+8,c)||!u32(p+12,d)||
           !u32(p+16,opt_.loaderFlags)||!u32(p+20,opt_.numberOfRvaAndSizes))
            return fail("Truncated PE32 Optional Header tail");
        opt_.sizeOfStackReserve=a; opt_.sizeOfStackCommit=b;
        opt_.sizeOfHeapReserve=c; opt_.sizeOfHeapCommit=d; p+=24;
    }
    uint64_t available=(optEnd>p)?(optEnd-p)/8:0;
    uint64_t count=std::min<uint64_t>(opt_.numberOfRvaAndSizes,available);
    for(uint64_t i=0;i<count;++i) {
        DataDirectory d{};
        if(!readU32(p+i*8,d.rva)||!readU32(p+i*8+4,d.size)) return fail("Invalid data directory");
        opt_.directories.push_back(d);
    }
    return true;
}
bool Parser::parseSections() {
    uint64_t off=static_cast<uint32_t>(dos_.e_lfanew)+4+20+file_.SizeOfOptionalHeader;
    uint64_t bytes=static_cast<uint64_t>(file_.NumberOfSections)*40;
    if(off>data_.size()||bytes>data_.size()-off) return fail("Section Header table exceeds file");
    for(uint16_t i=0;i<file_.NumberOfSections;++i) {
        uint64_t p=off+static_cast<uint64_t>(i)*40;
        Section s; size_t n=0;
        while(n<8 && data_[static_cast<size_t>(p)+n]!=0) { s.name.push_back(static_cast<char>(data_[static_cast<size_t>(p)+n])); ++n; }
        if(!readU32(p+8,s.virtualSize)||!readU32(p+12,s.virtualAddress)||
           !readU32(p+16,s.sizeOfRawData)||!readU32(p+20,s.pointerToRawData)||
           !readU32(p+24,s.pointerToRelocations)||!readU32(p+28,s.pointerToLinenumbers)||
           !readU16(p+32,s.numberOfRelocations)||!readU16(p+34,s.numberOfLinenumbers)||
           !readU32(p+36,s.characteristics)) return fail("Truncated Section Header");
        if(s.sizeOfRawData && (s.pointerToRawData>data_.size() ||
           s.sizeOfRawData>data_.size()-s.pointerToRawData)) return fail("Section raw data exceeds file");
        sections_.push_back(std::move(s));
    }
    return true;
}
bool Parser::parseImports() {
    if(opt_.directories.size()<=1) return true;
    const auto dir=opt_.directories[1];
    if(dir.rva==0 || dir.size==0) return true;
    auto base=rvaToOffset(dir.rva); if(!base) return fail("Import Directory RVA is unmapped");
    uint64_t max=dir.size/20;
    bool terminated=false;
    for(uint64_t i=0;i<max;++i) {
        uint64_t p=*base+i*20;
        uint32_t oft=0,ts=0,fc=0,nameRva=0,ft=0;
        if(!readU32(p,oft)||!readU32(p+4,ts)||!readU32(p+8,fc)||
           !readU32(p+12,nameRva)||!readU32(p+16,ft)) return fail("Truncated Import Descriptor");
        if(!(oft|ts|fc|nameRva|ft)) { terminated=true; break; }
        if(!nameRva) return fail("Import descriptor has no DLL name");
        ImportedLibrary lib;
        if(!readRvaCString(nameRva,lib.name)) return fail("Invalid imported DLL name RVA");
        uint32_t lookup=oft?oft:ft;
        auto thunkBase=rvaToOffset(lookup);
        if(!thunkBase) return fail("Invalid Import Lookup Table RVA");
        const uint64_t width=is64_?8:4;
        const uint64_t flag=is64_?0x8000000000000000ULL:0x80000000ULL;
        bool thunkEnd=false;
        uint64_t maxEntries=(data_.size()-static_cast<size_t>(*thunkBase))/width;
        for(uint64_t j=0;j<maxEntries;++j) {
            uint64_t val=0,at=*thunkBase+j*width;
            if(is64_) { if(!readU64(at,val)) return fail("Truncated 64-bit thunk"); }
            else { uint32_t v=0; if(!readU32(at,v)) return fail("Truncated 32-bit thunk"); val=v; }
            if(val==0) { thunkEnd=true; break; }
            ImportedFunction fn;
            if(val&flag) { fn.byOrdinal=true; fn.ordinal=static_cast<uint16_t>(val&0xffff); }
            else {
                if(val>UINT32_MAX) return fail("Import-by-name RVA is too large");
                auto no=rvaToOffset(static_cast<uint32_t>(val));
                if(!no||!readU16(*no,fn.hint)||!readCString(*no+2,fn.name))
                    return fail("Invalid IMAGE_IMPORT_BY_NAME");
            }
            lib.functions.push_back(std::move(fn));
        }
        if(!thunkEnd) return fail("Unterminated import thunk table");
        imports_.push_back(std::move(lib));
    }
    if(!terminated) return fail("Import descriptor array has no null terminator within directory size");
    return true;
}
bool Parser::parseExports() {
    if(opt_.directories.empty()) return true;
    const auto dir=opt_.directories[0];
    if(dir.rva==0||dir.size==0) return true;
    auto eo=rvaToOffset(dir.rva); if(!eo) return fail("Export Directory RVA is unmapped");
    uint32_t base=0,nfunc=0,nname=0,funcs=0,names=0,ords=0;
    if(!readU32(*eo+16,base)||!readU32(*eo+20,nfunc)||!readU32(*eo+24,nname)||
       !readU32(*eo+28,funcs)||!readU32(*eo+32,names)||!readU32(*eo+36,ords))
        return fail("Truncated Export Directory");
    if(nfunc>1000000||nname>1000000) return fail("Unreasonable export count");
    auto fo=rvaToOffset(funcs), no=rvaToOffset(names), oo=rvaToOffset(ords);
    if((nfunc&&!fo)||(nname&&(!no||!oo))) return fail("Export arrays have invalid RVAs");
    std::vector<uint32_t> fr(nfunc), nr(nname);
    std::vector<uint16_t> oi(nname);
    for(uint32_t i=0;i<nfunc;++i) if(!readU32(*fo+static_cast<uint64_t>(i)*4,fr[i])) return fail("Truncated Export Address Table");
    for(uint32_t i=0;i<nname;++i) {
        if(!readU32(*no+static_cast<uint64_t>(i)*4,nr[i])||
           !readU16(*oo+static_cast<uint64_t>(i)*2,oi[i])) return fail("Truncated export name/ordinal arrays");
    }
    std::vector<std::string> functionNames(nfunc);
    for(uint32_t i=0;i<nname;++i) {
        if(oi[i]>=nfunc) return fail("Export name ordinal index is out of range");
        std::string name;
        if(!readRvaCString(nr[i],name)) return fail("Invalid export name RVA");
        if(functionNames[oi[i]].empty()) functionNames[oi[i]]=std::move(name);
        else functionNames[oi[i]] += " | " + name;
    }
    uint64_t exportEnd=static_cast<uint64_t>(dir.rva)+dir.size;
    for(uint32_t i=0;i<nfunc;++i) {
        if(fr[i]==0) continue;
        ExportedFunction f; f.name=functionNames[i]; f.ordinal=static_cast<uint64_t>(base)+i; f.rva=fr[i];
        if(fr[i]>=dir.rva && static_cast<uint64_t>(fr[i])<exportEnd) {
            f.forwarded=true;
            if(!readRvaCString(fr[i],f.forwarder)) return fail("Invalid forwarded export string");
        }
        if(!f.name.empty() && f.name[0]=='?') f.demangled=llvmUndname(f.name);
        exports_.push_back(std::move(f));
    }
    return true;
}
bool Parser::parse() {
    std::ifstream in(path_,std::ios::binary);
    if(!in) return fail("Cannot open input file");
    in.seekg(0,std::ios::end); auto length=in.tellg();
    if(length<0) return fail("Cannot determine file size");
    if(static_cast<uint64_t>(length)>512ULL*1024*1024) return fail("File exceeds 512 MiB safety limit");
    data_.resize(static_cast<size_t>(length)); in.seekg(0);
    if(!data_.empty()&&!in.read(reinterpret_cast<char*>(data_.data()),static_cast<std::streamsize>(data_.size())))
        return fail("Failed to read input file");
    if(!parseDos()||!parseNt()||!parseSections()||!parseImports()||!parseExports()) return false;
    return true;
}
void Parser::print(std::ostream& out) const {
    out << "=== DOS HEADER ===\n";
    out << "e_magic: " << hex(dos_.e_magic,4) << " (MZ)\n";
    out << "e_lfanew: " << hex(static_cast<uint32_t>(dos_.e_lfanew)) << '\n';
    out << "=== NT / FILE HEADER ===\n";
    out << "Signature: PE\\0\\0\nMachine: " << hex(file_.Machine,4) << " (" << machineName(file_.Machine) << ")\n";
    out << "NumberOfSections: " << file_.NumberOfSections << "\nTimeDateStamp: " << hex(file_.TimeDateStamp)
        << "\nPointerToSymbolTable: " << hex(file_.PointerToSymbolTable) << "\nNumberOfSymbols: " << file_.NumberOfSymbols
        << "\nSizeOfOptionalHeader: " << file_.SizeOfOptionalHeader << "\nCharacteristics: " << hex(file_.Characteristics) << '\n';
    out << "=== OPTIONAL HEADER (" << (is64_?"PE32+":"PE32") << ") ===\n";
    out << "Magic: " << hex(opt_.magic,4) << "\nLinkerVersion: " << unsigned(opt_.majorLinkerVersion) << '.' << unsigned(opt_.minorLinkerVersion)
        << "\nSizeOfCode: " << opt_.sizeOfCode << "\nSizeOfInitializedData: " << opt_.sizeOfInitializedData
        << "\nSizeOfUninitializedData: " << opt_.sizeOfUninitializedData << "\nAddressOfEntryPoint: " << hex(opt_.addressOfEntryPoint)
        << "\nBaseOfCode: " << hex(opt_.baseOfCode) << "\nImageBase: " << hex(opt_.imageBase)
        << "\nSectionAlignment: " << opt_.sectionAlignment << "\nFileAlignment: " << opt_.fileAlignment
        << "\nSizeOfImage: " << opt_.sizeOfImage << "\nSizeOfHeaders: " << opt_.sizeOfHeaders
        << "\nSubsystem: " << opt_.subsystem << "\nDllCharacteristics: " << hex(opt_.dllCharacteristics)
        << "\nNumberOfRvaAndSizes: " << opt_.numberOfRvaAndSizes << '\n';
    out << "Data Directories:\n";
    for(size_t i=0;i<opt_.directories.size();++i)
        out << "  [" << i << "] RVA=" << hex(opt_.directories[i].rva) << " Size=" << hex(opt_.directories[i].size) << '\n';
    out << "=== SECTION HEADERS ===\n";
    for(const auto& s:sections_) out << s.name << ": VirtualSize=" << hex(s.virtualSize)
        << " VirtualAddress=" << hex(s.virtualAddress) << " SizeOfRawData=" << hex(s.sizeOfRawData)
        << " PointerToRawData=" << hex(s.pointerToRawData) << " Characteristics=" << hex(s.characteristics) << '\n';
    out << "=== IMPORTS ===\n";
    if(imports_.empty()) out << "(none)\n";
    for(const auto& lib:imports_) {
        out << "DLL: " << lib.name << '\n';
        for(const auto& f:lib.functions) {
            if(f.byOrdinal) out << "  Ordinal: " << f.ordinal << '\n';
            else out << "  " << f.name << " (Hint: " << f.hint << ")\n";
        }
    }
    out << "=== EXPORTS ===\n";
    if(exports_.empty()) out << "(none)\n";
    for(const auto& f:exports_) {
        out << "Ordinal: " << f.ordinal << " RVA: " << hex(f.rva) << " Name: "
            << (f.name.empty()?"<ordinal-only>":f.name);
        if(f.forwarded) out << " -> " << f.forwarder;
        out << '\n';
        if(!f.demangled.empty()) out << "  MSVC demangled: " << f.demangled << '\n';
        else if(!f.name.empty() && f.name[0]=='?') out << "  MSVC demangling unavailable (install LLVM tools / llvm-undname)\n";
    }
}
}
