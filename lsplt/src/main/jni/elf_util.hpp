// ELF文件处理工具类
#pragma once
#include <link.h>
#include <stdint.h>
#include <string_view>
#include <vector>

// ELF文件解析和操作类
class Elf {
    ElfW(Addr) base_addr_ = 0;      // 基地址
    ElfW(Addr) bias_addr_ = 0;      // 偏移地址

    ElfW(Ehdr) *header_ = nullptr;          // ELF头
    ElfW(Phdr) *program_header_ = nullptr;  // 程序头

    ElfW(Dyn) *dynamic_ = nullptr;          // .dynamic段
    ElfW(Word) dynamic_size_ = 0;

    const char *dyn_str_ = nullptr;         // .dynstr (字符串表)
    ElfW(Sym) *dyn_sym_ = nullptr;          // .dynsym (符号索引到字符串表偏移)

    ElfW(Addr) rel_plt_ = 0;                // .rel.plt 或 .rela.plt
    ElfW(Word) rel_plt_size_ = 0;

    ElfW(Addr) rel_dyn_ = 0;                // .rel.dyn 或 .rela.dyn
    ElfW(Word) rel_dyn_size_ = 0;

    ElfW(Addr) rel_android_ = 0;            // Android压缩的rel或rela
    ElfW(Word) rel_android_size_ = 0;

    // ELF哈希表
    uint32_t *bucket_ = nullptr;
    uint32_t bucket_count_ = 0;
    uint32_t *chain_ = nullptr;

    // append for GNU hash
    uint32_t sym_offset_ = 0;
    ElfW(Addr) *bloom_ = nullptr;
    uint32_t bloom_size_ = 0;
    uint32_t bloom_shift_ = 0;

    bool is_use_rela_ = false;
    bool valid_ = false;

    uint32_t GnuLookup(std::string_view name) const;
    uint32_t ElfLookup(std::string_view name) const;
    uint32_t LinearLookup(std::string_view name) const;
public:
    std::vector<uintptr_t> FindPltAddr(std::string_view name) const;
    Elf(uintptr_t base_addr);
    bool Valid() const { return valid_; };
};
