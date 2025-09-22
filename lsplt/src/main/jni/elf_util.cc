// ELF文件处理工具
// 提供ELF文件解析和PLT/GOT表操作功能

#include "elf_util.hpp"

#include <cstring>
#include <type_traits>
#include <vector>
#include <tuple>

// 定义各架构的重定位类型常量
#if defined(__arm__)
#define ELF_R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT  //.rel.plt
#define ELF_R_GENERIC_GLOB_DAT R_ARM_GLOB_DAT    //.rel.dyn
#define ELF_R_GENERIC_ABS R_ARM_ABS32            //.rel.dyn
#elif defined(__aarch64__)
#define ELF_R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_AARCH64_GLOB_DAT
#define ELF_R_GENERIC_ABS R_AARCH64_ABS64
#elif defined(__i386__)
#define ELF_R_GENERIC_JUMP_SLOT R_386_JMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_386_GLOB_DAT
#define ELF_R_GENERIC_ABS R_386_32
#elif defined(__x86_64__)
#define ELF_R_GENERIC_JUMP_SLOT R_X86_64_JUMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_X86_64_GLOB_DAT
#define ELF_R_GENERIC_ABS R_X86_64_64
#elif defined(__riscv)
#define ELF_R_GENERIC_JUMP_SLOT R_RISCV_JUMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT R_RISCV_64
#define ELF_R_GENERIC_ABS R_RISCV_64
#endif

// 根据架构定义符号和类型提取宏
#if defined(__LP64__)
#define ELF_R_SYM(info) ELF64_R_SYM(info)
#define ELF_R_TYPE(info) ELF64_R_TYPE(info)
#else
#define ELF_R_SYM(info) ELF32_R_SYM(info)
#define ELF_R_TYPE(info) ELF32_R_TYPE(info)
#endif

namespace {
// 根据ELF头和偏移量计算结构指针
template <typename T>
inline constexpr auto OffsetOf(ElfW(Ehdr) * head, ElfW(Off) off) {
    return reinterpret_cast<std::conditional_t<std::is_pointer_v<T>, T, T *>>(
        reinterpret_cast<uintptr_t>(head) + off);
}

// 根据偏移量设置指针，包含有效性检查
template <typename T>
inline constexpr auto SetByOffset(T &ptr, ElfW(Addr) base, ElfW(Addr) bias, ElfW(Addr) off) {
    if (auto val = bias + off; val > base) {
        ptr = reinterpret_cast<T>(val);
        return true;
    }
    ptr = 0;
    return false;
}

}  // namespace

// ELF类构造函数，解析ELF文件头和动态段
Elf::Elf(uintptr_t base_addr) : base_addr_(base_addr) {
    header_ = reinterpret_cast<decltype(header_)>(base_addr);

    // 检查ELF魔数
    if (0 != memcmp(header_->e_ident, ELFMAG, SELFMAG)) return;

    // 检查架构类型(64/32位)
#if defined(__LP64__)
    if (ELFCLASS64 != header_->e_ident[EI_CLASS]) return;
#else
    if (ELFCLASS32 != header_->e_ident[EI_CLASS]) return;
#endif

    // 检查字节序(小端/大端)
    if (ELFDATA2LSB != header_->e_ident[EI_DATA]) return;

    // 检查ELF版本
    if (EV_CURRENT != header_->e_ident[EI_VERSION]) return;

    // 检查文件类型(可执行文件或动态库)
    if (ET_EXEC != header_->e_type && ET_DYN != header_->e_type) return;

    // 检查目标架构
#if defined(__arm__)
    if (EM_ARM != header_->e_machine) return;
#elif defined(__aarch64__)
    if (EM_AARCH64 != header_->e_machine) return;
#elif defined(__i386__)
    if (EM_386 != header_->e_machine) return;
#elif defined(__x86_64__)
    if (EM_X86_64 != header_->e_machine) return;
#elif defined(__riscv)
    if (EM_RISCV != header_->e_machine) return;
#else
    return;
#endif

    // 检查ELF版本号
    if (EV_CURRENT != header_->e_version) return;

    // 获取程序头表指针
    program_header_ = OffsetOf<decltype(program_header_)>(header_, header_->e_phoff);

    // 遍历程序头表，查找LOAD和DYNAMIC段
    auto ph_off = reinterpret_cast<uintptr_t>(program_header_);
    for (int i = 0; i < header_->e_phnum; i++, ph_off += header_->e_phentsize) {
        auto *program_header = reinterpret_cast<ElfW(Phdr) *>(ph_off);
        // 找到第一个LOAD段，用于计算基地址偏移
        if (program_header->p_type == PT_LOAD && program_header->p_offset == 0) {
            if (base_addr_ >= program_header->p_vaddr) {
                bias_addr_ = base_addr_ - program_header->p_vaddr;
            }
        } else if (program_header->p_type == PT_DYNAMIC) {
            // 找到DYNAMIC段，保存动态链接信息
            dynamic_ = reinterpret_cast<decltype(dynamic_)>(program_header->p_vaddr);
            dynamic_size_ = program_header->p_memsz;
        }
    }
    if (!dynamic_ || !bias_addr_) return;
    // 计算动态段的实际内存地址
    dynamic_ =
        reinterpret_cast<decltype(dynamic_)>(bias_addr_ + reinterpret_cast<uintptr_t>(dynamic_));

    // 解析动态段，提取符号表、字符串表、重定位表等信息
    for (auto *dynamic = dynamic_, *dynamic_end = dynamic_ + (dynamic_size_ / sizeof(dynamic[0]));
         dynamic < dynamic_end; ++dynamic) {
        switch (dynamic->d_tag) {
        case DT_NULL:
            // 动态段结束标记
            dynamic = dynamic_end;
            break;
        case DT_STRTAB: {
            // 动态字符串表地址
            if (!SetByOffset(dyn_str_, base_addr_, bias_addr_, dynamic->d_un.d_ptr)) return;
            break;
        }
        case DT_SYMTAB: {
            // 动态符号表地址
            if (!SetByOffset(dyn_sym_, base_addr_, bias_addr_, dynamic->d_un.d_ptr)) return;
            break;
        }
        case DT_PLTREL:
            // PLT重定位类型(REL或RELA)
            is_use_rela_ = dynamic->d_un.d_val == DT_RELA;
            break;
        case DT_JMPREL: {
            // PLT重定位表地址
            if (!SetByOffset(rel_plt_, base_addr_, bias_addr_, dynamic->d_un.d_ptr)) return;
            break;
        }
        case DT_PLTRELSZ:
            // PLT重定位表大小
            rel_plt_size_ = dynamic->d_un.d_val;
            break;
        case DT_REL:
        case DT_RELA: {
            // 动态重定位表地址
            if (!SetByOffset(rel_dyn_, base_addr_, bias_addr_, dynamic->d_un.d_ptr)) return;
            break;
        }
        case DT_RELSZ:
        case DT_RELASZ:
            // 动态重定位表大小
            rel_dyn_size_ = dynamic->d_un.d_val;
            break;
        case DT_ANDROID_REL:
        case DT_ANDROID_RELA: {
            // Android特有的压缩重定位表地址
            if (!SetByOffset(rel_android_, base_addr_, bias_addr_, dynamic->d_un.d_ptr)) return;
            break;
        }
        case DT_ANDROID_RELSZ:
        case DT_ANDROID_RELASZ:
            // Android压缩重定位表大小
            rel_android_size_ = dynamic->d_un.d_val;
            break;
        case DT_HASH: {
            // 传统ELF哈希表，如果存在GNU哈希表则忽略
            if (bloom_) continue;
            auto *raw = reinterpret_cast<ElfW(Word) *>(bias_addr_ + dynamic->d_un.d_ptr);
            bucket_count_ = raw[0];
            bucket_ = raw + 2;
            chain_ = bucket_ + bucket_count_;
            break;
        }
        case DT_GNU_HASH: {
            // GNU哈希表，性能更优的符号查找算法
            auto *raw = reinterpret_cast<ElfW(Word) *>(bias_addr_ + dynamic->d_un.d_ptr);
            bucket_count_ = raw[0];
            sym_offset_ = raw[1];
            bloom_size_ = raw[2];
            bloom_shift_ = raw[3];
            bloom_ = reinterpret_cast<decltype(bloom_)>(raw + 4);
            bucket_ = reinterpret_cast<decltype(bucket_)>(bloom_ + bloom_size_);
            chain_ = bucket_ + bucket_count_ - sym_offset_;
            //            is_use_gnu_hash_ = true;
            break;
        }
        default:
            break;
        }
    }

    // 检查Android压缩重定位表格式
    if (0 != rel_android_) {
        const auto *rel = reinterpret_cast<const char *>(rel_android_);
        // 检查APS2魔数标识
        if (rel_android_size_ < 4 || rel[0] != 'A' || rel[1] != 'P' || rel[2] != 'S' ||
            rel[3] != '2') {
            return;
        }

        // 跳过APS2头部
        rel_android_ += 4;
        rel_android_size_ -= 4;
    }

    // 标记ELF解析成功
    valid_ = true;
}

// GNU哈希表符号查找算法
uint32_t Elf::GnuLookup(std::string_view name) const {
    static constexpr auto kBloomMaskBits = sizeof(ElfW(Addr)) * 8;
    static constexpr uint32_t kInitialHash = 5381;
    static constexpr uint32_t kHashShift = 5;

    if (!bucket_ || !bloom_) return 0;

    // 计算符号名称的哈希值
    uint32_t hash = kInitialHash;
    for (unsigned char chr : name) {
        hash += (hash << kHashShift) + chr;
    }

    // 使用Bloom过滤器进行快速预检
    auto bloom_word = bloom_[(hash / kBloomMaskBits) % bloom_size_];
    uintptr_t mask = 0 | uintptr_t{1} << (hash % kBloomMaskBits) |
                     uintptr_t{1} << ((hash >> bloom_shift_) % kBloomMaskBits);
    if ((mask & bloom_word) == mask) {
        // 在桶中查找符号
        auto idx = bucket_[hash % bucket_count_];
        if (idx >= sym_offset_) {
            const char *strings = dyn_str_;
            do {
                auto *sym = dyn_sym_ + idx;
                // 比较哈希值和符号名称是否匹配
                if (((chain_[idx] ^ hash) >> 1) == 0 && name == strings + sym->st_name) {
                    return idx;
                }
            } while ((chain_[idx++] & 1) == 0);
        }
    }
    return 0;
}

// 传统ELF哈希表符号查找算法
uint32_t Elf::ElfLookup(std::string_view name) const {
    static constexpr uint32_t kHashMask = 0xf0000000;
    static constexpr uint32_t kHashShift = 24;
    uint32_t hash = 0;
    uint32_t tmp;

    // 如果存在GNU哈希表或桶为空则不使用传统哈希查找
    if (!bucket_ || bloom_) return 0;

    // 计算传统ELF哈希值
    for (unsigned char chr : name) {
        hash = (hash << 4) + chr;
        tmp = hash & kHashMask;
        hash ^= tmp;
        hash ^= tmp >> kHashShift;
    }
    const char *strings = dyn_str_;

    // 在哈希桶中查找符号
    for (auto idx = bucket_[hash % bucket_count_]; idx != 0; idx = chain_[idx]) {
        auto *sym = dyn_sym_ + idx;
        if (name == strings + sym->st_name) {
            return idx;
        }
    }
    return 0;
}

// 线性查找符号，当哈希表不可用时的备选方案
uint32_t Elf::LinearLookup(std::string_view name) const {
    if (!dyn_sym_ || !sym_offset_) return 0;
    // 遍历所有符号进行匹配
    for (uint32_t idx = 0; idx < sym_offset_; idx++) {
        auto *sym = dyn_sym_ + idx;
        if (name == dyn_str_ + sym->st_name) {
            return idx;
        }
    }
    return 0;
}

// 查找符号在PLT表中的地址
std::vector<uintptr_t> Elf::FindPltAddr(std::string_view name) const {
    std::vector<uintptr_t> res;

    // 依次尝试不同的符号查找算法
    uint32_t idx = GnuLookup(name);
    if (!idx) idx = ElfLookup(name);
    if (!idx) idx = LinearLookup(name);
    if (!idx) return res;

    // 遍历重定位表的通用处理函数
    auto looper = [&]<typename T>(auto begin, auto size, bool is_plt) -> void {
        const auto *rel_end = reinterpret_cast<const T *>(begin + size);
        for (const auto *rel = reinterpret_cast<const T *>(begin); rel < rel_end; ++rel) {
            auto r_info = rel->r_info;
            auto r_offset = rel->r_offset;
            auto r_sym = ELF_R_SYM(r_info);
            auto r_type = ELF_R_TYPE(r_info);
            // 检查符号索引是否匹配
            if (r_sym != idx) continue;
            // PLT表只关心JUMP_SLOT类型的重定位
            if (is_plt && r_type != ELF_R_GENERIC_JUMP_SLOT) continue;
            // 动态重定位表关心ABS和GLOB_DAT类型
            if (!is_plt && r_type != ELF_R_GENERIC_ABS && r_type != ELF_R_GENERIC_GLOB_DAT) {
                continue;
            }
            auto addr = bias_addr_ + r_offset;
            if (addr > base_addr_) res.emplace_back(addr);
            // PLT表找到第一个就退出
            if (is_plt) break;
        }
    };

    // 遍历所有重定位表查找符号地址
    for (const auto &[rel, rel_size, is_plt] :
         {std::make_tuple(rel_plt_, rel_plt_size_, true),
          std::make_tuple(rel_dyn_, rel_dyn_size_, false),
          std::make_tuple(rel_android_, rel_android_size_, false)}) {
        if (!rel) continue;
        // 根据重定位类型选择相应的处理函数
        if (is_use_rela_) {
            looper.template operator()<ElfW(Rela)>(rel, rel_size, is_plt);
        } else {
            looper.template operator()<ElfW(Rel)>(rel, rel_size, is_plt);
        }
    }

    return res;
}
