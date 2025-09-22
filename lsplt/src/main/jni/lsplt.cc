// LSPlant PLT Hook库主实现
// 提供Android上PLT Hook功能，支持动态可执行文件的函数拦截

#include "include/lsplt.hpp"

#include <sys/mman.h>
#include <sys/sysmacros.h>

#include <array>
#include <cinttypes>
#include <list>
#include <map>
#include <mutex>
#include <vector>

#include "elf_util.hpp"
#include "logging.hpp"
#include "syscall.hpp"

namespace {
const uintptr_t kPageSize = getpagesize();

inline auto PageStart(uintptr_t addr) {
    return reinterpret_cast<char *>(addr / kPageSize * kPageSize);
}

// 获取页面结束地址
inline auto PageEnd(uintptr_t addr) {
    return reinterpret_cast<char *>(reinterpret_cast<uintptr_t>(PageStart(addr)) + kPageSize);
}

// Hook注册信息结构
struct RegisterInfo {
    dev_t dev;
    ino_t inode;
    std::pair<uintptr_t, uintptr_t> offset_range;
    std::string symbol;
    void *callback;
    void **backup;
};

// Hook信息结构，继承自MapInfo
struct HookInfo : public lsplt::MapInfo {
    std::map<uintptr_t, uintptr_t> hooks; // Hook地址映射
    uintptr_t backup; // 备份地址
    std::unique_ptr<Elf> elf; // ELF解析器
    bool self; // 是否为自身模块
    [[nodiscard]] bool Match(const RegisterInfo &info) const {
        return info.dev == dev && info.inode == inode && offset >= info.offset_range.first &&
               offset < info.offset_range.second;
    }
};

// Hook信息管理类，继承自map容器，按地址降序排列
class HookInfos : public std::map<uintptr_t, HookInfo, std::greater<>> {
public:
    // 扫描系统内存映射信息，构建Hook信息表
    static auto ScanHookInfo() {
        static ino_t kSelfInode = 0;
        static dev_t kSelfDev = 0;
        HookInfos info;
        auto maps = lsplt::MapInfo::Scan();
        // 首次运行时确定自身模块的inode和设备号
        if (kSelfInode == 0) {
            auto self = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
            for (auto &map : maps) {
                if (self >= map.start && self < map.end) {
                    kSelfInode = map.inode;
                    kSelfDev = map.dev;
                    LOGV("self inode = %lu", kSelfInode);
                    break;
                }
            }
        }
        // 遍历内存映射，筛选可Hook的模块
        for (auto &map : maps) {
            // we basically only care about r-?p entry
            // and for offset == 0 it's an ELF header
            // and for offset != 0 it's what we hook
            // both of them should not be xom
            if (!map.is_private || !(map.perms & PROT_READ) || map.path.empty() ||
                map.path[0] == '[') {
                continue;
            }
            auto start = map.start;
            const bool self = map.inode == kSelfInode && map.dev == kSelfDev;
            info.emplace(start, HookInfo{{std::move(map)}, {}, 0, nullptr, self});
        }
        return info;
    }

    // 根据注册信息过滤Hook信息，移除不匹配的条目
    void Filter(const std::list<RegisterInfo> &register_info) {
        for (auto iter = begin(); iter != end();) {
            const auto &info = iter->second;
            bool matched = false;
            // 检查当前Hook信息是否与任何注册信息匹配
            for (const auto &reg : register_info) {
                if (info.Match(reg)) {
                    matched = true;
                    break;
                }
            }
            if (matched) {
                LOGV("Match hook info %s:%lu %" PRIxPTR " %" PRIxPTR "-%" PRIxPTR,
                     iter->second.path.data(), iter->second.inode, iter->second.start,
                     iter->second.end, iter->second.offset);
                ++iter;
            } else {
                iter = erase(iter);
            }
        }
    }

    // 合并旧的Hook信息到当前信息表中
    void Merge(HookInfos &old) {
        // merge with old map info
        for (auto &info : old) {
            if (info.second.backup) {
                erase(info.second.backup);
            }
            if (auto iter = find(info.first); iter != end()) {
                iter->second = std::move(info.second);
            } else if (info.second.backup) {
                emplace(info.first, std::move(info.second));
            }
        }
    }

    // 执行单个地址的Hook操作
    bool DoHook(uintptr_t addr, uintptr_t callback, uintptr_t *backup) {
        LOGV("Hooking %p", reinterpret_cast<void *>(addr));
        auto iter = lower_bound(addr);
        if (iter == end()) return false;
        // iter.first < addr
        auto &info = iter->second;
        if (info.end <= addr) return false;
        const auto len = info.end - info.start;
        // 如果还没有备份且不是自身模块，则创建备份
        if (!info.backup && !info.self) {
            // let os find a suitable address
            auto *backup_addr = sys_mmap(nullptr, len, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
            LOGD("Backup %p to %p", reinterpret_cast<void *>(addr), backup_addr);
            if (backup_addr == MAP_FAILED) return false;
            if (auto *new_addr =
                    sys_mremap(reinterpret_cast<void *>(info.start), len, len,
                               MREMAP_FIXED | MREMAP_MAYMOVE | MREMAP_DONTUNMAP, backup_addr);
                new_addr == MAP_FAILED || new_addr != backup_addr) {
                new_addr = sys_mremap(reinterpret_cast<void *>(info.start), len, len,
                           MREMAP_FIXED | MREMAP_MAYMOVE, backup_addr);
                if (new_addr == MAP_FAILED || new_addr != backup_addr) {
                    return false;
                }
                LOGD("Backup with MREMAP_DONTUNMAP failed, tried without it");
            }
            // 重新映射原始区域为可写
            if (auto *new_addr = sys_mmap(reinterpret_cast<void *>(info.start), len,
                                          PROT_READ | PROT_WRITE | info.perms,
                                          MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0);
                new_addr == MAP_FAILED) {
                return false;
            }
            // 复制备份内容到新映射区域
            for (uintptr_t src = reinterpret_cast<uintptr_t>(backup_addr), dest = info.start,
                           end = info.start + len;
                 dest < end; src += kPageSize, dest += kPageSize) {
                memcpy(reinterpret_cast<void *>(dest), reinterpret_cast<void *>(src), kPageSize);
            }
            info.backup = reinterpret_cast<uintptr_t>(backup_addr);
        }
        // 处理自身模块的Hook，直接修改权限
        if (info.self) {
            // self hooking, no need backup since we are always dirty
            if (!(info.perms & PROT_WRITE)) {
                info.perms |= PROT_WRITE;
                mprotect(reinterpret_cast<void *>(info.start), len, info.perms);
            }
        }
        // 执行实际的Hook操作
        auto *the_addr = reinterpret_cast<uintptr_t *>(addr);
        auto the_backup = *the_addr;
        if (*the_addr != callback) {
            *the_addr = callback;
            if (backup) *backup = the_backup;
            __builtin___clear_cache(PageStart(addr), PageEnd(addr));
        }
        // 更新Hook记录
        if (auto hook_iter = info.hooks.find(addr); hook_iter != info.hooks.end()) {
            if (hook_iter->second == callback) info.hooks.erase(hook_iter);
        } else {
            info.hooks.emplace(addr, the_backup);
        }
        // 如果没有Hook了且不是自身模块，恢复原始映射
        if (info.hooks.empty() && !info.self) {
            LOGD("Restore %p from %p", reinterpret_cast<void *>(info.start),
                 reinterpret_cast<void *>(info.backup));
            // Note that we have to always use sys_mremap here,
            // see
            // https://cs.android.com/android/_/android/platform/bionic/+/4200e260d266fd0c176e71fbd720d0bab04b02db
            if (auto *new_addr =
                    sys_mremap(reinterpret_cast<void *>(info.backup), len, len,
                               MREMAP_FIXED | MREMAP_MAYMOVE, reinterpret_cast<void *>(info.start));
                new_addr == MAP_FAILED || reinterpret_cast<uintptr_t>(new_addr) != info.start) {
                return false;
            }
            info.backup = 0;
        }
        return true;
    }

    // 批量执行Hook操作，处理注册的所有Hook信息
    bool DoHook(std::list<RegisterInfo> &register_info) {
        bool res = true;
        // 反向遍历Hook信息，从高地址到低地址
        for (auto info_iter = rbegin(); info_iter != rend(); ++info_iter) {
            auto &info = info_iter->second;
            // 遍历注册信息，查找匹配的Hook目标
            for (auto iter = register_info.begin(); iter != register_info.end();) {
                const auto &reg = *iter;
                // 检查偏移量和设备信息是否匹配
                if (info.offset != iter->offset_range.first || !info.Match(reg)) {
                    ++iter;
                    continue;
                }
                // 创建ELF解析器
                if (!info.elf) info.elf = std::make_unique<Elf>(info.start);
                if (info.elf && info.elf->Valid()) {
                    LOGD("Hooking %s", iter->symbol.data());
                    // 查找符号在PLT表中的地址并执行Hook
                    for (auto addr : info.elf->FindPltAddr(reg.symbol)) {
                        res = DoHook(addr, reinterpret_cast<uintptr_t>(reg.callback),
                                     reinterpret_cast<uintptr_t *>(reg.backup)) &&
                              res;
                    }
                }
                iter = register_info.erase(iter);
            }
        }
        return res;
    }

    // 失效备份内存，恢复原始内存映射
    bool InvalidateBackup() {
        bool res = true;
        for (auto &[_, info] : *this) {
            if (!info.backup) continue;
            // 更新Hook地址的备份值
            for (auto &[addr, backup] : info.hooks) {
                // store new address to backup since we don't need backup
                backup = *reinterpret_cast<uintptr_t *>(addr);
            }
            auto len = info.end - info.start;
            // 恢复原始内存映射
            if (auto *new_addr =
                    mremap(reinterpret_cast<void *>(info.backup), len, len,
                           MREMAP_FIXED | MREMAP_MAYMOVE, reinterpret_cast<void *>(info.start));
                new_addr == MAP_FAILED || reinterpret_cast<uintptr_t>(new_addr) != info.start) {
                res = false;
                info.hooks.clear();
                continue;
            }
            // 临时设置写权限以恢复原始函数地址
            if (!mprotect(PageStart(info.start), len, PROT_WRITE)) {
                for (auto &[addr, backup] : info.hooks) {
                    *reinterpret_cast<uintptr_t *>(addr) = backup;
                }
                mprotect(PageStart(info.start), len, info.perms);
            }
            info.hooks.clear();
            info.backup = 0;
        }
        return res;
    }
};

// 全局变量定义
std::mutex hook_mutex; // Hook操作互斥锁
std::list<RegisterInfo> register_info; // 注册的Hook信息列表
HookInfos hook_info; // Hook信息管理器
}  // namespace

namespace lsplt::inline v2 {
[[maybe_unused]] std::vector<MapInfo> MapInfo::Scan(std::string_view pid) {
    constexpr static auto kPermLength = 5;
    constexpr static auto kMapEntry = 7;
    std::vector<MapInfo> info;
    auto path = "/proc/" + std::string{pid} + "/maps";
    auto maps = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path.c_str(), "r"), &fclose};
    if (maps) {
        char *line = nullptr;
        size_t len = 0;
        ssize_t read;
        // 逐行解析maps文件
        while ((read = getline(&line, &len, maps.get())) > 0) {
            line[read - 1] = '\0';
            uintptr_t start = 0;
            uintptr_t end = 0;
            uintptr_t off = 0;
            ino_t inode = 0;
            unsigned int dev_major = 0;
            unsigned int dev_minor = 0;
            std::array<char, kPermLength> perm{'\0'};
            int path_off;
            // 解析内存映射行格式
            if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %x:%x %lu %n%*s", &start,
                       &end, perm.data(), &off, &dev_major, &dev_minor, &inode,
                       &path_off) != kMapEntry) {
                continue;
            }
            // 跳过路径前的空白字符
            while (path_off < read && isspace(line[path_off])) path_off++;
            auto &ref = info.emplace_back(start, end, 0, perm[3] == 'p', off,
                                          static_cast<dev_t>(makedev(dev_major, dev_minor)), inode,
                                          line + path_off);
            if (perm[0] == 'r') ref.perms |= PROT_READ;
            if (perm[1] == 'w') ref.perms |= PROT_WRITE;
            if (perm[2] == 'x') ref.perms |= PROT_EXEC;
        }
        free(line);
    }
    return info;
}

// 注册Hook，适用于整个设备文件的符号Hook
[[maybe_unused]] bool RegisterHook(dev_t dev, ino_t inode, std::string_view symbol, void *callback,
                                   void **backup) {
    if (dev == 0 || inode == 0 || symbol.empty() || !callback) return false;

    const std::unique_lock lock(hook_mutex);
    static_assert(std::numeric_limits<uintptr_t>::min() == 0);
    static_assert(std::numeric_limits<uintptr_t>::max() == -1);
    // 注册Hook信息，偏移范围覆盖整个地址空间
    [[maybe_unused]] const auto &info = register_info.emplace_back(
        dev, inode,
        std::pair{std::numeric_limits<uintptr_t>::min(), std::numeric_limits<uintptr_t>::max()},
        std::string{symbol}, callback, backup);

    LOGV("RegisterHook %lu %s", info.inode, info.symbol.data());
    return true;
}

// 注册Hook，适用于指定偏移范围内的符号Hook
[[maybe_unused]] bool RegisterHook(dev_t dev, ino_t inode, uintptr_t offset, size_t size,
                                   std::string_view symbol, void *callback, void **backup) {
    if (dev == 0 || inode == 0 || symbol.empty() || !callback) return false;

    const std::unique_lock lock(hook_mutex);
    static_assert(std::numeric_limits<uintptr_t>::min() == 0);
    static_assert(std::numeric_limits<uintptr_t>::max() == -1);
    // 注册Hook信息，指定偏移范围
    [[maybe_unused]] const auto &info = register_info.emplace_back(
        dev, inode, std::pair{offset, offset + size}, std::string{symbol}, callback, backup);

    LOGV("RegisterHook %lu %" PRIxPTR "-%" PRIxPTR " %s", info.inode, info.offset_range.first,
         info.offset_range.second, info.symbol.data());
    return true;
}

// 提交Hook操作，执行所有注册的Hook
[[maybe_unused]] bool CommitHook() {
    const std::unique_lock lock(hook_mutex);
    if (register_info.empty()) return true;

    // 扫描当前内存映射信息
    auto new_hook_info = HookInfos::ScanHookInfo();
    if (new_hook_info.empty()) return false;

    // 过滤匹配的Hook信息
    new_hook_info.Filter(register_info);

    // 合并旧的Hook信息
    new_hook_info.Merge(hook_info);
    // update to new map info
    hook_info = std::move(new_hook_info);

    // 执行Hook操作
    return hook_info.DoHook(register_info);
}

// 程序退出时自动调用的析构函数，用于清理备份内存
[[gnu::destructor]] [[maybe_unused]] bool InvalidateBackup() {
    const std::unique_lock lock(hook_mutex);
    return hook_info.InvalidateBackup();
}
}  // namespace lsplt::inline v2
