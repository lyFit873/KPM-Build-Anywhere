// ==========================================
// 0. 盘古开天：手动定义所有基础 C 语言类型 (ARM64)
// ==========================================
#define NULL ((void *)0)
typedef unsigned long size_t;
typedef unsigned long uintptr_t;
typedef unsigned long phys_addr_t;
typedef unsigned long dma_addr_t;

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef unsigned int u32;
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef unsigned long long u64;

typedef int bool;
#define true 1
#define false 0

// 彻底抛弃模板头文件，强制映射 KPM 底层符号
#define KPM_INIT(fn) int kpi_init(void)
#define KPM_CTL0(fn) int kpi_ctl0(char *arg)
#define KPM_EXIT(fn) void kpi_exit(void)

// ==========================================
// 1. 无头文件生存指南：手搓必需的底层结构
// ==========================================
struct hlist_node { struct hlist_node *next, **pprev; };
struct hlist_head { struct hlist_node *first; };
struct list_head { struct list_head *next, *prev; };
typedef struct { volatile unsigned int slock; } raw_spinlock_t;
typedef u32 kprobe_opcode_t;

struct kprobe; struct pt_regs;
typedef int (*kprobe_pre_handler_t) (struct kprobe *, struct pt_regs *);
typedef void (*kprobe_post_handler_t) (struct kprobe *, struct pt_regs *, unsigned long flags);
typedef int (*kprobe_fault_handler_t) (struct kprobe *, struct pt_regs *, int trapnr);

struct kprobe {
    struct hlist_node hlist;
    struct list_head list;
    unsigned long nmissed;
    phys_addr_t addr;
    const char *symbol_name;
    unsigned int offset;
    kprobe_pre_handler_t pre_handler;
    kprobe_post_handler_t post_handler;
    kprobe_fault_handler_t fault_handler;
    kprobe_opcode_t opcode;
};

struct kretprobe_instance; struct kretprobe;
typedef int (*kretprobe_handler_t) (struct kretprobe_instance *, struct pt_regs *);

struct kretprobe {
    struct kprobe kp;
    kretprobe_handler_t handler;
    kretprobe_handler_t entry_handler;
    int maxactive;
    int nmissed;
    size_t data_size;
    struct hlist_head free_instances;
    raw_spinlock_t lock;
};

struct kretprobe_instance {
    struct hlist_node hlist;
    struct kretprobe *rp;
    kprobe_opcode_t *ret_addr;
    void *task;
    char data[0];
};

extern int register_kprobe(struct kprobe *p);
extern void unregister_kprobe(struct kprobe *p);
extern int register_kretprobe(struct kretprobe *rp);
extern void unregister_kretprobe(struct kretprobe *rp);
extern unsigned long kallsyms_lookup_name(const char *name);

// ==========================================
// 2. 动态函数指针 (绕过环境检查)
// ==========================================
static int (*p_cam_mem_get_cpu_buf)(int32_t buf_handle, uintptr_t *vaddr_ptr, size_t *len) = NULL;
static void *(*p_vmalloc)(unsigned long size) = NULL;
static void (*p_vfree)(const void *addr) = NULL;
static unsigned long (*p__copy_to_user)(void *to, const void *from, unsigned long n) = NULL;
static void *(*p_memcpy)(void *dest, const void *src, size_t n) = NULL;
static void *(*p_memset)(void *s, int c, size_t n) = NULL;

// ==========================================
// 3. 核心业务逻辑与状态机
// ==========================================
#define CAM_NUM_OUT_PER_COMP_IRQ_MAX 6
struct cam_isp_hw_done_event_data {
    uint32_t num_handles;
    uint32_t resource_handle[CAM_NUM_OUT_PER_COMP_IRQ_MAX];
    uint32_t last_consumed_addr[CAM_NUM_OUT_PER_COMP_IRQ_MAX]; 
    uint64_t timestamp;
};

#define MAX_MAP_ENTRIES 256
struct iova_map_entry { uint32_t iova; int32_t buf_handle; };
static struct iova_map_entry iova_map[MAX_MAP_ENTRIES];
static int map_idx = 0;
static int map_lock = 0; // 手写原子锁

static void record_iova_mapping(uint32_t iova, int32_t handle) {
    while (__sync_lock_test_and_set(&map_lock, 1)); 
    iova_map[map_idx].iova = iova;
    iova_map[map_idx].buf_handle = handle;
    map_idx = (map_idx + 1) % MAX_MAP_ENTRIES;
    __sync_lock_release(&map_lock);
}

static int32_t lookup_buf_handle(uint32_t iova) {
    int i; int32_t handle = 0;
    while (__sync_lock_test_and_set(&map_lock, 1));
    for (i = 0; i < MAX_MAP_ENTRIES; i++) {
        int idx = (map_idx - 1 - i + MAX_MAP_ENTRIES) % MAX_MAP_ENTRIES;
        if (iova_map[idx].iova == iova) { handle = iova_map[idx].buf_handle; break; }
    }
    __sync_lock_release(&map_lock);
    return handle;
}

// 状态控制
static volatile int capture_status = 0; // 0:空闲, 1:等待抓取, 2:抓取完成
static volatile int tamper_enabled = 0;
static bool hooks_installed = false;
static void *cached_frame = NULL;
static size_t cached_size = 0;
#define MAX_FRAME_SIZE (80 * 1024 * 1024) // 80MB

// ==========================================
// 4. 双 Hook 实现
// ==========================================
struct hook_a_data { int32_t buf_handle; dma_addr_t *iova_ptr; };

static int entry_cam_mem_get_io_buf(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct hook_a_data *data = (struct hook_a_data *)ri->data;
    u64 *x = (u64 *)regs; 
    data->buf_handle = (int32_t)x[0];
    data->iova_ptr = (dma_addr_t *)x[2];
    return 0;
}

static int ret_cam_mem_get_io_buf(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct hook_a_data *data = (struct hook_a_data *)ri->data;
    if (data->iova_ptr) {
        dma_addr_t iova = *(data->iova_ptr); 
        record_iova_mapping((uint32_t)iova, data->buf_handle);
    }
    return 0;
}

static struct kretprobe krp_get_io_buf = {
    .handler = ret_cam_mem_get_io_buf,
    .entry_handler = entry_cam_mem_get_io_buf,
    .data_size = sizeof(struct hook_a_data),
    .maxactive = 32,
    .kp.symbol_name = "cam_mem_get_io_buf",
};

static int pre_vfe_out_done(struct kprobe *p, struct pt_regs *regs) {
    struct cam_isp_hw_done_event_data *evt;
    uint32_t iova, buf_handle;
    uintptr_t vaddr = 0; size_t len = 0;
    u64 *x = (u64 *)regs;

    if ((capture_status == 0 && !tamper_enabled) || !p_cam_mem_get_cpu_buf) return 0;

    evt = (struct cam_isp_hw_done_event_data *)x[1]; 
    if (!evt || evt->num_handles == 0 || evt->num_handles > CAM_NUM_OUT_PER_COMP_IRQ_MAX) return 0;

    iova = evt->last_consumed_addr[0];
    buf_handle = lookup_buf_handle(iova);

    if (buf_handle != 0 && p_cam_mem_get_cpu_buf(buf_handle, &vaddr, &len) == 0 && vaddr != 0) {
        
        // [修改画面]
        if (tamper_enabled && p_memset) {
            size_t wipe_offset = len / 3;
            size_t wipe_size = len / 16;
            if (wipe_offset + wipe_size <= len) {
                p_memset((void *)(vaddr + wipe_offset), 0x00, wipe_size);
            }
        }

        // [截获画面]
        if (capture_status == 1 && cached_frame && p_memcpy) {
            size_t copy_len = len > MAX_FRAME_SIZE ? MAX_FRAME_SIZE : len;
            p_memcpy(cached_frame, (void *)vaddr, copy_len);
            cached_size = copy_len;
            capture_status = 2; // 通知用户态准备就绪
        }
    }
    return 0; 
}

static struct kprobe kp_vfe_out_done = {
    .symbol_name = "cam_vfe_bus_ver3_handle_vfe_out_done_bottom_half",
    .pre_handler = pre_vfe_out_done,
};

// ==========================================
// 5. KPM 极简通信接口
// ==========================================
KPM_INIT(cam_kpm_init) { return 0; }

KPM_CTL0(cam_kpm_control0) {
    if (!arg) return -1;
    char cmd = arg[0];

    // 初始化 Hook 和环境
    if (cmd == '1' && !hooks_installed) {
        p_cam_mem_get_cpu_buf = (void *)kallsyms_lookup_name("cam_mem_get_cpu_buf");
        p_vmalloc = (void *)kallsyms_lookup_name("vmalloc");
        p_vfree = (void *)kallsyms_lookup_name("vfree");
        p__copy_to_user = (void *)kallsyms_lookup_name("_copy_to_user");
        p_memcpy = (void *)kallsyms_lookup_name("memcpy");
        p_memset = (void *)kallsyms_lookup_name("memset");

        if (!p_cam_mem_get_cpu_buf || !p_vmalloc || !p__copy_to_user) return -1;

        if (!cached_frame) cached_frame = p_vmalloc(MAX_FRAME_SIZE);
        
        register_kretprobe(&krp_get_io_buf);
        register_kprobe(&kp_vfe_out_done);
        hooks_installed = true;
        return 0;
    }
    else if (cmd == 'c' && hooks_installed) {
        capture_status = 1;
        return 0;
    }
    else if (cmd == 't' && hooks_installed) {
        tamper_enabled = !tamper_enabled;
        return 0;
    }
    else if (cmd == 'r' && hooks_installed) {
        if (capture_status != 2) return -11; 

        unsigned long user_addr = 0;
        int i = 2; 
        while (arg[i]) {
            char c = arg[i];
            if (c == '\n' || c == '\r') break;
            user_addr <<= 4;
            if (c >= '0' && c <= '9') user_addr |= (c - '0');
            else if (c >= 'a' && c <= 'f') user_addr |= (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') user_addr |= (c - 'A' + 10);
            else break;
            i++;
        }

        if (user_addr && cached_size > 0) {
            uint64_t size_header = (uint64_t)cached_size;
            p__copy_to_user((void *)user_addr, &size_header, 8);
            if (p__copy_to_user((void *)(user_addr + 8), cached_frame, cached_size) == 0) {
                capture_status = 0; 
                return 0; 
            }
        }
        return -1;
    }
    return 0;
}

KPM_EXIT(cam_kpm_exit) {
    if (hooks_installed) {
        unregister_kretprobe(&krp_get_io_buf);
        unregister_kprobe(&kp_vfe_out_done);
    }
    if (cached_frame && p_vfree) p_vfree(cached_frame);
}
