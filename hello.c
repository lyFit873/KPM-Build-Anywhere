#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

// 引入 KPM 模板核心头文件
#include "kputils.h"
#include "common.h"

// ==========================================
// 1. 暴力手搓 kprobes 结构体 (绕过残缺头文件限制)
// ==========================================
typedef u32 kprobe_opcode_t;
struct kprobe;
struct pt_regs;
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

struct kretprobe_instance;
struct kretprobe;
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

// 声明内核导出的 API
extern int register_kprobe(struct kprobe *p);
extern void unregister_kprobe(struct kprobe *p);
extern int register_kretprobe(struct kretprobe *rp);
extern void unregister_kretprobe(struct kretprobe *rp);

// ==========================================
// 2. 高通 Camera 数据结构定义
// ==========================================
#define CAM_NUM_OUT_PER_COMP_IRQ_MAX 6

struct cam_isp_hw_done_event_data {
    uint32_t num_handles;
    uint32_t resource_handle[CAM_NUM_OUT_PER_COMP_IRQ_MAX];
    uint32_t last_consumed_addr[CAM_NUM_OUT_PER_COMP_IRQ_MAX]; // IOVA
    uint64_t timestamp;
};

// ==========================================
// 3. IOVA <-> buf_handle 映射表 (Hook A 维护)
// ==========================================
#define MAX_MAP_ENTRIES 256
struct iova_map_entry {
    uint32_t iova;
    int32_t buf_handle;
};
static struct iova_map_entry iova_map[MAX_MAP_ENTRIES];
static int map_idx = 0;
static DEFINE_SPINLOCK(map_lock);

static void record_iova_mapping(uint32_t iova, int32_t handle) {
    spin_lock(&map_lock);
    iova_map[map_idx].iova = iova;
    iova_map[map_idx].buf_handle = handle;
    map_idx = (map_idx + 1) % MAX_MAP_ENTRIES;
    spin_unlock(&map_lock);
}

static int32_t lookup_buf_handle(uint32_t iova) {
    int i;
    int32_t handle = 0;
    spin_lock(&map_lock);
    for (i = 0; i < MAX_MAP_ENTRIES; i++) {
        int idx = (map_idx - 1 - i + MAX_MAP_ENTRIES) % MAX_MAP_ENTRIES;
        if (iova_map[idx].iova == iova) {
            handle = iova_map[idx].buf_handle;
            break;
        }
    }
    spin_unlock(&map_lock);
    return handle;
}

// ==========================================
// 4. 用户态数据交互通道 (Misc Device)
// ==========================================
struct frame_node {
    struct list_head list;
    void *data;
    size_t size;
    size_t read_offset;
};
static LIST_HEAD(frame_queue);
static DEFINE_SPINLOCK(queue_lock);
static DECLARE_WAIT_QUEUE_HEAD(cam_wait_queue);

static bool capture_enabled = false;
static bool tamper_enabled = false;
static bool hooks_installed = false;

static ssize_t cam_dump_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    struct frame_node *node = NULL;
    size_t copy_len;
    
    if (wait_event_interruptible(cam_wait_queue, !list_empty(&frame_queue)))
        return -ERESTARTSYS;

    spin_lock(&queue_lock);
    if (!list_empty(&frame_queue)) node = list_first_entry(&frame_queue, struct frame_node, list);
    spin_unlock(&queue_lock);
    if (!node) return 0;

    copy_len = min(count, node->size - node->read_offset);
    if (copy_to_user(buf, (char *)node->data + node->read_offset, copy_len)) return -EFAULT;

    node->read_offset += copy_len;
    if (node->read_offset >= node->size) {
        spin_lock(&queue_lock);
        list_del(&node->list);
        spin_unlock(&queue_lock);
        vfree(node->data);
        kfree(node);
    }
    return copy_len;
}
static const struct file_operations cam_dump_fops = { .owner = THIS_MODULE, .read = cam_dump_read };
static struct miscdevice cam_dump_dev = { .minor = MISC_DYNAMIC_MINOR, .name = "cam_raw_dump", .fops = &cam_dump_fops, .mode = 0666 };

// ==========================================
// 5. 函数指针与 Hook 定义
// ==========================================
static int (*p_cam_mem_get_cpu_buf)(int32_t buf_handle, uintptr_t *vaddr_ptr, size_t *len) = NULL;

// Hook A 传递结构
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
    dma_addr_t iova = 0;
    if (data->iova_ptr) {
        copy_from_kernel_nofault(&iova, data->iova_ptr, sizeof(iova));
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
    uintptr_t vaddr = 0;
    size_t len = 0;
    struct frame_node *new_node;
    u64 *x = (u64 *)regs;

    if ((!capture_enabled && !tamper_enabled) || !p_cam_mem_get_cpu_buf) return 0;

    evt = (struct cam_isp_hw_done_event_data *)x[1]; 
    if (!evt || evt->num_handles == 0 || evt->num_handles > CAM_NUM_OUT_PER_COMP_IRQ_MAX) return 0;

    iova = evt->last_consumed_addr[0];
    buf_handle = lookup_buf_handle(iova);

    if (buf_handle != 0) {
        if (p_cam_mem_get_cpu_buf(buf_handle, &vaddr, &len) == 0 && vaddr != 0) {
            
            // [功能：篡改画面]
            if (tamper_enabled) {
                size_t wipe_offset = len / 3;
                size_t wipe_size = len / 16;
                if (wipe_offset + wipe_size <= len) {
                    memset((void *)(vaddr + wipe_offset), 0x00, wipe_size);
                }
            }

            // [功能：抓取画面]
            if (capture_enabled) {
                new_node = kmalloc(sizeof(*new_node), GFP_ATOMIC);
                if (new_node) {
                    new_node->data = vmalloc(len);
                    if (new_node->data) {
                        memcpy(new_node->data, (void *)vaddr, len);
                        new_node->size = len;
                        new_node->read_offset = 0;

                        spin_lock(&queue_lock);
                        list_add_tail(&new_node->list, &frame_queue);
                        spin_unlock(&queue_lock);
                        wake_up_interruptible(&cam_wait_queue);
                        
                        capture_enabled = false; 
                    } else {
                        kfree(new_node);
                    }
                }
            }
        }
    }
    return 0; 
}

static struct kprobe kp_vfe_out_done = {
    .symbol_name = "cam_vfe_bus_ver3_handle_vfe_out_done_bottom_half",
    .pre_handler = pre_vfe_out_done,
};

// ==========================================
// 6. KPM 接口定义
// ==========================================

KPM_INIT(cam_kpm_init) {
    pr_info("[KPM] OnePlus Camera dump&tamper loaded.\n");
    misc_register(&cam_dump_dev);
    return 0; 
}

KPM_CTL0(cam_kpm_control0) {
    char cmd[16];
    if (copy_from_user(cmd, arg, sizeof(cmd))) return -EFAULT;

    if (cmd[0] == '1' && !hooks_installed) {
        p_cam_mem_get_cpu_buf = (void *)kallsyms_lookup_name("cam_mem_get_cpu_buf");
        if (!p_cam_mem_get_cpu_buf) return -EINVAL;

        register_kretprobe(&krp_get_io_buf);
        register_kprobe(&kp_vfe_out_done);
        hooks_installed = true;
        pr_info("[KPM] Hooks installed.\n");
    }
    else if (cmd[0] == 'c' && hooks_installed) {
        capture_enabled = true;
        pr_info("[KPM] Capture requested.\n");
    }
    else if (cmd[0] == 't' && hooks_installed) {
        tamper_enabled = !tamper_enabled;
        pr_info("[KPM] Tamper mode toggled.\n");
    }
    return 0;
}

KPM_EXIT(cam_kpm_exit) {
    if (hooks_installed) {
        unregister_kretprobe(&krp_get_io_buf);
        unregister_kprobe(&kp_vfe_out_done);
    }
    misc_deregister(&cam_dump_dev);
    pr_info("[KPM] Unloaded.\n");
}
