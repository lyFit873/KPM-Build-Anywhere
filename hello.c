#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
// 假设你的 KPM 模板提供了这些头文件
// #include "kputils.h" 
// #include "common.h"

// ==========================================
// 1. 高通 Camera 数据结构定义 (根据交接文档还原)
// ==========================================
#define CAM_NUM_OUT_PER_COMP_IRQ_MAX 6

struct cam_isp_hw_done_event_data {
    uint32_t num_handles;
    uint32_t resource_handle[CAM_NUM_OUT_PER_COMP_IRQ_MAX];
    uint32_t last_consumed_addr[CAM_NUM_OUT_PER_COMP_IRQ_MAX]; // IOVA
    uint64_t timestamp;
};

// ==========================================
// 2. IOVA <-> buf_handle 映射表 (Hook A 维护)
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
    // 逆序查找，确保拿到最新绑定的 buffer
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
// 3. 用户态数据交互通道 (Misc Device)
// ==========================================
// (复用之前我们讨论好的 frame_queue 和 Waitqueue 逻辑)
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
// 4. 函数指针与 Hook 定义
// ==========================================
// 导出函数的指针
static int (*p_cam_mem_get_cpu_buf)(int32_t buf_handle, uintptr_t *vaddr_ptr, size_t *len) = NULL;

// Hook A: cam_mem_get_io_buf (Kretprobe)
struct hook_a_data { int32_t buf_handle; dma_addr_t *iova_ptr; };

static int entry_cam_mem_get_io_buf(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct hook_a_data *data = (struct hook_a_data *)ri->data;
    data->buf_handle = (int32_t)regs->regs[0];
    data->iova_ptr = (dma_addr_t *)regs->regs[2];
    return 0;
}

static int ret_cam_mem_get_io_buf(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct hook_a_data *data = (struct hook_a_data *)ri->data;
    dma_addr_t iova = 0;
    
    // 从指针中读取高通驱动分配的真实 IOVA (使用 copy_from_kernel_nofault 防止崩溃)
    if (data->iova_ptr) {
        copy_from_kernel_nofault(&iova, data->iova_ptr, sizeof(iova));
        // 取低32位记录 (因为 last_consumed_addr 是 uint32_t)
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

// Hook B: cam_vfe_bus_ver3_handle_vfe_out_done_bottom_half (Kprobe)
static int pre_vfe_out_done(struct kprobe *p, struct pt_regs *regs) {
    struct cam_isp_hw_done_event_data *evt;
    uint32_t iova, buf_handle;
    uintptr_t vaddr = 0;
    size_t len = 0;
    struct frame_node *new_node;

    if (!capture_enabled || !p_cam_mem_get_cpu_buf) return 0;

    evt = (struct cam_isp_hw_done_event_data *)regs->regs[1]; // 参数2: evt_payload_priv
    if (!evt || evt->num_handles == 0 || evt->num_handles > CAM_NUM_OUT_PER_COMP_IRQ_MAX) return 0;

    // 这里我们只取第一个 handle，通常 RDI (Raw Dump) 会在其中
    iova = evt->last_consumed_addr[0];
    buf_handle = lookup_buf_handle(iova);

    if (buf_handle != 0) {
        if (p_cam_mem_get_cpu_buf(buf_handle, &vaddr, &len) == 0 && vaddr != 0) {
            // 成功拿到虚拟地址，拷贝数据放入队列
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
                    
                    // 抓到一帧后自动关闭，防止内存瞬间被海量高帧率 RAW 撑爆
                    capture_enabled = false; 
                } else {
                    kfree(new_node);
                }
            }
        } else {
            // 如果走到这里，说明交接文档里提到的 CAM_MEM_FLAG_KMD_ACCESS 标志位缺失问题真的发生了！
            pr_err("[KPM] cam_mem_get_cpu_buf 拒绝访问 handle 0x%x\n", buf_handle);
        }
    }
    return 0; // 允许原函数继续执行
}

static struct kprobe kp_vfe_out_done = {
    .symbol_name = "cam_vfe_bus_ver3_handle_vfe_out_done_bottom_half",
    .pre_handler = pre_vfe_out_done,
};

static bool hooks_installed = false;

// ==========================================
// 5. KPM 模板接口实现
// ==========================================

KPM_INIT(cam_kpm_init) {
    pr_info("[KPM] OnePlus 相机截获模块已加载。等待 CTL0 指令注入 Hook...\n");
    misc_register(&cam_dump_dev);
    return 0; // 不在这里挂钩，避免找不到符号
}

// 通过向 /sys/kpm/ctl0 写入指令交互 (KPM 框架自动提供)
KPM_CTL0(cam_kpm_control0) {
    char cmd[16];
    if (copy_from_user(cmd, arg, sizeof(cmd))) return -EFAULT;

    if (cmd[0] == '1' && !hooks_installed) {
        // 动态解析导出函数
        p_cam_mem_get_cpu_buf = (void *)kallsyms_lookup_name("cam_mem_get_cpu_buf");
        if (!p_cam_mem_get_cpu_buf) {
            pr_err("[KPM] 致命错误: 找不到 cam_mem_get_cpu_buf\n");
            return -EINVAL;
        }

        if (register_kretprobe(&krp_get_io_buf) < 0) pr_err("[KPM] Hook A 挂载失败\n");
        if (register_kprobe(&kp_vfe_out_done) < 0) pr_err("[KPM] Hook B 挂载失败\n");
        
        hooks_installed = true;
        pr_info("[KPM] 双 Hook 已成功挂载，准备就绪！\n");
        return 0;
    }
    
    if (cmd[0] == 'c' && hooks_installed) {
        // 触发一次抓帧 (安全机制：每次只抓一帧，防止内存 OOM)
        capture_enabled = true;
        pr_info("[KPM] 开启抓帧，等待下一帧到来...\n");
    }
    return 0;
}

KPM_EXIT(cam_kpm_exit) {
    if (hooks_installed) {
        unregister_kretprobe(&krp_get_io_buf);
        unregister_kprobe(&kp_vfe_out_done);
    }
    misc_deregister(&cam_dump_dev);
    pr_info("[KPM] 模块已卸载。\n");
}
