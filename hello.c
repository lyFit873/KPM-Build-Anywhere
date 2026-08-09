// ==========================================
// hello.c —— KPM 摄像头 RDI 原始数据提取模块
// 基于 KernelPatch 官方 hook.h / kputils.h API
// ⚠️ 编译前必须核对: hook_fargs_t 系列结构体里访问
//    原函数参数值/返回值的具体字段名(本代码里标注为
//    TODO 的地方),对照 bmax121/KernelPatch 仓库
//    kpms/demo-inlinehook/ 目录下的真实示例源码
// ==========================================

#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/string.h>

KPM_NAME("cam-raw-dump");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("Camera RDI raw data extractor via VFE bus hook");

// ------------------------------------------
// 动态符号指针,init阶段通过kallsyms_lookup_name获取
// ------------------------------------------
static int (*p_cam_mem_get_cpu_buf)(int32_t buf_handle, uintptr_t *vaddr_ptr, size_t *len) = NULL;

static unsigned long addr_get_io_buf = 0;
static unsigned long addr_vfe_out_done = 0;

// ------------------------------------------
// IOVA -> buf_handle 映射表 (Hook A 写入, Hook B 查询)
// ------------------------------------------
#define MAX_MAP_ENTRIES 64
struct iova_map_entry { uint32_t iova; int32_t buf_handle; };
static struct iova_map_entry iova_map[MAX_MAP_ENTRIES];
static int map_idx = 0;

static void record_iova_mapping(uint32_t iova, int32_t handle)
{
    iova_map[map_idx].iova = iova;
    iova_map[map_idx].buf_handle = handle;
    map_idx = (map_idx + 1) % MAX_MAP_ENTRIES;
}

static int32_t lookup_buf_handle(uint32_t iova)
{
    int i;
    for (i = 0; i < MAX_MAP_ENTRIES; i++) {
        int idx = (map_idx - 1 - i + MAX_MAP_ENTRIES) % MAX_MAP_ENTRIES;
        if (iova_map[idx].iova == iova)
            return iova_map[idx].buf_handle;
    }
    return 0;
}

// ------------------------------------------
// 抓取状态机 + 帧缓冲(供 control0 导出用)
// ------------------------------------------
#define MAX_FRAME_SIZE (32 * 1024 * 1024)  // 先按32MB留,不够再调
static volatile int capture_status = 0;    // 0=空闲 1=等待抓取 2=已就绪
static void *cached_frame = NULL;
static size_t cached_size = 0;

// ==========================================
// Hook A: cam_mem_get_io_buf
// buf_handle(输入参数) -> IOVA(输出参数,一般是个指针参数)
// TODO: 确认 cam_mem_get_io_buf 的真实函数签名(参数个数/顺序),
//       对照 cam_mem_mgr.c 里 EXPORT_SYMBOL(cam_mem_get_io_buf)
//       上方的函数定义来核对参数个数,决定用 hook_wrap 几号参数变体
// ==========================================
static void before_get_io_buf(hook_fargs3_t *args, void *udata)
{
    // TODO: 确认参数访问字段名(可能是 args->arg0 或 args->args[0] 等,
    //       需要看 hook.h 里 hook_fargsN_t 的真实定义)
    // 这里先假设 args->arg0 = buf_handle (第一个参数)
    // 用 args->local.data0 把 buf_handle 暂存下来,供 after 阶段用
    args->local.data0 = args->arg0;
}

static void after_get_io_buf(hook_fargs3_t *args, void *udata)
{
    int32_t buf_handle = (int32_t)args->local.data0;
    // TODO: 确认输出参数(IOVA指针)在 hook_fargs 里怎么取,
    //       这里假设第三个参数是 dma_addr_t* 类型的输出指针 args->arg2
    dma_addr_t *iova_ptr = (dma_addr_t *)args->arg2;
    if (iova_ptr && buf_handle) {
        uint32_t iova = (uint32_t)(*iova_ptr);
        record_iova_mapping(iova, buf_handle);
    }
}

// ==========================================
// Hook B: cam_vfe_bus_ver3_handle_vfe_out_done_bottom_half
// 帧完成回调,从事件结构体里取 last_consumed_addr
// TODO: 确认这个函数的真实参数个数/顺序,来自
//       cam_vfe_bus_ver3.c 约2433行的函数定义
// ==========================================
#define CAM_NUM_OUT_PER_COMP_IRQ_MAX 6
struct cam_isp_hw_done_event_data {
    uint32_t num_handles;
    uint32_t resource_handle[CAM_NUM_OUT_PER_COMP_IRQ_MAX];
    uint32_t last_consumed_addr[CAM_NUM_OUT_PER_COMP_IRQ_MAX];
    uint64_t timestamp;
};

static void before_vfe_out_done(hook_fargs2_t *args, void *udata)
{
    // TODO: 确认 cam_isp_hw_done_event_data* 在参数列表第几位
    struct cam_isp_hw_done_event_data *evt =
        (struct cam_isp_hw_done_event_data *)args->arg1;

    if (capture_status != 1 || !evt || evt->num_handles == 0)
        return;
    if (!p_cam_mem_get_cpu_buf || !cached_frame)
        return;

    uint32_t iova = evt->last_consumed_addr[0];
    int32_t buf_handle = lookup_buf_handle(iova);
    if (!buf_handle)
        return;

    uintptr_t vaddr = 0;
    size_t len = 0;
    if (p_cam_mem_get_cpu_buf(buf_handle, &vaddr, &len) == 0 && vaddr) {
        size_t copy_len = len > MAX_FRAME_SIZE ? MAX_FRAME_SIZE : len;
        memcpy(cached_frame, (void *)vaddr, copy_len);
        cached_size = copy_len;
        capture_status = 2;
        pr_info("cam-raw-dump: frame captured, size=%zu\n", copy_len);
    }
}

// ==========================================
// 生命周期回调
// ==========================================
static long cam_kpm_init(const char *args, const char *event, void *reserved)
{
    p_cam_mem_get_cpu_buf = (typeof(p_cam_mem_get_cpu_buf))kallsyms_lookup_name("cam_mem_get_cpu_buf");
    addr_get_io_buf = kallsyms_lookup_name("cam_mem_get_io_buf");
    addr_vfe_out_done = kallsyms_lookup_name("cam_vfe_bus_ver3_handle_vfe_out_done_bottom_half");

    if (!p_cam_mem_get_cpu_buf || !addr_get_io_buf || !addr_vfe_out_done) {
        pr_err("cam-raw-dump: symbol lookup failed (cpu_buf=%p io_buf=%p vfe_done=%p)\n",
               p_cam_mem_get_cpu_buf, (void *)addr_get_io_buf, (void *)addr_vfe_out_done);
        return -1;
    }

    cached_frame = kp_malloc(MAX_FRAME_SIZE);
    if (!cached_frame) {
        pr_err("cam-raw-dump: alloc frame buffer failed\n");
        return -1;
    }

    // TODO: hook_wrap3 / hook_wrap2 的具体调用签名需对照 hook.h 核实
    hook_wrap3((void *)addr_get_io_buf, before_get_io_buf, after_get_io_buf, NULL);
    hook_wrap2((void *)addr_vfe_out_done, before_vfe_out_done, NULL, NULL);

    pr_info("cam-raw-dump: init ok, kernelpatch version: %x\n", kpver);
    return 0;
}

static long cam_kpm_control0(const char *args, char *__user out_msg, int outlen)
{
    if (!args) return -1;
    char cmd = args[0];

    if (cmd == 'c') {
        // 触发一次抓取
        capture_status = 1;
        compat_copy_to_user(out_msg, "capture armed", 15);
        return 0;
    }
    else if (cmd == 's') {
        // 查询状态
        char buf[32];
        snprintf(buf, sizeof(buf), "status=%d size=%zu", capture_status, cached_size);
        compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
        return 0;
    }
    else if (cmd == 'r') {
        // 读取:约定 args+2 开始是用户态传入的目标地址(hex字符串)
        // TODO: 这段用户态地址解析目前用compat_copy_to_user按块拷贝,
        //       如果一帧数据超过outlen需要分块传输,当前版本假设
        //       out_msg缓冲区足够大或者只做小尺寸测试验证用
        if (capture_status != 2) {
            compat_copy_to_user(out_msg, "not ready", 10);
            return -1;
        }
        // 仅做状态回传示例,真正大块数据导出建议改用落盘方案(见下方说明)
        compat_copy_to_user(out_msg, cached_frame, outlen < cached_size ? outlen : cached_size);
        capture_status = 0;
        return 0;
    }
    return 0;
}

static long cam_kpm_exit(void *reserved)
{
    if (addr_get_io_buf)
        unhook((void *)addr_get_io_buf);
    if (addr_vfe_out_done)
        unhook((void *)addr_vfe_out_done);
    if (cached_frame)
        kp_free(cached_frame);
    pr_info("cam-raw-dump: exit\n");
    return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
