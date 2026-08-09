// ==========================================
// hello.c —— KPM 诊断版本(隔离测试用)
// 只做符号查找 + 打印,不做 hook,不做内存分配
// 用于确认 init 是否能正常跑完
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

// ==========================================
// 生命周期回调(诊断精简版)
// ==========================================
static long cam_kpm_init(const char *args, const char *event, void *reserved)
{
    pr_info("cam-raw-dump: step1 entered init\n");

    p_cam_mem_get_cpu_buf = (typeof(p_cam_mem_get_cpu_buf))kallsyms_lookup_name("cam_mem_get_cpu_buf");
    addr_get_io_buf = kallsyms_lookup_name("cam_mem_get_io_buf");
    addr_vfe_out_done = kallsyms_lookup_name("cam_vfe_bus_ver3_handle_vfe_out_done_bottom_half");

    pr_info("cam-raw-dump: step2 symbols cpu_buf=%p io_buf=%lx vfe_done=%lx\n",
            p_cam_mem_get_cpu_buf, addr_get_io_buf, addr_vfe_out_done);

    pr_info("cam-raw-dump: step3 init finished, kernelpatch version: %x\n", kpver);

    // 先直接返回成功,不做hook,不做malloc,方便隔离问题
    return 0;
}

static long cam_kpm_control0(const char *args, char *__user out_msg, int outlen)
{
    if (!args) return -1;

    char buf[128];
    snprintf(buf, sizeof(buf), "cpu_buf=%p io_buf=%lx vfe_done=%lx",
             p_cam_mem_get_cpu_buf, addr_get_io_buf, addr_vfe_out_done);
    compat_copy_to_user(out_msg, buf, strlen(buf) + 1);
    return 0;
}

static long cam_kpm_exit(void *reserved)
{
    pr_info("cam-raw-dump: exit\n");
    return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
