#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>

KPM_NAME("cam-raw-dump");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("Camera RDI raw data extractor via VFE bus hook");

static long cam_kpm_init(const char *args, const char *event, void *reserved)
{
    pr_info("cam-raw-dump: step1 before lookup1\n");
    unsigned long addr1 = kallsyms_lookup_name("cam_mem_get_cpu_buf");
    pr_info("cam-raw-dump: step2 addr1=%lx\n", addr1);

    pr_info("cam-raw-dump: step3 before lookup2\n");
    unsigned long addr2 = kallsyms_lookup_name("cam_mem_get_io_buf");
    pr_info("cam-raw-dump: step4 addr2=%lx\n", addr2);

    pr_info("cam-raw-dump: step5 before lookup3\n");
    unsigned long addr3 = kallsyms_lookup_name("cam_vfe_bus_ver3_handle_vfe_out_done_bottom_half");
    pr_info("cam-raw-dump: step6 addr3=%lx\n", addr3);

    return 0;
}

static long cam_kpm_control0(const char *args, char *__user out_msg, int outlen)
{
    char echo[64] = "echo: ";
    strncat(echo, args, 48);
    compat_copy_to_user(out_msg, echo, sizeof(echo));
    return 0;
}

static long cam_kpm_exit(void *reserved)
{
    pr_info("cam-raw-dump exit\n");
    return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
