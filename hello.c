#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>

// 手动补充正确的函数原型声明,避免编译器把返回值当成 int 处理
// (之前编译日志确认了 kp_malloc 被隐式声明为返回 int,导致64位指针被截断)
extern void *kp_malloc(size_t size);
extern void kp_free(void *mem);

KPM_NAME("cam-raw-dump");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("Camera RDI raw data extractor via VFE bus hook");

#define MAX_FRAME_SIZE (32 * 1024 * 1024)
static void *cached_frame = NULL;

static long cam_kpm_init(const char *args, const char *event, void *reserved)
{
    pr_info("cam-raw-dump: step1 before malloc\n");
    cached_frame = kp_malloc(MAX_FRAME_SIZE);
    pr_info("cam-raw-dump: step2 after malloc, ptr=%p\n", cached_frame);

    if (!cached_frame) {
        pr_err("cam-raw-dump: malloc failed\n");
        return -1;
    }

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
    if (cached_frame)
        kp_free(cached_frame);
    pr_info("cam-raw-dump exit\n");
    return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
