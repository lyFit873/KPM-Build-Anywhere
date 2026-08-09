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

// 中转缓冲区,固定2MB,已验证稳定
#define CHUNK_SIZE (2 * 1024 * 1024)
static unsigned char chunk_buf[CHUNK_SIZE];

static long cam_kpm_init(const char *args, const char *event, void *reserved)
{
    pr_info("cam-raw-dump: step1 init, chunk_buf at %p, size=%d\n",
             chunk_buf, CHUNK_SIZE);
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
