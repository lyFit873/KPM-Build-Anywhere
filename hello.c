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

// 手动定义需要的flag值(与内核fcntl.h一致,避免依赖可能缺失的头文件)
#define O_WRONLY   00000001
#define O_CREAT    00000100
#define O_TRUNC    00001000

#define CHUNK_SIZE (2 * 1024 * 1024)
static unsigned char chunk_buf[CHUNK_SIZE];

// 动态符号指针,类型对照真实内核函数签名手写
static void *(*p_filp_open)(const char *filename, int flags, unsigned short mode) = NULL;
static long (*p_kernel_write)(void *file, const void *buf, unsigned long count, long long *pos) = NULL;
static int (*p_filp_close)(void *filp, void *id) = NULL;

// IS_ERR的手动判断(内核里错误指针是把errno编码进高地址区间)
static int is_err_ptr(void *ptr)
{
    unsigned long addr = (unsigned long)ptr;
    return addr >= (unsigned long)-4095;
}

static long cam_kpm_init(const char *args, const char *event, void *reserved)
{
    pr_info("cam-raw-dump: step1 looking up file io symbols\n");

    p_filp_open = (void *)kallsyms_lookup_name("filp_open");
    p_kernel_write = (void *)kallsyms_lookup_name("kernel_write");
    p_filp_close = (void *)kallsyms_lookup_name("filp_close");

    pr_info("cam-raw-dump: step2 filp_open=%p kernel_write=%p filp_close=%p\n",
            p_filp_open, p_kernel_write, p_filp_close);

    if (!p_filp_open || !p_kernel_write || !p_filp_close) {
        pr_err("cam-raw-dump: symbol lookup failed\n");
        return -1;
    }

    // 测试写一个小文件,验证整条链路
    memset(chunk_buf, 'A', 64);  // 填一点测试数据

    void *f = p_filp_open("/data/local/tmp/kpm_test.txt",
                            O_CREAT | O_WRONLY | O_TRUNC, 0644);

    if (is_err_ptr(f)) {
        pr_err("cam-raw-dump: filp_open failed, ptr=%p\n", f);
        return -1;
    }

    pr_info("cam-raw-dump: step3 file opened, f=%p\n", f);

    long long pos = 0;
    long written = p_kernel_write(f, chunk_buf, 64, &pos);

    pr_info("cam-raw-dump: step4 written=%ld bytes\n", written);

    p_filp_close(f, NULL);

    pr_info("cam-raw-dump: step5 file closed, test complete\n");

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
