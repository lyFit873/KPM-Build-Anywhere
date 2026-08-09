#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>

KPM_NAME("kpm-hello-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module Example");

static long hello_init(const char *args, const char *event, void *reserved)
{
    pr_info("hello init, event: %s, args: %s\n", event, args);
    pr_info("kernelpatch version: %x\n", kpver);
    return 0;
}

static long hello_control0(const char *args, char *__user out_msg, int outlen)
{
    char echo[64] = "echo: ";
    strncat(echo, args, 48);
    compat_copy_to_user(out_msg, echo, sizeof(echo));
    return 0;
}

static long hello_exit(void *reserved)
{
    pr_info("hello exit\n");
    return 0;
}

KPM_INIT(hello_init);
KPM_CTL0(hello_control0);
KPM_EXIT(hello_exit);
