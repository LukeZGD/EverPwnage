// jailbreak.m from openpwnage

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <UIKit/UIKit.h>
#include <sys/mount.h>
#include <spawn.h>
#include <sys/sysctl.h>
#include <sys/stat.h>

#include "jailbreak.h"
#include "mac_policy_ops.h"
#include "patchfinder8.h"
#include "tar.h"

#import "ViewController.h"

uint32_t pmaps[TTB_SIZE];
int pmapscnt = 0;

bool isA5orA5X(void) {
    if(strstr(ckernv, "S5L894")) {
        printf("A5(X) device\n");
        return true;
    }
    printf("A6(X) device\n");
    return false;
}

uint32_t rk32(uint32_t addr, task_t tfp0) {
    vm_size_t bytesRead=0;
    uint32_t ret = 0;
    vm_read_overwrite(tfp0,addr,4,(vm_address_t)&ret,&bytesRead);
    return ret;
}

void wk32(uint32_t addr, uint32_t value, task_t tfp0) {
    vm_write(tfp0,addr,(vm_offset_t)&value,4);
}

void wk16(uint32_t addr, uint32_t value, task_t tfp0) {
    vm_write(tfp0,addr,(vm_offset_t)&value,2);
}

void wk8(uint32_t addr, uint8_t value, task_t tfp0) {
    vm_write(tfp0,addr,(vm_offset_t)&value,1);
}

kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
void copyout(uint32_t to, void* from, size_t size, task_t tfp0) {
    mach_vm_write(tfp0, to, (vm_offset_t)from, (mach_msg_type_number_t)size);
}

uint32_t find_kernel_pmap(uintptr_t kernel_base) {
    uint32_t pmap_addr;

    if(isA5orA5X()) {
        printf("A5(X) ");
        if (strstr(ckernv, "3248.6") || strstr(ckernv, "3248.5") || strstr(ckernv, "3248.4")) {
            printf("9.3.x\n");
            pmap_addr = 0x3f6454;
        } else if (strstr(ckernv, "3248.31") || strstr(ckernv, "3248.21")) {
            printf("9.2-9.2.1\n");
            pmap_addr = 0x3ef444;
        } else if (strstr(ckernv, "3248.10")) {
            printf("9.1\n");
            pmap_addr = 0x3f8444;
        } else if (strstr(ckernv, "3248.1.") || strstr(ckernv, "3247.1.88")) {
            printf("9.0-9.0.2\n");
            pmap_addr = 0x3f7444;
        } else if (strstr(ckernv, "2784")) {
            printf("8.3-8.4.1\n");
            pmap_addr = 0x3a211c;
        } else if (strstr(ckernv, "2783.5")) {
            printf("8.2\n");
            pmap_addr = 0x39411c;
        } else if (strstr(ckernv, "2783.3.26")) {
            printf("8.1.3\n");
            pmap_addr = 0x39211c;
        } else {
            printf("8.0-8.1.2\n");
            pmap_addr = 0x39111c;
        }
    } else {
        printf("A6(X) ");
        if (strstr(ckernv, "3248.6") || strstr(ckernv, "3248.5") || strstr(ckernv, "3248.4")) {
            printf("9.3.x\n");
            pmap_addr = 0x3fe454;
        } else if (strstr(ckernv, "3248.31") || strstr(ckernv, "3248.21")) {
            printf("9.2-9.2.1\n");
            pmap_addr = 0x3f6444;
        } else if (strstr(ckernv, "3248.10")) {
            printf("9.1\n");
            pmap_addr = 0x3ff444;
        } else if (strstr(ckernv, "3248.1.") || strstr(ckernv, "3247.1.88")) {
            printf("9.0-9.0.2\n");
            pmap_addr = 0x3fd444;
        } else if (strstr(ckernv, "2784")) {
            printf("8.3-8.4.1\n");
            pmap_addr = 0x3a711c;
        } else if (strstr(ckernv, "2783.5")) {
            printf("8.2\n");
            pmap_addr = 0x39a11c;
        } else {
            printf("8.0-8.1.3\n");
            pmap_addr = 0x39711c;
        }
    }
    printf("using offset 0x%08x for pmap\n",pmap_addr);
    return pmap_addr + kernel_base;
}

// debugger 1 and 2 for a5(x) 9.x
uint32_t find_PE_i_can_has_debugger_1(void) {
    uint32_t PE_i_can_has_debugger_1;
    if (strstr(ckernv, "3248.60")) {
        printf("9.3.3-9.3.4\n");
        PE_i_can_has_debugger_1 = 0x3a82d4;
    } else if (strstr(ckernv, "3248.50")) {
        printf("9.3.2\n");
        PE_i_can_has_debugger_1 = 0x3a7ff4;
    } else if (strstr(ckernv, "3248.41")) {
        printf("9.3-9.3.1\n");
        PE_i_can_has_debugger_1 = 0x3a7ea4;
    } else if (strstr(ckernv, "3248.31")) {
        printf("9.2.1\n");
        PE_i_can_has_debugger_1 = 0x3a1434;
    } else if (strstr(ckernv, "3248.21")) {
        printf("9.2\n");
        PE_i_can_has_debugger_1 = 0x3a12c4;
    } else if (strstr(ckernv, "3248.10")) {
        printf("9.1\n");
        PE_i_can_has_debugger_1 = 0x3aa734;
    } else {
        printf("9.0-9.0.2\n");
        PE_i_can_has_debugger_1 = 0x3a8fc4;
    }
    return PE_i_can_has_debugger_1;
}

uint32_t find_PE_i_can_has_debugger_2(void) {
    uint32_t PE_i_can_has_debugger_2;
    if (strstr(ckernv, "3248.6") || strstr(ckernv, "3248.5") || strstr(ckernv, "3248.4")) {
        printf("9.3.x\n");
        PE_i_can_has_debugger_2 = 0x456070;
    } else if (strstr(ckernv, "3248.31") || strstr(ckernv, "3248.21")) {
        printf("9.2-9.2.1\n");
        PE_i_can_has_debugger_2 = 0x44f070;
    } else if (strstr(ckernv, "3248.10")) {
        printf("9.1\n");
        PE_i_can_has_debugger_2 = 0x457860;
    } else {
        printf("9.0-9.0.2\n");
        PE_i_can_has_debugger_2 = 0x4567d0;
    }
    return PE_i_can_has_debugger_2;
}

void patch_kernel_pmap(task_t tfp0, uintptr_t kernel_base) {
    uint32_t kernel_pmap         = find_kernel_pmap(kernel_base);
    uint32_t kernel_pmap_store   = rk32(kernel_pmap,tfp0);
    uint32_t tte_virt            = rk32(kernel_pmap_store,tfp0);
    uint32_t tte_phys            = rk32(kernel_pmap_store+4,tfp0);

    printf("kernel pmap store @ 0x%08x\n",
            kernel_pmap_store);
    printf("kernel pmap tte is at VA 0x%08x PA 0x%08x\n",
            tte_virt,
            tte_phys);

    /*
     *  every page is writable
     */
    uint32_t i;
    for (i = 0; i < TTB_SIZE; i++) {
        uint32_t addr   = tte_virt + (i << 2);
        uint32_t entry  = rk32(addr,tfp0);
        if (entry == 0) continue;
        if ((entry & 0x3) == 1) {
            /*
             *  if the 2 lsb are 1 that means there is a second level
             *  pagetable that we need to give readwrite access to.
             *  zero bytes 0-10 to get the pagetable address
             */
            uint32_t second_level_page_addr = (entry & (~0x3ff)) - tte_phys + tte_virt;
            for (int i = 0; i < 256; i++) {
                /*
                 *  second level pagetable has 256 entries, we need to patch all
                 *  of them
                 */
                uint32_t sladdr  = second_level_page_addr+(i<<2);
                uint32_t slentry = rk32(sladdr,tfp0);

                if (slentry == 0)
                    continue;

                /*
                 *  set the 9th bit to zero
                 */
                uint32_t new_entry = slentry & (~0x200);
                if (slentry != new_entry) {
                    wk32(sladdr, new_entry,tfp0);
                    pmaps[pmapscnt++] = sladdr;
                }
            }
            continue;
        }

        if ((entry & L1_SECT_PROTO) == 2) {
            uint32_t new_entry  =  L1_PROTO_TTE(entry);
            new_entry           &= ~L1_SECT_APX;
            wk32(addr, new_entry,tfp0);
        }
    }

    printf("every page is actually writable\n");
    usleep(100000);
}

bool is_pmap_patch_success(task_t tfp0, uintptr_t kernel_base) {
    patch_kernel_pmap(tfp0, kernel_base);

    uint32_t before = -1;
    uint32_t after = -1;

    printf("check pmap patch\n");

    before = rk32(kernel_base, tfp0);
    wk32(kernel_base, 0x41414141, tfp0);
    after = rk32(kernel_base, tfp0);
    wk32(kernel_base, before, tfp0);

    if ((before != after) && (after == 0x41414141)) {
        printf("pmap patched!\n");
    } else {
        printf("pmap patch failed\n");
        return false;
    }
    return true;
}

void run_cmd(char *cmd, ...) {
    pid_t pid;
    va_list ap;
    char* cmd_ = NULL;

    va_start(ap, cmd);
    vasprintf(&cmd_, cmd, ap);

    char *argv[] = {"sh", "-c", cmd_, NULL};

    int status;
    printf("Run command: %s\n", cmd_);
    status = posix_spawn(&pid, "/bin/sh", NULL, NULL, argv, NULL);
    if (status == 0) {
        printf("Child pid: %i\n", pid);
        do {
            if (waitpid(pid, &status, 0) != -1) {
                printf("Child status %d\n", WEXITSTATUS(status));
            } else {
                perror("waitpid");
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
    } else {
        printf("posix_spawn: %s\n", strerror(status));
    }
}

void run_tar(char *cmd, ...) {
    pid_t pid;
    va_list ap;
    char* cmd_ = NULL;

    va_start(ap, cmd);
    vasprintf(&cmd_, cmd, ap);

    char *argv[] = {"/bin/tar", "-xf", cmd_, "-C", "/", "--preserve-permissions", "--no-overwrite-dir", NULL};

    int status;
    printf("Run command: %s\n", cmd_);
    status = posix_spawn(&pid, "/bin/tar", NULL, NULL, argv, NULL);
    if (status == 0) {
        printf("Child pid: %i\n", pid);
        do {
            if (waitpid(pid, &status, 0) != -1) {
                printf("Child status %d\n", WEXITSTATUS(status));
            } else {
                perror("waitpid");
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
    } else {
        printf("posix_spawn: %s\n", strerror(status));
        exit(1);
    }
}

void dump_kernel(mach_port_t tfp0, vm_address_t kernel_base, uint8_t *dest, size_t ksize) {
    for (vm_address_t addr = kernel_base, e = 0; addr < kernel_base + ksize; addr += CHUNK_SIZE, e += CHUNK_SIZE) {
        pointer_t buf = 0;
        vm_address_t sz = 0;
        vm_read(tfp0, addr, CHUNK_SIZE, &buf, &sz);
        if (buf == 0 || sz == 0)
            continue;
        bcopy((uint8_t *)buf, dest + e, CHUNK_SIZE);
    }
}

void patch_kernel(mach_port_t tfp0, uint32_t kernel_base) {
    printf("unsandboxing...\n");
    
    uint8_t* kdata = NULL;
    size_t ksize = 0xFFE000;
    kdata = malloc(ksize);
    dump_kernel(tfp0, kernel_base, kdata, ksize);
    if (!kdata) {
        printf("f\n");
        exit(1);
    }
    printf("now...\n");
    
    uint32_t sbopsoffset = find_sbops(kernel_base, kdata, ksize);

    printf("nuking sandbox\n");
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_access), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_create), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_notify_create), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_open), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_link), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exec), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_stat), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_rename), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_file_check_mmap), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_cred_label_update_execve), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_mount_check_stat), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_proc_check_fork), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattr), 0,tfp0);
    wk32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_iokit_check_get_property), 0,tfp0);
    printf("nuked sandbox\n");
    printf("let's go for code exec...\n");
    
    uint32_t tfp0_patch = find_tfp0_patch(kernel_base, kdata, ksize);
    uint32_t mapForIO = find_mapForIO(kernel_base, kdata, ksize);
    uint32_t sandbox_call_i_can_has_debugger = find_sandbox_call_i_can_has_debugger8(kernel_base, kdata, ksize);
    uint32_t proc_enforce8 = find_proc_enforce8(kernel_base, kdata, ksize);
    uint32_t vm_fault_enter = find_vm_fault_enter_patch_84(kernel_base, kdata, ksize);
    uint32_t vm_map_enter8 = find_vm_map_enter_patch8(kernel_base, kdata, ksize);
    uint32_t vm_map_protect8 = find_vm_map_protect_patch_84(kernel_base, kdata, ksize);
    uint32_t csops8 = find_csops8(kernel_base, kdata, ksize);
    uint32_t cs_enforcement_disable_amfi = find_cs_enforcement_disable_amfi8(kernel_base, kdata, ksize);
    uint32_t mount_common = find_mount8(kernel_base, kdata, ksize);
    uint32_t PE_i_can_has_debugger_1 = find_i_can_has_debugger_1(kernel_base, kdata, ksize);
    uint32_t PE_i_can_has_debugger_2 = find_i_can_has_debugger_2(kernel_base, kdata, ksize);
    uint32_t csops2 = find_csops2(kernel_base, kdata, ksize);

    printf("patching mount_common at 0x%08x\n", kernel_base + mount_common);
    wk8(kernel_base + mount_common + 1, 0xe0, tfp0);
        
    printf("patching cs_enforcement_disable_amfi - 4\n");
    wk8(kernel_base + cs_enforcement_disable_amfi - 4, 1, tfp0);

    printf("patching csops2 at 0x%08x\n", kernel_base + csops2);
    wk8(kernel_base + csops2, 0x20, tfp0);

    printf("patching tfp0 at 0x%08x\n", kernel_base + tfp0_patch);
    wk32(kernel_base + tfp0_patch, 0xbf00bf00, tfp0);

    printf("patching mapForIO at 0x%08x\n", kernel_base + mapForIO);
    wk32(kernel_base + mapForIO, 0xbf00bf00,tfp0);

    printf("patching cs_enforcement_disable_amfi at 0x%08x\n", kernel_base + cs_enforcement_disable_amfi - 1);
    wk8(kernel_base + cs_enforcement_disable_amfi, 1, tfp0);
    
    printf("patching PE_i_can_has_debugger_1 at 0x%08x\n", kernel_base + PE_i_can_has_debugger_1);
    wk32(kernel_base + PE_i_can_has_debugger_1, 1, tfp0);
    
    printf("patching PE_i_can_has_debugger_2 at 0x%08x\n", kernel_base + PE_i_can_has_debugger_2);
    wk32(kernel_base + PE_i_can_has_debugger_2, 1, tfp0);
    
    printf("patching sandbox_call_i_can_has_debugger at 0x%08x\n", kernel_base + sandbox_call_i_can_has_debugger);
    wk32(kernel_base + sandbox_call_i_can_has_debugger, 0xbf00bf00, tfp0);

    printf("patching proc_enforce at 0x%08x\n", kernel_base + proc_enforce8);
    wk8(kernel_base + proc_enforce8, 0, tfp0);

    printf("patching vm_fault_enter at 0x%08x\n", kernel_base + vm_fault_enter);
    wk32(kernel_base + vm_fault_enter, 0x2201bf00, tfp0);

    printf("patching vm_map_enter at 0x%08x\n", kernel_base + vm_map_enter8);
    wk32(kernel_base + vm_map_enter8, 0x4280bf00, tfp0);

    printf("patching vm_map_protect at 0x%08x\n", kernel_base + vm_map_protect8);
    wk32(kernel_base + vm_map_protect8, 0xbf00bf00, tfp0);

    printf("patching csops at 0x%08x\n", kernel_base + csops8);
    wk32(kernel_base + csops8, 0xbf00bf00, tfp0);
}

// sandbox stuff
// by xerub's iloader
unsigned int
make_b_w(int pos, int tgt)
{
    int delta;
    unsigned int i;
    unsigned short pfx;
    unsigned short sfx;

    unsigned int omask_1k = 0xB800;
    unsigned int omask_2k = 0xB000;
    unsigned int omask_3k = 0x9800;
    unsigned int omask_4k = 0x9000;

    unsigned int amask = 0x7FF;
    int range;

    range = 0x400000;

    delta = tgt - pos - 4; /* range: 0x400000 */
    i = 0;
    if(tgt > pos) i = tgt - pos - 4;
    if(tgt < pos) i = pos - tgt - 4;

    if (i < range){
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_1k | ((delta >>  1) & amask);

        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }

    if (range < i && i < range*2){ // range: 0x400000-0x800000
        delta -= range;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_2k | ((delta >>  1) & amask);

        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }

    if (range*2 < i && i < range*3){ // range: 0x800000-0xc000000
        delta -= range*2;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_3k | ((delta >>  1) & amask);

        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }

    if (range*3 < i && i < range*4){ // range: 0xc00000-0x10000000
        delta -= range*3;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_4k | ((delta >>  1) & amask);
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }

    return -1;
}

unsigned int
make_bl(int pos, int tgt)
{
    int delta;
    unsigned short pfx;
    unsigned short sfx;

    unsigned int omask = 0xF800;
    unsigned int amask = 0x07FF;

    delta = tgt - pos - 4; /* range: 0x400000 */
    pfx = 0xF000 | ((delta >> 12) & 0x7FF);
    sfx =  omask | ((delta >>  1) & amask);

    return (unsigned int)pfx | ((unsigned int)sfx << 16);
}

void patch_bootargs(uint32_t addr, task_t tfp0){
    //printf("set bootargs\n");
    uint32_t bootargs_addr = rk32(addr, tfp0) + 0x38;
    const char* new_bootargs = "cs_enforcement_disable=1 amfi_get_out_of_my_way=1";

    // evasi0n6
    size_t new_bootargs_len = strlen(new_bootargs) + 1;
    size_t bootargs_buf_len = (new_bootargs_len + 3) / 4 * 4;
    char bootargs_buf[bootargs_buf_len];

    strlcpy(bootargs_buf, new_bootargs, bootargs_buf_len);
    memset(bootargs_buf + new_bootargs_len, 0, bootargs_buf_len - new_bootargs_len);
    copyout(bootargs_addr, bootargs_buf, bootargs_buf_len, tfp0);
}

// unjail9 from daibutsu
void patch_kernel_90(mach_port_t tfp0, uint32_t kbase){
    printf("[*] jailbreaking...\n");

    printf("[*] running kdumper\n");
    uint8_t* kdata = NULL;
    size_t ksize = 0xFFE000;
    kdata = malloc(ksize);
    dump_kernel(tfp0, kbase, kdata, ksize);
    if (!kdata) {
        printf("fuck\n");
        exit(1);
    }
    printf("now...\n");

    /* patchfinder */
    printf("[*] running patchfinder\n");
    uint32_t proc_enforce = kbase + find_proc_enforce8(kbase, kdata, ksize);
    uint32_t cs_enforcement_disable_amfi = kbase + find_cs_enforcement_disable_amfi8(kbase, kdata, ksize);
    uint32_t p_bootargs = kbase + find_p_bootargs_generic(kbase, kdata, ksize);
    uint32_t vm_fault_enter = kbase + find_vm_fault_enter_patch(kbase, kdata, ksize);
    uint32_t vm_map_enter = kbase + find_vm_map_enter_patch8(kbase, kdata, ksize);
    uint32_t vm_map_protect = kbase + find_vm_map_protect_patch(kbase, kdata, ksize);
    uint32_t sandbox_call_i_can_has_debugger = kbase + find_sandbox_call_i_can_has_debugger8(kbase, kdata, ksize);
    uint32_t sb_patch = kbase + find_sb_evaluate_90(kbase, kdata, ksize);
    uint32_t memcmp_addr = find_memcmp8(kbase, kdata, ksize);
    uint32_t vn_getpath = find_vn_getpath8(kbase, kdata, ksize);
    uint32_t csops_addr = kbase + find_csops8(kbase, kdata, ksize);
    uint32_t amfi_file_check_mmap = kbase + find_amfi_file_check_mmap(kbase, kdata, ksize);
    uint32_t PE_i_can_has_debugger_1;
    uint32_t PE_i_can_has_debugger_2;
    uint32_t mount_patch;
    uint32_t mapForIO;
    uint32_t i_can_has_kernel_configuration_got;
    uint32_t lwvm_jump;

    if (isA5orA5X()) {
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
        printf("[PF] i_can_has_kernel_configuration_got: %08x\n", i_can_has_kernel_configuration_got);
        printf("[PF] lwvm_jump:                  %08x\n", lwvm_jump);
    } else {
        mapForIO = kbase + find_mapForIO(kbase, kdata, ksize);
        printf("[PF] mapForIO:                   %08x\n", mapForIO);
    }

    printf("[PF] proc_enforce:               %08x\n", proc_enforce);
    printf("[PF] cs_enforcement_disable:     %08x\n", cs_enforcement_disable_amfi);
    printf("[PF] PE_i_can_has_debugger_1:    %08x\n", PE_i_can_has_debugger_1);
    printf("[PF] PE_i_can_has_debugger_2:    %08x\n", PE_i_can_has_debugger_2);
    printf("[PF] p_bootargs:                 %08x\n", p_bootargs);
    printf("[PF] vm_fault_enter:             %08x\n", vm_fault_enter);
    printf("[PF] vm_map_enter:               %08x\n", vm_map_enter);
    printf("[PF] vm_map_protect:             %08x\n", vm_map_protect);
    printf("[PF] mount_patch:                %08x\n", mount_patch);
    printf("[PF] sb_call_i_can_has_debugger: %08x\n", sandbox_call_i_can_has_debugger);
    printf("[PF] sb_evaluate:                %08x\n", sb_patch);
    printf("[PF] memcmp:                     %08x\n", memcmp_addr);
    printf("[PF] vn_getpath:                 %08x\n", vn_getpath);
    printf("[PF] csops:                      %08x\n", csops_addr);
    printf("[PF] amfi_file_check_mmap:       %08x\n", amfi_file_check_mmap);

    printf("[*] running kernelpatcher\n");

    /* proc_enforce: -> 0 */
    printf("[*] proc_enforce\n");
    wk32(proc_enforce, 0, tfp0);

    /* cs_enforcement_disable = 1 && amfi_get_out_of_my_way = 1 */
    printf("[*] cs_enforcement_disable_amfi\n");
    wk8(cs_enforcement_disable_amfi, 1, tfp0);
    wk8(cs_enforcement_disable_amfi-1, 1, tfp0);

    /* bootArgs */
    printf("[*] bootargs\n");
    patch_bootargs(p_bootargs, tfp0);

    /* debug_enabled -> 1 */
    printf("[*] debug_enabled\n");
    wk32(PE_i_can_has_debugger_1, 1, tfp0);
    wk32(PE_i_can_has_debugger_2, 1, tfp0);

    /* vm_fault_enter */
    printf("[*] vm_fault_enter\n");
    wk16(vm_fault_enter, 0x2201, tfp0);

    /* vm_map_enter */
    printf("[*] vm_map_enter\n");
    wk32(vm_map_enter, 0xbf00bf00, tfp0);

    /* vm_map_protect: set NOP */
    printf("[*] vm_map_protect\n");
    wk32(vm_map_protect, 0xbf00bf00, tfp0);

    /* mount patch */
    printf("[*] mount patch\n");
    if (strstr(ckernv, "3248.1.")) {
        wk8(mount_patch, 0xe7, tfp0);
    } else {
        wk8(mount_patch, 0xe0, tfp0);
    }

    /* mapForIO: prevent kIOReturnLockedWrite error */
    printf("[*] mapForIO\n");
    if (strstr(ckernv, "3248.6") || strstr(ckernv, "3248.5") || strstr(ckernv, "3248.4")) {
        wk32(i_can_has_kernel_configuration_got, lwvm_jump, tfp0);
    } else {
        wk32(mapForIO, 0xbf00bf00, tfp0);
    }

    /* csops */
    printf("[*] csops\n");
    wk32(csops_addr, 0xbf00bf00, tfp0);

    /* amfi_file_check_mmap */
    printf("[*] amfi_file_check_mmap\n");
    wk32(amfi_file_check_mmap, 0xbf00bf00, tfp0);

    /* sandbox */
    printf("[*] sandbox\n");
    wk32(sandbox_call_i_can_has_debugger, 0xbf00bf00, tfp0);

    /* sb_evaluate */
    unsigned char pangu9_payload[] = {
        0x1f, 0xb5, 0xad, 0xf5, 0x82, 0x6d, 0x1c, 0x6b, 0x01, 0x2c, 0x34, 0xd1,
        0x5c, 0x6b, 0x00, 0x2c, 0x31, 0xd0, 0x69, 0x46, 0x5f, 0xf4, 0x80, 0x60,
        0x0d, 0xf5, 0x80, 0x62, 0x10, 0x60, 0x20, 0x46, 0x11, 0x11, 0x11, 0x11,
        0x1c, 0x28, 0x01, 0xd0, 0x00, 0x28, 0x24, 0xd1, 0x68, 0x46, 0x17, 0xa1,
        0x10, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x28, 0x1d, 0xd0, 0x68, 0x46,
        0x0f, 0xf2, 0x5c, 0x01, 0x13, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x28,
        0x0d, 0xd1, 0x68, 0x46, 0x18, 0xa1, 0x31, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x00, 0x28, 0x0e, 0xd0, 0x68, 0x46, 0x22, 0xa1, 0x27, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x00, 0x28, 0x07, 0xd1, 0x0d, 0xf5, 0x82, 0x6d, 0x01, 0xbc,
        0x00, 0x21, 0x01, 0x60, 0x18, 0x21, 0x01, 0x71, 0x1e, 0xbd, 0x0d, 0xf5,
        0x82, 0x6d, 0x05, 0x98, 0x86, 0x46, 0x1f, 0xbc, 0x01, 0xb0, 0xcc, 0xcc,
        0xcc, 0xcc, 0xdd, 0xdd, 0xdd, 0xdd, 0x00, 0xbf, 0x2f, 0x70, 0x72, 0x69,
        0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x72, 0x2f, 0x74, 0x6d, 0x70,
        0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x72,
        0x2f, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x00, 0x2f, 0x70, 0x72, 0x69,
        0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x72, 0x2f, 0x6d, 0x6f, 0x62,
        0x69, 0x6c, 0x65, 0x2f, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2f,
        0x50, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x2f,
        0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x00, 0x00, 0xbf,
        0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x72,
        0x2f, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x2f, 0x4c, 0x69, 0x62, 0x72,
        0x61, 0x72, 0x79, 0x2f, 0x50, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e,
        0x63, 0x65, 0x73, 0x00, 0x02, 0x00, 0x00, 0x00
    };

    uint32_t payload_base = 0xb00; // taig8
    size_t payload_len = 0x110;

    uint32_t vn_getpath_bl = make_bl(payload_base+0x20, vn_getpath);
    uint32_t memcmp_bl_1 = make_bl(payload_base+0x32, memcmp_addr);
    uint32_t memcmp_bl_2 = make_bl(payload_base+0x42, memcmp_addr);
    uint32_t memcmp_bl_3 = make_bl(payload_base+0x50, memcmp_addr);
    uint32_t memcmp_bl_4 = make_bl(payload_base+0x5e, memcmp_addr);
    uint32_t sb_evaluate_val = rk32(sb_patch, tfp0);
    uint32_t back_sb_evaluate = make_b_w(payload_base+0x86, (sb_patch+4-kbase));

    *(uint32_t*)(pangu9_payload+0x20) = vn_getpath_bl;
    *(uint32_t*)(pangu9_payload+0x32) = memcmp_bl_1;
    *(uint32_t*)(pangu9_payload+0x42) = memcmp_bl_2;
    *(uint32_t*)(pangu9_payload+0x50) = memcmp_bl_3;
    *(uint32_t*)(pangu9_payload+0x5e) = memcmp_bl_4;
    *(uint32_t*)(pangu9_payload+0x82) = sb_evaluate_val;
    *(uint32_t*)(pangu9_payload+0x86) = back_sb_evaluate;

    void* sandbox_payload = malloc(payload_len);
    memcpy(sandbox_payload, pangu9_payload, payload_len);

    if (strstr(ckernv, "3248.1")) { // 9.0-9.1
        // hook sb_evaluate
        printf("[*] sb_evaluate\n");
        copyout((kbase + payload_base), sandbox_payload, payload_len, tfp0);
        printf("[*] sb_evaluate_hook\n");
        uint32_t sb_evaluate_hook = make_b_w((sb_patch-kbase), payload_base);
        wk32(sb_patch, sb_evaluate_hook, tfp0);
    } else { // 9.2-9.3.4
        uint32_t sbopsoffset = kbase + find_sbops(kbase, kdata, ksize);
        printf("nuking sandbox\n");
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_rename), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_access), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_create), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_file_check_mmap), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exec), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_link), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_open), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_stat), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_notify_create), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattr), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_mount_check_stat), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_proc_check_fork), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_iokit_check_get_property), 0,tfp0);
        wk32(sbopsoffset + offsetof(struct mac_policy_ops, mpo_cred_label_update_execve), 0,tfp0);
    }

    printf("[*] patch tfp0\n");
    uint32_t tfp0_patch = kbase + find_tfp0_patch(kbase, kdata, ksize);
    printf("[PF] tfp0_patch: %08x\n", tfp0_patch);
    wk32(tfp0_patch, 0xbf00bf00, tfp0);

    printf("enable patched.\n");
}

char *getFilePath(const char *fileName) {
    NSString *filePathObj = [[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:[NSString stringWithUTF8String:fileName]];
    return [filePathObj UTF8String];
}

void postjailbreak(bool untether_on) {
    printf("[*] remounting rootfs\n");
    char* nmr = strdup("/dev/disk0s1s1");
    int mntr = mount("hfs", "/", MNT_UPDATE, &nmr);
    printf("remount = %d\n",mntr);
    while (mntr != 0) {
        mntr = mount("hfs", "/", MNT_UPDATE, &nmr);
        printf("remount = %d\n",mntr);
        usleep(100000);
    }
    sync();

    bool InstallBootstrap = false;
    if (!((access("/.installed-openpwnage", F_OK) != -1) || (access("/.installed_everpwnage", F_OK) != -1) ||
          (access("/.installed_home_depot", F_OK) != -1) || (access("/untether/untether", F_OK) != -1) ||
          (access("/.installed_daibutsu", F_OK) != -1)) || reinstall_strap) {
        printf("installing bootstrap...\n");

        FILE *f1 = fopen("/bin/tar", "wb");
        if (f1) {
            size_t r1 = fwrite(tar, sizeof tar[0], tar_len, f1);
            printf("wrote %zu elements out of %d requested\n", r1,  tar_len);
            fclose(f1);
        }

        chmod("/bin/tar", 0777);
        printf("chmod'd tar_path\n");

        printf("extracting bootstrap\n");
        run_tar("%s", getFilePath("bootstrap.tar"));

        printf("disabling stashing\n");
        run_cmd("/bin/touch /.cydia_no_stash");

        printf("copying launchctl\n");
        run_cmd("/bin/cp -p %s /bin/launchctl", getFilePath("launchctl"));

        printf("fixing perms...\n");
        chmod("/bin/tar", 0755);
        chmod("/bin/launchctl", 0755);
        chmod("/private", 0777);
        chmod("/private/var", 0777);
        chmod("/private/var/mobile", 0777);
        chmod("/private/var/mobile/Library", 0777);
        chmod("/private/var/mobile/Library/Preferences", 0777);
        mkdir("/Library/LaunchDaemons", 0755);
        FILE* fp = fopen("/private/etc/apt/sources.list.d/LukeZGD.list", "w");
        fprintf(fp, "deb https://lukezgd.github.io/repo ./\n");
        fclose(fp);
        fp = fopen("/.installed_everpwnage", "w");
        fprintf(fp, "do **NOT** delete this file, it's important. it's how we detect if the bootstrap was installed.\n");
        fclose(fp);

        sync();

        printf("bootstrap installed\n");
        InstallBootstrap = true;
    } else {
        printf("bootstrap already installed\n");
    }

    printf("allowing jailbreak apps to be shown\n");
    NSMutableDictionary *md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
    [md setObject:[NSNumber numberWithBool:YES] forKey:@"SBShowNonDefaultSystemApps"];
    [md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];

    printf("restarting cfprefs\n");
    run_cmd("/usr/bin/killall -9 cfprefsd &");

    if (install_openssh) {
        printf("extracting openssh\n");
        run_tar("%s", getFilePath("openssh.tar"));
    }

    printf("loading launch daemons\n");
    run_cmd("/bin/launchctl load /Library/LaunchDaemons/*");
    run_cmd("/etc/rc.d/*");

    if (InstallBootstrap) {
        printf("running uicache\n");
        run_cmd("su -c uicache mobile");
    }

    if (untether_on) {
        if (strstr(ckernv, "3248") || strstr(ckernv, "3247") ||
            strstr(ckernv, "2784.30") || (isA5orA5X() && strstr(ckernv, "2783"))) {
            // all 9.x, 8.4, a5(x) 8.0-8.2
            printf("extracting everuntether\n");
            run_tar(getFilePath("everuntether.tar"));
        } else {
            // a6(x) 8.x, a5(x) 8.3-8.4.1
            printf("extracting daibutsu untether\n");
            run_tar(getFilePath("untether.tar"));
        }
        printf("running postinst\n");
        run_cmd("/bin/bash /private/var/tmp/postinst configure");
        printf("done.");
        return;
    }

    FILE* fp = fopen("/tmp/.jailbroken", "w");
    fprintf(fp, "jailbroken.\n");
    fclose(fp);

    printf("respringing\n");
    run_cmd("(killall -9 backboardd) &");

    return;
}
