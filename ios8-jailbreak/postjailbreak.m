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

#include "oob_entry/oob_entry.h"
#include "postjailbreak.h"
#include "tar.h"

#import "ViewController.h"

void run_cmd(char *cmd, ...) {
    pid_t pid;
    va_list ap;
    char* cmd_ = NULL;

    va_start(ap, cmd);
    vasprintf(&cmd_, cmd, ap);

    char *argv[] = {"sh", "-c", cmd_, NULL};

    int status;
    print_log("Run command: %s\n", cmd_);
    status = posix_spawn(&pid, "/bin/sh", NULL, NULL, argv, NULL);
    if (status == 0) {
        print_log("Child pid: %i\n", pid);
        do {
            if (waitpid(pid, &status, 0) != -1) {
                print_log("Child status %d\n", WEXITSTATUS(status));
            } else {
                perror("waitpid");
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
    } else {
        print_log("posix_spawn: %s\n", strerror(status));
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
    print_log("Run command: %s\n", cmd_);
    status = posix_spawn(&pid, "/bin/tar", NULL, NULL, argv, NULL);
    if (status == 0) {
        print_log("Child pid: %i\n", pid);
        do {
            if (waitpid(pid, &status, 0) != -1) {
                print_log("Child status %d\n", WEXITSTATUS(status));
            } else {
                perror("waitpid");
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
    } else {
        print_log("posix_spawn: %s\n", strerror(status));
        exit(1);
    }
}

char *getFilePath(const char *fileName) {
    NSString *filePathObj = [[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:[NSString stringWithUTF8String:fileName]];
    return [filePathObj UTF8String];
}

void postjailbreak(void) {
    print_log("[*] remounting rootfs\n");
    char* nmr = strdup("/dev/disk0s1s1");
    int mntr = mount("hfs", "/", MNT_UPDATE, &nmr);
    print_log("remount = %d\n",mntr);
    while (mntr != 0) {
        mntr = mount("hfs", "/", MNT_UPDATE, &nmr);
        print_log("remount = %d\n",mntr);
        usleep(100000);
    }
    sync();

    bool install_bootstrap = false;
    if (!((access("/.installed-openpwnage", F_OK) != -1) || (access("/.installed_everpwnage", F_OK) != -1) ||
          (access("/.installed_home_depot", F_OK) != -1) || (access("/untether/untether", F_OK) != -1) ||
          (access("/.installed_daibutsu", F_OK) != -1)) || reinstall_strap) {
        print_log("installing bootstrap...\n");

        FILE *f1 = fopen("/bin/tar", "wb");
        if (f1) {
            size_t r1 = fwrite(tar, sizeof tar[0], tar_len, f1);
            print_log("wrote %zu elements out of %d requested\n", r1,  tar_len);
            fclose(f1);
        }

        chmod("/bin/tar", 0777);
        print_log("chmod'd tar_path\n");

        print_log("extracting bootstrap\n");
        run_tar("%s", getFilePath("bootstrap.tar"));

        print_log("disabling stashing\n");
        run_cmd("/bin/touch /.cydia_no_stash");

        print_log("copying launchctl\n");
        run_cmd("/bin/cp -p %s /bin/launchctl", getFilePath("launchctl"));

        print_log("fixing perms...\n");
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

        print_log("bootstrap installed\n");
        install_bootstrap = true;
    } else {
        print_log("bootstrap already installed\n");
    }

    print_log("allowing jailbreak apps to be shown\n");
    NSMutableDictionary *md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
    [md setObject:[NSNumber numberWithBool:YES] forKey:@"SBShowNonDefaultSystemApps"];
    [md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];

    print_log("restarting cfprefs\n");
    run_cmd("/usr/bin/killall -9 cfprefsd &");

    if (install_openssh) {
        print_log("extracting openssh\n");
        run_tar("%s", getFilePath("openssh.tar"));
    }

    if (tweaks_on) {
        print_log("loading launch daemons\n");
        run_cmd("/bin/launchctl load /Library/LaunchDaemons/*");
        run_cmd("/etc/rc.d/*");
    }

    if (install_bootstrap) {
        print_log("running uicache\n");
        run_cmd("su -c uicache mobile");
    }

    if (untether_on) {
        print_log("extracting everuntether\n");
        run_tar(getFilePath("everuntether.tar"));
        print_log("done.");
        return;
    }

    FILE* fp = fopen("/tmp/.jailbroken", "w");
    fprintf(fp, "jailbroken.\n");
    fclose(fp);

    print_log("respringing\n");
    run_cmd("(killall -9 backboardd) &");

    return;
}
