//
//  ViewController.m
//  ios8-jailbreak
//
//  Created by lukezgd on 12/14/24.
//  Copyright © 2024 lukezgd. All rights reserved.
//

#import "ViewController.h"

#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include "daibutsu/jailbreak.h"
#include "postjailbreak.h"
#include "oob_entry/oob_entry.h"
#include "oob_entry/memory.h"

@interface ViewController ()

@property (weak, nonatomic) IBOutlet UIButton *jailbreak_button;
@property (weak, nonatomic) IBOutlet UISwitch *tweaks_toggle;
@property (weak, nonatomic) IBOutlet UILabel *title_label;
@property (weak, nonatomic) IBOutlet UILabel *version_label;
@property (weak, nonatomic) IBOutlet UILabel *deviceinfo_label;
@property (weak, nonatomic) IBOutlet UIButton *more_button;

@end

@implementation ViewController

NSString *system_machine;
NSString *system_version;
char *ckernv;
bool install_openssh = true;
bool reinstall_strap = false;
bool untether_on = true;
bool tweaks_on = true;
bool ios9 = false;

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    _title_label.text = @"EverPwnage";
    NSString *version = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    _version_label.text = [NSString stringWithFormat:@"v%@", version];

    struct utsname systemInfo;
    uname(&systemInfo);

    system_machine = [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding];
    system_version = [[UIDevice currentDevice] systemVersion];
    ckernv = strdup(systemInfo.version);
    print_log("%s\n", ckernv);

    _deviceinfo_label.text = [NSString stringWithFormat:@"%@ | iOS %@", system_machine, system_version];
    NSLog(@"Running on %@ with iOS %@", system_machine, system_version);

    // disable button and toggle if jailbroken/untether detected (everuntether is also detected as daibutsu)
    if (access("/daibutsu", F_OK) != -1 || (access("/everuntether", F_OK) != -1) ||
        access("/untether/untether", F_OK) != -1 || (access("/tmp/.jailbroken", F_OK) != -1)) {
        _tweaks_toggle.enabled = NO;
        [_tweaks_toggle setOn:NO];
        _jailbreak_button.enabled = NO;
        [_jailbreak_button setTitle:@"Jailbroken" forState:UIControlStateDisabled];
    }

    // enable jailbreak button if reinstall_strap is true
    if (reinstall_strap) {
        _tweaks_toggle.enabled = YES;
        [_tweaks_toggle setOn:YES];
        _jailbreak_button.enabled = YES;
        [_jailbreak_button setTitle:@"Jailbreak" forState:UIControlStateNormal];
        if (access("/daibutsu", F_OK) != -1 || access("/everuntether", F_OK) != -1 || access("/untether/untether", F_OK) != -1) {
            untether_on = false;
        }
    }

    // disable toggle if 9.3.5/6
    if (strstr(ckernv, "3248.61")) {
        untether_on = false;
    }

    // iOS 9.0-9.3.6
    if (strstr(ckernv, "3248") || strstr(ckernv, "3247.1.88")) {
        ios9 = true;
    }

    // iOS 8.0-9.3.6
    if (!(ios9 || strstr(ckernv, "2784") || strstr(ckernv, "2783"))) {
        _jailbreak_button.enabled = NO;
        [_jailbreak_button setTitle:@"Not Supported" forState:UIControlStateDisabled];
    }

    if (strstr(ckernv, "2423")) {
        _tweaks_toggle.enabled = NO;
        [_tweaks_toggle setOn:YES];
        _more_button.enabled = NO;
    }
}

- (IBAction)jailbreak_pressed:(id)sender {
    print_log("button pressed\n");

    _jailbreak_button.enabled = NO;
    [sender setTitle:@"Jailbreaking" forState:UIControlStateDisabled];

    // Ensure UI updates are applied
    dispatch_async(dispatch_get_main_queue(), ^{
        [self performSelector:@selector(jailbreak_begin) withObject:self];
    });
}

- (void)jailbreak_begin {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self jailbreak];
    });
}

- (void)jailbreak {
    print_log("[*] jailbreak\n");

    run_exploit();
    if (kinfo->tfp0 == 0) {
        print_log("failed to get tfp0 :(\n");
        exit(1);
    }
    print_log("[*] got tfp0: 0x%x\n", kinfo->tfp0);
    print_log("[*] kbase=0x%08lx\n", kinfo->kernel_base);

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
    if (getuid() != 0 || getgid() != 0) exit(1);

    print_log("[*] patching kernel...\n");
    jailbreak_init();
    if (ios9)
        unjail9();
    else
        unjail8();

    print_log("[*] time for postjailbreak...\n");
    tweaks_on = _tweaks_toggle.isOn;
    print_log("[*] untether_on: %d\n", untether_on);
    print_log("[*] tweaks_on: %d\n", tweaks_on);
    postjailbreak();

    dispatch_async(dispatch_get_main_queue(), ^{
        [self showCompletionAlert];
    });
}

// Show an alert after successful jailbreak
- (void)showCompletionAlert {
    if (@available(iOS 8, *)) {
        // iOS 8 and later
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Success"
                                                                       message:@"Jailbreak/untether is now done. Rebooting your device."
                                                                preferredStyle:UIAlertControllerStyleAlert];

        UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"OK"
                                                           style:UIAlertActionStyleDefault
                                                         handler:^(UIAlertAction *action) {
                                                             reboot(0);
                                                         }];
        [alert addAction:okAction];
        [self presentViewController:alert animated:YES completion:nil];
    } else {
        // iOS 7
        UIAlertView *alertView = [[UIAlertView alloc] initWithTitle:@"Success"
                                                            message:@"Jailbreak/untether is now done. Rebooting your device."
                                                           delegate:nil
                                                  cancelButtonTitle:@"OK"
                                                  otherButtonTitles:nil];
        [alertView show];
        // Reboot the device on button press
        alertView.delegate = self;
    }
}

// For iOS 7: handle the reboot in the alert view delegate method
- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex {
    if (buttonIndex == 0) { // "OK" button
        reboot(0);
    }
}

- (IBAction)showSettingsViewController:(id)sender {
    // Initialize the SettingsViewController
    UIStoryboard *storyboard = [UIStoryboard storyboardWithName:@"Main" bundle:nil];
    SettingsViewController *settingsVC = [storyboard instantiateViewControllerWithIdentifier:@"SettingsViewController"];
    settingsVC.delegate = self;

    // Check for iPad or iPhone
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        // iPad: Show as popover
        settingsVC.modalPresentationStyle = UIModalPresentationPopover;
        UIPopoverPresentationController *popover = settingsVC.popoverPresentationController;
        if (popover) {
            popover.sourceView = sender;
            popover.sourceRect = [sender bounds];
            popover.permittedArrowDirections = UIPopoverArrowDirectionAny;
            popover.delegate = settingsVC; // Assign popover delegate
        }
        [self presentViewController:settingsVC animated:YES completion:nil];
    } else {
        UINavigationController *navController = [[UINavigationController alloc] initWithRootViewController:settingsVC];
        [self presentViewController:navController animated:YES completion:nil];
    }
}

#pragma mark - SettingsViewControllerDelegate
- (void)didUpdateTogglesWithFirstToggle:(BOOL)firstToggle secondToggle:(BOOL)secondToggle untetherToggle:(BOOL)untetherToggle {
    // Update label with toggle values
    install_openssh = firstToggle;
    reinstall_strap = secondToggle;
    untether_on = untetherToggle;
    NSLog([NSString stringWithFormat:@"Toggle 1: %@, Toggle 2: %@, Toggle 3: %@",
           firstToggle ? @"ON" : @"OFF",
          secondToggle ? @"ON" : @"OFF",
        untetherToggle ? @"ON" : @"OFF"]);
    [self viewDidLoad];
}

@end
