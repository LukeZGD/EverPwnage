//
//  ViewController.m
//  ios8-jailbreak
//
//  Created by lukezgd on 12/14/24.
//  Copyright © 2024 lukezgd. All rights reserved.
//

#import "ViewController.h"

#import <sys/utsname.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#import "jailbreak.h"
#import "sock_port_2_legacy/sockpuppet.h"

@interface ViewController ()

@property (weak, nonatomic) IBOutlet UIButton *jailbreak_button;
@property (weak, nonatomic) IBOutlet UISwitch *untether_toggle;
@property (weak, nonatomic) IBOutlet UILabel *title_label;
@property (weak, nonatomic) IBOutlet UILabel *version_label;
@property (weak, nonatomic) IBOutlet UILabel *deviceinfo_label;

@end

@implementation ViewController

NSString *system_machine;
NSString *system_version;
char *ckernv;
bool install_openssh = false;
bool reinstall_strap = false;
bool ios9 = false;

addr_t self_port_address = 0;

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
    printf("%s\n", ckernv);

    _deviceinfo_label.text = [NSString stringWithFormat:@"%@ | iOS %@", system_machine, system_version];
    NSLog(@"Running on %@ with iOS %@", system_machine, system_version);

    // iOS 9.0-9.3.4
    if ((!strstr(ckernv, "3248.61") && strstr(ckernv, "3248")) || strstr(ckernv, "3247.1.88"))
        ios9 = true;

    // iOS 8.0-9.3.4
    if (!(ios9 || strstr(ckernv, "2784") || strstr(ckernv, "2783"))) {
        _jailbreak_button.enabled = NO;
        [_jailbreak_button setTitle:@"Not Supported" forState:UIControlStateDisabled];
    }

    // disable button and toggle if jailbroken/daibutsu detected (everuntether is also detected as daibutsu)
    if (access("/.installed_daibutsu", F_OK) != -1 || access("/tmp/.jailbroken", F_OK) != -1) {
        _untether_toggle.enabled = NO;
        [_untether_toggle setOn:NO];
        _jailbreak_button.enabled = NO;
        [_jailbreak_button setTitle:@"Jailbroken" forState:UIControlStateDisabled];
    }
}

- (IBAction)jailbreak_pressed:(id)sender {
    printf("button pressed\n");

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
    printf("jailbreak\n");

    mach_port_t tfp0;
    uint32_t kernel_base;
    tfp0 = exploit(&kernel_base);
    if (tfp0 == 0) {
        printf("failed to get tfp0 :(\n");
        exit(1);
    }
    printf("[*]got tfp0: 0x%x\n", tfp0);
    printf("[*]kbase=0x%08lx\n", kernel_base);

    if (is_pmap_patch_success(tfp0, kernel_base)) {
        printf("pmap patch success!\n");
    } else {
        printf("pmap patch failed :(\n");
        exit(1);
    }

    printf("patching kernel...\n");
    if (ios9)
        patch_kernel_90(tfp0, kernel_base);
    else
        patch_kernel(tfp0, kernel_base);

    printf("time for postjailbreak...\n");
    postjailbreak(_untether_toggle.isOn);

    dispatch_async(dispatch_get_main_queue(), ^{
        [self showCompletionAlert];
    });
}

// Show an alert after successful jailbreak
- (void)showCompletionAlert {
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
- (void)didUpdateTogglesWithFirstToggle:(BOOL)firstToggle secondToggle:(BOOL)secondToggle {
    // Update label with toggle values
    install_openssh = firstToggle;
    reinstall_strap = secondToggle;
    NSLog([NSString stringWithFormat:@"Toggle 1: %@, Toggle 2: %@",
           firstToggle ? @"ON" : @"OFF",
           secondToggle ? @"ON" : @"OFF"]);
}

@end
