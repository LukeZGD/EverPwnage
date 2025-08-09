//
//  SettingsViewController.m
//  TestEx
//
//  Created by lukezgd on 12/17/24.
//  Copyright © 2024 lukezgd. All rights reserved.
//

#import "SettingsViewController.h"
#import "postjailbreak.h"

@interface SettingsViewController ()

@end

@implementation SettingsViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"More Settings";

    // Add a Done button for iPhone only
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPhone) {
        UIBarButtonItem *doneButton = [[UIBarButtonItem alloc] initWithTitle:@"Done"
                                                                       style:UIBarButtonItemStyleDone
                                                                      target:self
                                                                      action:@selector(dismissView)];
        self.navigationItem.rightBarButtonItem = doneButton;
    }
    
    [_firstToggleSwitch setOn:install_openssh];
    [_secondToggleSwitch setOn:reinstall_strap];
    [_untetherSwitch setOn:untether_on];
    
    if (strstr(ckernv, "3248.61")) {
        _untetherSwitch.enabled = NO;
        [_untetherSwitch setOn:NO];
    }
}

- (IBAction)toggleValueChanged:(id)sender {
    // Optional: Do something when toggles change
}

#pragma mark - Shared Dismiss Logic
- (void)dismissAction {
    // Notify the delegate with the toggle values
    if ([self.delegate respondsToSelector:@selector(didUpdateTogglesWithFirstToggle:secondToggle:untetherToggle:)]) {
        [self.delegate didUpdateTogglesWithFirstToggle:self.firstToggleSwitch.isOn
                                          secondToggle:self.secondToggleSwitch.isOn
                                        untetherToggle:self.untetherSwitch.isOn];
    }

    // Dismiss the view controller
    [self dismissViewControllerAnimated:YES completion:nil];
}

#pragma mark - Done Button Action (for iPhones)
- (void)dismissView {
    [self dismissAction];
}

#pragma mark - UIPopoverPresentationControllerDelegate (for iPads)
- (void)popoverPresentationControllerDidDismissPopover:(UIPopoverPresentationController *)popoverPresentationController {
    [self dismissAction];
}

@end
