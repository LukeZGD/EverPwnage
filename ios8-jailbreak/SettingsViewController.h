//
//  SettingsViewController.h
//  TestEx
//
//  Created by lukezgd on 12/17/24.
//  Copyright © 2024 lukezgd. All rights reserved.
//

#import <UIKit/UIKit.h>

@protocol SettingsViewControllerDelegate <NSObject>

- (void)didUpdateTogglesWithFirstToggle:(BOOL)firstToggle
                           secondToggle:(BOOL)secondToggle
                         untetherToggle:(BOOL)untetherToggle;

@end

@interface SettingsViewController : UIViewController <UIPopoverPresentationControllerDelegate>

@property (nonatomic, weak) id<SettingsViewControllerDelegate> delegate;

@property (weak, nonatomic) IBOutlet UISwitch *firstToggleSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *secondToggleSwitch;
@property (weak, nonatomic) IBOutlet UISwitch *untetherSwitch;

@end
