# EverPwnage

**iOS 8.0-9.3.6 Jailbreak for 32-bit Devices**

## Usage

Download and sideload the IPA from the [latest release](https://github.com/LukeZGD/EverPwnage/releases/latest) using [Sideloadly](https://sideloadly.io/).

On Linux, use [Legacy iOS Kit](https://github.com/LukeZGD/Legacy-iOS-Kit) to sideload the IPA.

## Supported Devices

- **A5(X) devices:** iPhone 4S; iPad 2, 3, mini 1; iPod touch 5
- **A6(X) devices:** iPhone 5, 5C; iPad 4

## Untether

EverPwnage has an **"Install Untether" toggle**, which controls the installation of EverUntether.

- The toggle is **enabled by default** for a fully untethered jailbreak.
- Users can manually disable the toggle if they prefer to remain semi-untethered.
- **iOS 9.3.5 and 9.3.6 are not untethered**. Semi-untethered only.

EverUntether is a [forked version](https://github.com/LukeZGD/daibutsu) of daibutsu untether (based on v1.2.3), updated to replace Trident/sock_port_2_legacy with [oob_entry](https://github.com/staturnzz/oob_entry), and some fixes for iOS 9 support. Compatible with all 32-bit devices on iOS 8.0-9.3.4.

## Switching from Other Jailbreaks

If you are using other semi-untethered jailbreaks for 32-bit devices on iOS 8-9, you can switch to EverPwnage.

Devices that already have EtasonJB or daibutsu untether installed can also switch to EverUntether. Simply install the EverUntether package from my repo: https://lukezgd.github.io/repo

You cannot use EverPwnage/EverUntether if your device is already jailbroken with these: Pangu8, Pangu9, TaiG, PPJailbreak, wtfis. These jailbreaks are incompatible for migration.

## Building

This project was initially built using Xcode 9.4.1/10.1 and macOS High Sierra 10.13.6.

Versions 1.3 and newer are built using Xcode 13.4.1 and macOS Monterey 12.6.

## Credits

- Special thanks to [kok3shidoll](https://github.com/kok3shidoll/), [Clarity](https://github.com/TheRealClarity/), and [staturnz](https://github.com/staturnzz/) for their incredible work and support. This jailbreak wouldn’t have been possible without them
- Thanks to [Merculous](https://github.com/Merculous) for testing and feedback
- exploit: [oob_entry](https://github.com/staturnzz/oob_entry)
- untether and patches: [daibutsu](https://github.com/kok3shidoll/daibutsu)
- untether: [jsc_untether](https://github.com/staturnzz/jsc_untether)
- some ios 9 patches: [libkok3shi](https://github.com/kok3shidoll/libkok3shi)
- got IOKit stuff and other learnings from: [wtfis](https://github.com/TheRealClarity/wtfis)
- base of this jailbreak: [openpwnage](https://github.com/0xilis/openpwnage)
