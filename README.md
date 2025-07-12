# EverPwnage

**iOS 8.0-9.3.4 Jailbreak for 32-bit Devices**

## Usage

Download and sideload the IPA from the [latest release](https://github.com/LukeZGD/EverPwnage/releases/latest).

## Supported Devices

- **A5(X) devices:** iPhone 4S; iPad 2, 3, mini 1; iPod touch 5
- **A6(X) devices:** iPhone 5, 5C; iPad 4

## Jailbreak Modes

EverPwnage has an **"Install Untether" toggle**, which controls the installation of **daibutsu untether** or **EverUntether**, depending on the device and iOS version:

- The toggle is **enabled by default** for a fully untethered jailbreak.
- Users can manually disable the toggle if they prefer to remain semi-untethered.

## Untether

- **daibutsu untether**
    - daibutsu untether utilizes dyld_shared_cache patch for bypassing codesigning and sock_port_2_legacy for the untether executable, developed by kok3shidoll (v2.0.3).
    - Used on A5(X) devices on iOS 8.3-8.4.1, and A6(X) devices on iOS 8.0-8.4.1, except 8.4.
- **EverUntether**
    - EverUntether is a combination of [jsc_untether](https://github.com/staturnzz/jsc_untether) by staturnz (thanks to their work and assistance) and a [forked version](https://github.com/LukeZGD/daibutsu) of daibutsu untether (based on v1.2.3), updated to replace Trident with sock_port_2_legacy, and some fixes for iOS 9 support.
    - Used on A5(X) devices on iOS 8.0-8.2, and all devices on iOS 8.4 and 9.0-9.3.4.

## Switching from Other Jailbreaks

If you are using other iOS 8 jailbreaks like EtasonJB, HomeDepot, or openpwnage, you can switch to EverPwnage. Jailbreaking with EverPwnage and keeping the "Install Untether" toggle enabled will switch your device to daibutsu untether or EverUntether.

Do **not** use EverPwnage if your device is already jailbroken with these: Pangu8, Pangu9, TaiG, PPJailbreak, wtfis

These jailbreaks are already untethered and/or incompatible with migration.

## Building

This project is built using Xcode 10.1 and macOS High Sierra 10.13.6.

## Credits

- Special thanks to [kok3shidoll](https://github.com/kok3shidoll/), [Clarity](https://github.com/TheRealClarity/), and [staturnz](https://github.com/staturnzz/) for their incredible work and support. This jailbreak wouldn’t have been possible without them
- Thanks to [Merculous](https://github.com/Merculous) for testing and feedback
- exploit: [sock_port_2_legacy](https://github.com/kok3shidoll/sock_port_2_legacy/tree/ios8)
- untether and patches: [daibutsu untether](https://kok3shidoll.github.io/info/jp.daibutsu.untether841/indexv2.html) ([GitHub repo](https://github.com/kok3shidoll/daibutsu)), [libkok3shi](https://github.com/kok3shidoll/libkok3shi)
- got IOKit stuff and other learnings from: [wtfis](https://github.com/TheRealClarity/wtfis)
- base of this jailbreak: [openpwnage](https://github.com/0xilis/openpwnage)
