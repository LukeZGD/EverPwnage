#!/bin/bash
xcodebuild clean build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO -sdk iphoneos -configuration Debug
strip build/Debug-iphoneos/ios8-jailbreak.app/ios8-jailbreak
mkdir build/Debug-iphoneos/Payload
mv build/Debug-iphoneos/ios8-jailbreak.app build/Debug-iphoneos/Payload
ditto -c -k --sequesterRsrc --keepParent build/Debug-iphoneos/Payload EverPwnage.ipa
