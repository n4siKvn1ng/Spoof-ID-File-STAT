# Spoof ID File STAT

**Spoof ID when app is get ID from File STAT with KPM. ID that receive by the App have spoof after the STAT get value.**

## Requirement

[APatch](https://github.com/bmax121/APatch) is installed

## Supported Versions

Currently only supports arm64 architecture.  
Linux 3.18 - 6.6 (theoretically)  
Same as APatch

## Features

- **Persistent Spoof Data**: Spoof values are saved to `/data/adb/.spoof/` and persist across reboots
- **Auto-detection**: Automatically detects target application (FPJS) on first launch
- **Reset Fingerprint**: Use control command to generate new fingerprint

## How To Use?

### 1. Install the Module
Make sure APatch is installed. Open the APatch app, go to the KPModule tab, then select the 'Load' option and choose the spoofSTAT.kpm file. If you haven't downloaded the spoofSTAT.kpm file yet, you can get it from [here](https://github.com/n4siKvn1ng/Spoof-ID-File-STAT/releases)

### 2. Create Spoof Directory (First Time Only)
Run in terminal as root:
```bash
mkdir -p /data/adb/.spoof
chmod 700 /data/adb/.spoof
```

### 3. Generate New Fingerprint
To reset and generate a new device fingerprint, use APatch control:
```bash
# Via APatch app or terminal:
apatch kpm control spoofSTAT stat
```

This will:
- Clear memory cache
- Invalidate persistent files
- Reset target UID detection
- Generate new random values on next app launch

## How It Works

1. **First Launch**: When target app opens, random spoof offsets are generated and saved to `/data/adb/.spoof/spoof_<UID>.dat`
2. **Subsequent Launches**: Saved values are loaded from file, keeping fingerprint consistent
3. **Reset Command**: When "stat" argument is passed, files are invalidated and new values will be generated

## File Storage

Spoof data is stored in:
```
/data/adb/.spoof/
├── spoof_10382.dat    # UID 10382
├── spoof_10XXX.dat    # Other UIDs
└── ...
```

## BUG
- Report if you find any bug

## Get Involved
If you can write clean code, find bugs other than the ones mentioned, or want to contribute, feel free to open a PR.

## More Information
[Documentation](https://github.com/bmax121/KernelPatch/tree/main/doc)

## Credits
- [0bbedCode](https://github.com/0bbedCode/XPL-EX): Inspiration of this project and the initial code
- [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf): Some ideas for parsing kernel symbols
- [android-inline-hook](https://github.com/bytedance/android-inline-hook): Some code for fixing arm64 inline hook instructions
- [tlsf](https://github.com/mattconte/tlsf): Memory allocator used for KPM

## License
I haven't decided on a license for this open source project yet, so feel free to use it and contribute.
