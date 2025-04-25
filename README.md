# Spoof ID File STAT

**Spoof ID when app is get ID from File STAT with KPM. ID that receive by the App have spoof after the STAT get value.**

## Requirement

[APatch](https://github.com/bmax121/APatch) is installed

## Supported Versions

Currently only supports arm64 architecture.  
Linux 3.18 - 6.6 (theoretically)  
Same as APatch

## BUG
Do not embed this module into APatch, as it may cause the phone’s functionality to malfunction. If this happens, the solution is to reinstall APatch without embedding the module.

## How To Use?
Make sure APatch is installed. Open the APatch app, go to the KPModule tab, then select the 'Load' option and choose the spoofSTAT.kpm file. If you haven't downloaded the spoofSTAT.kpm file yet, you can get it from [here](https://github.com/n4siKvn1ng/Spoof-ID-File-STAT/releases)

## Get Involved
If you can write clean code, find bugs other than the ones mentioned, or want to contribute, feel free to open a PR.

## More Information
[Documentation](https://github.com/bmax121/KernelPatch/tree/main/doc)

## Credits
- [0bbedCode](https://github.com/0bbedCode/XPL-EX): Inspiration of this project and the initial code
- [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf): Some ideas for parsing kernel symbols.
- [android-inline-hook](https://github.com/bytedance/android-inline-hook): Some code for fixing arm64 inline hook instructions.
- [tlsf](https://github.com/mattconte/tlsf): Memory allocator used for KPM. (Need another to allocate ROX memory.)

## License
I haven’t decided on a license for this open source project yet, so feel free to use it and contribute.
