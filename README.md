# Nyuki Android Process Dumper (AProcDump)

## Introduction

The Nyuki Android Process Dumper (AProcDump) is a user-mode software application that runs natively on Android devices and is capable of acquiring the volatile memory of processes without the need for compiling and installing any kernel modules. This application is not a replacement to full physical memory acquisition but rather a quick drop-and-execute alternative. The Nyuki Android Process can be compiled once and used across multiple Android platforms. It can be executed through the Android Debug Bridge (ADB) and supports various methods of extraction. As always, this application requires root access on the device's Operating System.

### Features
* Output memory into a file, network stream or standard output
* List a process's allocated modules and heaps
* Acquire memory of specific maps given their name
* Selectively filter memory regions based on permissions and allocation type
 *Acquire specific memory regions given a memory range


## Dependencies
* Android NDK is required for compiling.
* Android Debug Bridge (adb) required for running.

## Compiling and Running
```
cd aprocdump
/path/to/ndk-build all .
```

In order to run the application it must be pushed into a running Android device.
To do that use the following _adb_ commands: 
```
adb push /path/to/aprocdump /data/local
adb shell chmod 750 /data/local/aprocdump
adb shell /data/local/aprocdump --help
```

## More info
View more info and download binary file at Silensec's Website [here](http://silensec.com/downloads-menu/aprocdump)