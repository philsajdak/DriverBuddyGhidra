# DriverBuddy for Ghidra

A collection of Python scripts for analyzing Windows drivers in Ghidra, such as finding device names and IOCTL handlers. It is inspired by [DriverBuddy](https://github.com/nccgroup/DriverBuddy), which is an IDA Pro Python plugin that helps automate some tedious Windows Kernel Drivers reverse engineering tasks. This project aims to port over its functionalities for Ghidra.

## Table of Contents
- [Scripts](#scripts)
  - [find_device_name.py](#1-find_device_namepy)
    - [Features](#features)
    - [Detection Methods](#detection-methods)
    - [Limitations](#limitations)
  - [find_ioctls.py](#2-find_ioctlspy)
    - [Features](#features-1)
    - [Detection Methods](#detection-methods-1)
    - [Limitations](#limitations-1)
- [Installation](#installation)
- [Usage](#usage)
- [Output Examples](#output-examples)
  - [find_device_name.py](#find_device_namepy)
  - [find_ioctls.py](#find_ioctlspy)
- [Requirements](#requirements)
- [Notes](#notes)

## Scripts

### 1. find_device_name.py
A Ghidra script that scans binary files for Windows device names using multiple detection methods.

#### Features
- Scans memory blocks for device name patterns
- Analyzes functions handling device names (IoCreateSymbolicLink, RtlInitUnicodeString, IoDeleteSymbolicLink)
- Uses both direct memory scanning and decompiler analysis
- Pattern matching using regular expressions

#### Detection Methods
- Direct string scanning in memory blocks
- Parameter analysis in function calls
- Analysis of decompiled C code
- Pattern matching for device name formats

#### Limitations
- Cannot detect dynamically generated device names
- May miss obfuscated or encrypted strings
- Only works on device names following standard Windows naming patterns
- Relies on Ghidra's decompilation accuracy
- May produce false positives for similar patterns

### 2. find_ioctls.py
A Ghidra script that identifies and analyzes IOCTL (I/O Control) codes in Windows drivers.

#### Features
- Locates device control dispatch routines
- Identifies IOCTL codes used by the driver
- Analyzes IOCTL handlers for:
  - Input/output buffer requirements
  - Buffer size checks
  - Expected buffer field values
  - Memory operations
  - Error codes
  - Function calls

#### Detection Methods
- Pattern matching for IOCTL dispatch routines
- Analysis of decompiled C code for IOCTL codes (≥ 0x200000)
- Buffer validation pattern detection
- Memory operation tracking

#### Limitations
- Relies on Ghidra's decompilation accuracy
- May miss dynamically constructed IOCTL codes
- Pattern matching might miss non-standard implementations
- Cannot detect runtime-generated validation checks
- Only works on standard Windows driver implementations

## Installation

1. Clone this repository
2. Add the main `dbg-scripts` directory in Ghidra:
   - Go to `Window` > `Script Manager`
   - In the `Script Manager` window, go to `Manage Script Directories`
   - In the `Bundle Manager` window, add the `dbg-scripts` directory
   - The scripts will be populated inside the `Script Manager` window. Enable them by checking the `In Tool` box.
3. Refresh the script list to see the new scripts

## Usage

Run the desired script on an analyzed file by double-clicking it or using the keyboard shortcut (Shift+E for `find_device_names.py` or Shift+T for `find_ioctls.py`). You can modify the keyboard shortcuts inside the script files.

## Output Examples

### find_device_name.py

![find_device_name output](img/find_device_name_output.png)

### find_ioctls.py

![find_ioctls output](img/find_ioctls_output.png)

## Requirements

- Latest version of Ghidra
- Python 2.7 (Jython, included with Ghidra)

## Notes

- These scripts are designed for Ghidra's Jython environment (Python 2.7)
- Pattern matching and analysis methods may need adjustment for specific drivers
- Results should be manually verified due to the complex nature of driver analysis
- `find_ioctls.py` works okay at detecting IOCTLs, but needs better buffer input/output detection since it sometimes produces incorrect results
- This is a living repo, and will hopefully implement other DriverBuddyReloaded features in the future