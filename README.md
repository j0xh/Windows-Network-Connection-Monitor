# Windows Network Connection Monitor

A lightweight C++ CLI tool for real-time monitoring of active network connections in Windows. It maps TCP/UDP sockets to their owning processes, flags suspicious activity, and logs events.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6.svg)

##  Key Features

*   **Real-Time Monitoring:** View active TCP and UDP connections as they happen.
*   **Process Mapping:** Identifies the specific process (Name & PID) responsible for every connection.
*   **Security Flagging:**
    *   **[PUBLIC]**: Instantly spots connections to public/internet IP addresses.
    *   **[SUSPICIOUS]**: Highlights connections on ports commonly associated with malware or vulnerabilities (e.g., 445 SMB, 3389 RDP). Edit the ports and services to your preferences in the source code.
*   **Freeze/Pause Mode:** Press `P` to freeze the output for close inspection without stopping the application.
*   **Background Logging:** Automatically saves all activity to `connections.log` for forensic review.

##  Prerequisities

*   **OS:** Windows 10 or Windows 11.
*   **Permissions:** **Administrator privileges** are highly recommended.
    *   *Why?* Without Admin rights, Windows hides the process names of system services (showing them as "Unknown"), limiting the tool's effectiveness.

##  Installation & Building

No installation is required, just a single executable. To build from source:

### Requirements
*   Visual Studio (2019/2022) with C++ Desktop Development credentials.
*   Windows SDK.

  
##  User Guide

### 1. Starting the Monitor

To compile the source, open a command prompt and run this , in the directory of the project: cl main.cpp /link iphlpapi.lib ws2_32.lib
Open a command prompt (cmd or powershell) as Administrator and run the tool:
```
cmd NetMonitor.exe
```
OR

Right click , run as Admin. (optional but recommended)


### 2. Reading the Output
The main screen is divided into two sections:

**Active TCP Connections**
Shows established connections to other machines.
```
Process                        PID      Local Address             Remote Address            Notes
----------------------------------------------------------------------------------------------------
chrome.exe                     1420     192.xxx.x.xx:52431        142.xxx.xxx.xx:443        [PUBLIC]
svchost.exe                    844      192.xxx.x.xx:445          192.xxx.x.xx:5985         [SUSPICIOUS]
```
*   **Process:** The executable name.
*   **Remote Address:** Where the data is going.
*   **Notes:** Look for `[PUBLIC]` (Internet traffic) or `[SUSPICIOUS]` (Potential risks).

**Active UDP Listeners**
Shows ports your computer is listing on.
```
Process                        PID      Local Address             Notes
----------------------------------------------------------------------------------------------------
Discord.exe                    9120     0.0.0.0:50002             
```

### 3. Controls
*   **Pause/Resume:** Press **`P`** on your keyboard.
    *   This stops the screen from refreshing so you can copy text or analyze a specific moment.
    *   Background logging also pauses to prevent log spam.
*   **Exit:** Press **`Ctrl+C`**.

### 4. Logging
Check the `connections.log` file created in the same directory. It contains a historical record of what the monitor saw, useful for spotting transient connections that appeared and vanished quickly.

```
TCP chrome.exe (1420) 192.xxx.x.xx:52431 -> 142.xxx.xxx.xxx:443 [PUBLIC]
UDP Discord.exe (9120) 0.0.0.0:50002
```

## Disclaimer
This tool is for educational and administrative monitoring purposes. It reads system connection tables using standard Windows APIs (`GetExtendedTcpTable`). It does not packet sniff, intercept SSL, or modify traffic.
