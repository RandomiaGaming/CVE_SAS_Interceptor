# System Processes
This document is a list of all the major system processes I know about and what they do. This is not a comprehensive list and is just a quick reference sheet for me when I am researching hacks.

wlanext.exe - Windows Wireless LAN Extensibility Framework
Responsible for hosting an API for applications to use the LAN and wifi networks.

winlogon.exe - Windows Logon
Responsible for rendering the windows login screen as well as storing information about the current user session. Also handles the SAS (CTRL + ALT + DEL).

wininit.exe - Windows Initialization
Responsible for starting up many critical system services and processes. Runs just after the kernel is loaded.

winload.exe - Windows Loader
Runs even before the kernel and is responsible for loading the starting the kernel. It lives in the system reserved partition.

ntoskrnl.exe (System) - New Technology Operating System Kernel
Responsible for the core functionality of Windows.

svchost.exe - Service Host
Responsible for hosting services that are not standalone.

smss.exe - Session Manager Subsystem
Responsible for certain parts of the logon process. Also sets up the user session environment. And lastly handles Restart/Shutdown procedures by backing up system state to filesystem for later. Additionally if a kernel panic (BSOD) occurs smss is responsible for creating the crash dump.

services.exe - Service Manager
Manages the services running on the PC. Responsible for starting and stopping services.

lsass.exe - Local Security Authority Subsystem Service
lsass is responsible for checking passwords against the database during logon as well as other situations like runas. lsass also is responsible for issuing tokens to apps and users.

dwm.exe - Desktop Window Manager
Responsible for rendering the windows to the screen. Without dwm only the mouse can be moved.

csrss.exe - Client Server Runtime Subsystem
csrss is responsible for managing subsystems like the console subsystem or GDI (graphics device interface) subsystem (sometimes called win GUI). It also plays a role in the management of threads.

conhost.exe - Console Host
Responsible for rendering and hosting console windows used by apps with the console subsystem.

cmd.exe - Command Prompt
A system utility for running user inputted commands or shell scripts.

explorer.exe - Windows Shell
In addition to being file explorer. explorer.exe also is the windows shell and is responsible for rendering the task bar, and desktop as well as making the Alt + Tab menu prettier. Without the shell the Alt + Tab menu reverts to its default pixelated look.

BootMGR - Pre Boot Manager
Runs straight after the UEFI BIOS. Checks file integrity as well as launching winload.exe for the main bootloader.