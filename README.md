# System Health Monitor

## Overview

The **System Health Monitor** is a Python application designed to provide users with an intuitive console interface for checking and managing their system's health. It features various functionalities such as update management, package information retrieval, physical device status checks, and network monitoring, making it ideal for users who want to keep an eye on system performance and security.

## Features

- **Update Management**: Easily check for system updates on Windows and various Linux distributions (Ubuntu, Debian, Arch, Fedora).
- **Package Information**: Retrieve and display information about installed packages on your system.
- **Physical Device Status**: Monitor the status of physical devices like cameras and microphones, checking if they are in use.
- **Network Monitoring**: Check your current IP address, MAC address, DNS information, and perform ping tests to gauge network responsiveness.
- **Traffic Monitoring**: Track incoming and outgoing data traffic on your system.
- **Active Applications**: List the top active applications running on your system for better security awareness.

## Requirements

- Python 3.x
- `psutil` library (automatically installed if missing)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/system-health-monitor.git
   cd system-health-monitor
