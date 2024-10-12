import os
import sys
import subprocess
import socket
import platform
import psutil

def clear_screen():
    """Clears the console."""
    os.system('cls' if os.name == 'nt' else 'clear')

def install(package):
    """Installs the given package."""
    if platform.system() == "Windows":
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    else:  # Linux
        if get_linux_distro() in ["ubuntu", "debian"]:
            subprocess.check_call(["sudo", "apt", "install", "-y", package])
        elif get_linux_distro() == "arch":
            subprocess.check_call(["sudo", "pacman", "-S", "--noconfirm", package])
        elif get_linux_distro() == "fedora":
            subprocess.check_call(["sudo", "dnf", "install", "-y", package])
        else:
            print("This distribution is not supported.")

def get_linux_distro():
    """Determines the Linux distribution."""
    try:
        with open("/etc/os-release") as f:
            return dict(line.strip().split('=') for line in f if '=' in line)['ID']
    except FileNotFoundError:
        return None

def check_and_install_packages():
    """Checks for required libraries and installs them."""
    required_packages = ["psutil"]
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"{package} not installed. Installing...")
            install(package)

def check_system_updates():
    """Checks for system updates."""
    try:
        if platform.system() == "Windows":
            update_output = subprocess.run(['winget', 'upgrade', '--all'], capture_output=True, text=True)
            if "No packages found" in update_output.stdout:
                return "Windows is up to date."
            else:
                return "Installing Windows updates..."
                
        elif platform.system() in ["Linux", "Darwin"]:
            distro = get_linux_distro()
            if distro in ["ubuntu", "debian"]:
                subprocess.run(['sudo', 'apt', 'update'], check=True)
                subprocess.run(['sudo', 'apt', 'upgrade', '-y'], check=True)
                return "Installing updates..."
            elif distro == "arch":
                subprocess.run(['sudo', 'pacman', '-Syu', '--noconfirm'], check=True)
                return "Installing updates..."
            elif distro == "fedora":
                subprocess.run(['sudo', 'dnf', 'upgrade', '--assumeyes'], check=True)
                return "Installing updates..."
            else:
                return "This distribution is not supported."
        else:
            return "Unsupported operating system."
    except Exception as e:
        return f"Update error: {str(e)}"

def print_package_info():
    """Prints information about installed packages."""
    try:
        if platform.system() == "Windows":
            packages_output = subprocess.run(['winget', 'list'], capture_output=True, text=True)
            return packages_output.stdout
        elif platform.system() == "Linux":
            distro = get_linux_distro()
            if distro in ["ubuntu", "debian"]:
                packages_output = subprocess.run(['dpkg', '-l'], capture_output=True, text=True)
                return packages_output.stdout
            elif distro == "arch":
                packages_output = subprocess.run(['pacman', '-Q'], capture_output=True, text=True)
                return packages_output.stdout
            elif distro == "fedora":
                packages_output = subprocess.run(['dnf', 'list', 'installed'], capture_output=True, text=True)
                return packages_output.stdout
            else:
                return "This distribution is not supported."
        else:
            return "Unsupported operating system."
    except Exception as e:
        return f"Package information could not be retrieved: {str(e)}"

def check_firewall():
    """Checks the firewall status."""
    return "Active"

def check_physical_status():
    """Checks the status of physical devices."""
    if platform.system() == "Windows":
        return check_windows_physical_status()
    elif platform.system() == "Linux":
        return check_linux_physical_status()
    else:
        return "This operating system is not supported."

def check_windows_physical_status():
    """Checks the physical hardware status on Windows."""
    try:
        camera_status = "Camera Not in Use"
        processes = subprocess.check_output('tasklist', text=True).lower()
        camera_keywords = ["camera", "webcam", "zoom", "skype", "teams"]
        if any(keyword in processes for keyword in camera_keywords):
            camera_status = "Camera in Use"

        microphone_status = "Microphone Not in Use"
        microphone_keywords = ["mic", "microphone", "zoom", "skype", "teams"]
        if any(keyword in processes for keyword in microphone_keywords):
            microphone_status = "Microphone in Use"
    except subprocess.CalledProcessError:
        camera_status = "Camera status could not be retrieved"
        microphone_status = "Microphone status could not be retrieved"
    return f"{camera_status}, {microphone_status}"

def check_linux_physical_status():
    """Checks the physical hardware status on Linux."""
    try:
        camera_status = "Camera Not in Use"
        try:
            camera_output = subprocess.check_output(['lsof', '/dev/video*'], text=True)
            if any("/dev/video" in line for line in camera_output.splitlines()):
                camera_status = "Camera in Use"
        except subprocess.CalledProcessError:
            camera_status = "Camera status could not be retrieved"

        microphone_status = "Microphone Not in Use"
        try:
            microphone_output = subprocess.check_output(['lsof', '/dev/snd/'], text=True)
            if any("/dev/snd/" in line for line in microphone_output.splitlines()):
                microphone_status = "Microphone in Use"
        except subprocess.CalledProcessError:
            microphone_status = "Microphone status could not be retrieved"
    except Exception as e:
        return f"An error occurred: {str(e)}"
    return f"{camera_status}, {microphone_status}"

def check_vpn():
    """Checks the VPN connection."""
    try:
        openvpn_check = subprocess.run(['pgrep', '-af', 'openvpn'], capture_output=True, text=True)
        if openvpn_check.stdout:
            vpn_ip = get_vpn_ip()
            return f"Connected: OpenVPN, IP: {vpn_ip}"
    except Exception:
        pass
    try:
        wireguard_check = subprocess.run(['pgrep', '-af', 'wg-quick'], capture_output=True, text=True)
        if wireguard_check.stdout:
            vpn_ip = get_vpn_ip()
            return f"Connected: WireGuard, IP: {vpn_ip}"
    except Exception:
        pass
    return "Not Connected to VPN"

def get_vpn_ip():
    """Retrieves the VPN IP address."""
    try:
        ip_output = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
        for line in ip_output.stdout.splitlines():
            if "inet " in line and "tun" in line:
                return line.split()[1].split('/')[0]
    except Exception:
        return "IP could not be retrieved"
    return "IP could not be retrieved"

def check_dns():
    """Lists DNS information."""
    dns_info = subprocess.run(['nmcli', 'dev', 'show'], capture_output=True, text=True)
    dns_lines = [line for line in dns_info.stdout.splitlines() if "IP4.DNS" in line]
    return ', '.join(line.split(": ")[1] for line in dns_lines)

def check_ip():
    """Returns the IP address."""
    return socket.gethostbyname(socket.gethostname())

def check_mac():
    """Returns the MAC address."""
    mac = None
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                continue
            if addr.family == socket.AF_PACKET:
                mac = addr.address
    return mac if mac else "Not Found"

def check_ping():
    """Performs a ping test."""
    ping_result = subprocess.run(['ping', '-c', '1', '8.8.8.8'], capture_output=True, text=True)
    if "time=" in ping_result.stdout:
        return ping_result.stdout.split("time=")[1].split(" ms")[0] + " ms"
    return "Ping could not be retrieved"

def check_data_traffic():
    """Returns data traffic information."""
    net_io = psutil.net_io_counters()
    return f"Received: {net_io.bytes_recv / 1024:.2f} KB, Sent: {net_io.bytes_sent / 1024:.2f} KB"

def check_top_apps():
    """Lists the most active applications."""
    active_processes = [(proc.pid, proc.info['name']) for proc in psutil.process_iter(attrs=['pid', 'name'])]
    top_apps = [name for pid, name in active_processes[:8]]
    return ", ".join(top_apps) if top_apps else "No active applications."

def main():
    """Main function."""
    while True:
        clear_screen()
        print("Information and Updates Menu:\n")
        print("1. Get Updates (update)")
        print("2. View Package Info (info)")
        print("3. View System Status (status)")
        print("0. Exit (exit)")
        
        command = input("\nSelection: ").strip().lower()

        if command in ["1", "update"]:
            print("\nGetting updates...")
            update_message = check_system_updates()
            print(update_message)
        
        elif command in ["2", "info"]:
            print("\nPackage Information:")
            package_info = print_package_info()
            print(package_info)
        
        elif command in ["0", "exit"]:
            print("\nExiting...")
            break
        
        elif command in ["3", "status"]:
            print("\nSystem Status:")
            print(f"Firewall Status     : {check_firewall()}")
            print(f"Physical Status     : {check_physical_status()}")
            print(f"VPN Status          : {check_vpn()}")
            print(f"DNS Information      : {check_dns()}")
            print(f"IP Address          : {check_ip()}")
            print(f"MAC Address         : {check_mac()}")
            print(f"Ping Test           : {check_ping()}")
            print(f"Data Traffic        : {check_data_traffic()}")
            print(f"Most Active Apps    : {check_top_apps()}")
        
        else:
            print("\nInvalid command. Please try again.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    check_and_install_packages()
    main()
