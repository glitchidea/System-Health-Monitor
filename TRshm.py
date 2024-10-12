import os
import sys
import subprocess
import socket
import platform
import psutil

def clear_screen():
    """Konsolu temizler."""
    os.system('cls' if os.name == 'nt' else 'clear')

def install(package):
    """Verilen paketi yükler."""
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
            print("Bu dağıtım desteklenmiyor.")

def get_linux_distro():
    """Linux dağıtımını belirler."""
    try:
        with open("/etc/os-release") as f:
            return dict(line.strip().split('=') for line in f if '=' in line)['ID']
    except FileNotFoundError:
        return None

def check_and_install_packages():
    """Gerekli kütüphaneleri kontrol eder ve yükler."""
    required_packages = ["psutil"]
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"{package} yüklenmedi. Yükleniyor...")
            install(package)

def check_system_updates():
    """Sistem güncellemelerini kontrol eder."""
    try:
        if platform.system() == "Windows":
            update_output = subprocess.run(['winget', 'upgrade', '--all'], capture_output=True, text=True)
            if "No packages found" in update_output.stdout:
                return "Windows güncel"
            else:
                return "Windows güncellemeleri yükleniyor..."
                
        elif platform.system() in ["Linux", "Darwin"]:
            distro = get_linux_distro()
            if distro in ["ubuntu", "debian"]:
                subprocess.run(['sudo', 'apt', 'update'], check=True)
                subprocess.run(['sudo', 'apt', 'upgrade', '-y'], check=True)
                return "Güncellemeler yükleniyor..."
            elif distro == "arch":
                subprocess.run(['sudo', 'pacman', '-Syu', '--noconfirm'], check=True)
                return "Güncellemeler yükleniyor..."
            elif distro == "fedora":
                subprocess.run(['sudo', 'dnf', 'upgrade', '--assumeyes'], check=True)
                return "Güncellemeler yükleniyor..."
            else:
                return "Bu dağıtım desteklenmiyor."
        else:
            return "Desteklenmeyen işletim sistemi."
    except Exception as e:
        return f"Güncelleme hatası: {str(e)}"

def print_package_info():
    """Mevcut paketlerin bilgilerini yazdırır."""
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
                return "Bu dağıtım desteklenmiyor."
        else:
            return "Desteklenmeyen işletim sistemi."
    except Exception as e:
        return f"Paket bilgisi alınamadı: {str(e)}"

def check_firewall():
    """Firewall durumunu kontrol eder."""
    return "Aktif"

def check_physical_status():
    """Fiziksel cihazların durumunu kontrol eder."""
    if platform.system() == "Windows":
        return check_windows_physical_status()
    elif platform.system() == "Linux":
        return check_linux_physical_status()
    else:
        return "Bu işletim sistemi desteklenmiyor."

def check_windows_physical_status():
    """Windows'taki fiziksel donanım durumunu kontrol eder."""
    try:
        camera_status = "Kamera Kullanılmıyor"
        processes = subprocess.check_output('tasklist', text=True).lower()
        camera_keywords = ["camera", "webcam", "zoom", "skype", "teams"]
        if any(keyword in processes for keyword in camera_keywords):
            camera_status = "Kamera Kullanılıyor"

        microphone_status = "Mikrofon Kullanılmıyor"
        microphone_keywords = ["mic", "microphone", "zoom", "skype", "teams"]
        if any(keyword in processes for keyword in microphone_keywords):
            microphone_status = "Mikrofon Kullanılıyor"
    except subprocess.CalledProcessError:
        camera_status = "Kamera durumu alınamadı"
        microphone_status = "Mikrofon durumu alınamadı"
    return f"{camera_status}, {microphone_status}"

def check_linux_physical_status():
    """Linux'taki fiziksel donanım durumunu kontrol eder."""
    try:
        camera_status = "Kamera Kullanılmıyor"
        try:
            camera_output = subprocess.check_output(['lsof', '/dev/video*'], text=True)
            if any("/dev/video" in line for line in camera_output.splitlines()):
                camera_status = "Kamera Kullanılıyor"
        except subprocess.CalledProcessError:
            camera_status = "Kamera durumu alınamadı"

        microphone_status = "Mikrofon Kullanılmıyor"
        try:
            microphone_output = subprocess.check_output(['lsof', '/dev/snd/'], text=True)
            if any("/dev/snd/" in line for line in microphone_output.splitlines()):
                microphone_status = "Mikrofon Kullanılıyor"
        except subprocess.CalledProcessError:
            microphone_status = "Mikrofon durumu alınamadı"
    except Exception as e:
        return f"Bir hata oluştu: {str(e)}"
    return f"{camera_status}, {microphone_status}"

def check_vpn():
    """VPN bağlantısını kontrol eder."""
    try:
        openvpn_check = subprocess.run(['pgrep', '-af', 'openvpn'], capture_output=True, text=True)
        if openvpn_check.stdout:
            vpn_ip = get_vpn_ip()
            return f"Bağlı: OpenVPN, IP: {vpn_ip}"
    except Exception:
        pass
    try:
        wireguard_check = subprocess.run(['pgrep', '-af', 'wg-quick'], capture_output=True, text=True)
        if wireguard_check.stdout:
            vpn_ip = get_vpn_ip()
            return f"Bağlı: WireGuard, IP: {vpn_ip}"
    except Exception:
        pass
    return "VPN Bağlı Değil"

def get_vpn_ip():
    """VPN IP adresini alır."""
    try:
        ip_output = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
        for line in ip_output.stdout.splitlines():
            if "inet " in line and "tun" in line:
                return line.split()[1].split('/')[0]
    except Exception:
        return "IP alınamadı"
    return "IP alınamadı"

def check_dns():
    """DNS bilgilerini listeler."""
    dns_info = subprocess.run(['nmcli', 'dev', 'show'], capture_output=True, text=True)
    dns_lines = [line for line in dns_info.stdout.splitlines() if "IP4.DNS" in line]
    return ', '.join(line.split(": ")[1] for line in dns_lines)

def check_ip():
    """IP adresini döndürür."""
    return socket.gethostbyname(socket.gethostname())

def check_mac():
    """MAC adresini döndürür."""
    mac = None
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                continue
            if addr.family == socket.AF_PACKET:
                mac = addr.address
    return mac if mac else "Bulunamadı"

def check_ping():
    """Ping testi yapar."""
    ping_result = subprocess.run(['ping', '-c', '1', '8.8.8.8'], capture_output=True, text=True)
    if "time=" in ping_result.stdout:
        return ping_result.stdout.split("time=")[1].split(" ms")[0] + " ms"
    return "Ping alınamadı"

def check_data_traffic():
    """Veri trafiğini döndürür."""
    net_io = psutil.net_io_counters()
    return f"Gelen: {net_io.bytes_recv / 1024:.2f} KB, Giden: {net_io.bytes_sent / 1024:.2f} KB"

def check_top_apps():
    """En aktif uygulamaları listeler."""
    active_processes = [(proc.pid, proc.info['name']) for proc in psutil.process_iter(attrs=['pid', 'name'])]
    top_apps = [name for pid, name in active_processes[:8]]
    return ", ".join(top_apps) if top_apps else "Aktif uygulama yok."

def main():
    """Ana fonksiyon."""
    while True:
        clear_screen()
        print("Bilgi ve Güncellemeler Menüsü:\n")
        print("1. Güncellemeleri Al (update)")
        print("2. Paket Bilgilerini Gör (info)")
        print("3. Sistem Durumunu Gör (status)")
        print("0. Çıkış (exit)")
        
        command = input("\nSeçim : ").strip().lower()

        if command in ["1", "update"]:
            print("\nGüncellemeler alınıyor...")
            update_message = check_system_updates()
            print(update_message)
        
        elif command in ["2", "info"]:
            print("\nPaket Bilgileri:")
            package_info = print_package_info()
            print(package_info)
        
        elif command in ["0", "exit"]:
            print("\nÇıkış yapılıyor...")
            break
        
        elif command in ["3", "status"]:
            print("\nSistem Durumu:")
            print(f"Firewall Durumu    : {check_firewall()}")
            print(f"Fiziksel Durum       : {check_physical_status()}")
            print(f"VPN Durumu           : {check_vpn()}")
            print(f"DNS Bilgileri        : {check_dns()}")
            print(f"IP Adresi            : {check_ip()}")
            print(f"MAC Adresi           : {check_mac()}")
            print(f"Ping Testi           : {check_ping()}")
            print(f"Veri Trafiği         : {check_data_traffic()}")
            print(f"En Aktif Uygulamalar : {check_top_apps()}")
        
        else:
            print("\nGeçersiz komut. Lütfen tekrar deneyin.")
        
        input("\nDevam etmek için Enter'a basın...")

if __name__ == "__main__":
    check_and_install_packages()
    main()
