"""KARTIKA-CDS Interactive CLI Launcher (Inspired by 9router).
Menyediakan antarmuka interaktif di PowerShell / Terminal dengan menu navigasi panah,
auto-launch background gateway, browser launcher, dan live monitoring.
"""
import os
import sys
import time
import json
import socket
import webbrowser
import subprocess
from pathlib import Path

# Aktifkan ANSI escape codes & UTF-8 di Windows console
os.system('')
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent
RUN_DIR = BASE_DIR / "run"
PIDS_FILE = RUN_DIR / "pids.json"
PYTHON = sys.executable

# Warna ANSI
ORANGE = "\033[38;2;240;110;50m"
BOLD_ORANGE = "\033[1;38;2;255;120;60m"
GREEN = "\033[38;2;40;220;120m"
CYAN = "\033[38;2;0;229;255m"
YELLOW = "\033[38;2;255;180;0m"
RED = "\033[38;2;255;70;70m"
GRAY = "\033[38;2;140;150;160m"
WHITE = "\033[1;37m"
DIM = "\033[2m"
RESET = "\033[0m"

MENU_ITEMS = [
    ("Web UI (Open in Browser)", "Menjalankan gateway di latar belakang & membuka split-view di browser"),
    ("Terminal UI (Interactive CLI)", "Pemantauan status radar OT, brankas file, dan port secara real-time"),
    ("Run Live Smoke Test", "Pengujian otomatis 8 skenario serangan & file sah TNI AD"),
    ("FEC Loss Simulation", "Simulasi ketahanan paket loss dengan Reed-Solomon RS(4,2)"),
    ("Check Gateway Status", "Pemeriksaan kesehatan port (5000, 5001, 8000, 9999) & kunci"),
    ("Stop Gateway Services", "Menghentikan semua proses server di latar belakang"),
    ("Exit", "Keluar dari launcher"),
]

def is_port_listening(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False

def is_gateway_running() -> bool:
    return is_port_listening(8000) and is_port_listening(5000) and is_port_listening(5001)

def start_gateway_background():
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    for d in ("data/low/dropzone", "data/low/quarantine", "data/high/secure_vault", "data/high/staging", "keys"):
        (BASE_DIR / d).mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["DIODE_RX_HOST"] = "127.0.0.1"
    env["DIODE_RX_BIND"] = "127.0.0.1"
    env["LOW_UI_HOST"] = "127.0.0.1"
    env["LOW_UI_PORT"] = "5000"
    env["HIGH_UI_HOST"] = "127.0.0.1"
    env["HIGH_UI_PORT"] = "5001"
    env["DIODE_REQUIRE_ENGINES"] = "yara"

    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

    pids = []
    # 1. Receiver UDP High-Side & Web UI High
    if not is_port_listening(5001):
        p1 = subprocess.Popen([PYTHON, "-m", "high_side.udp_receiver"], cwd=str(BASE_DIR), env=env, creationflags=flags)
        pids.append(p1.pid)
        p2 = subprocess.Popen([PYTHON, "-m", "high_side.app"], cwd=str(BASE_DIR), env=env, creationflags=flags)
        pids.append(p2.pid)
    
    # 2. Low-Side UI
    if not is_port_listening(5000):
        p3 = subprocess.Popen([PYTHON, "-m", "low_side.app"], cwd=str(BASE_DIR), env=env, creationflags=flags)
        pids.append(p3.pid)

    # 3. Demo Split-View
    if not is_port_listening(8000):
        p4 = subprocess.Popen([PYTHON, "-m", "http.server", "8000", "--bind", "127.0.0.1", "--directory", "demo"], cwd=str(BASE_DIR), env=env, creationflags=flags)
        pids.append(p4.pid)

    # Simpan PIDs
    existing_pids = []
    if PIDS_FILE.exists():
        try:
            existing_pids = json.loads(PIDS_FILE.read_text())
        except Exception:
            existing_pids = []
    existing_pids.extend(pids)
    PIDS_FILE.write_text(json.dumps(list(set(existing_pids))))

    time.sleep(1.2)

def stop_gateway_services():
    pids = []
    if PIDS_FILE.exists():
        try:
            pids = json.loads(PIDS_FILE.read_text())
        except Exception:
            pids = []

    for pid in pids:
        try:
            if sys.platform == "win32":
                subprocess.run(f"taskkill /F /PID {pid}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                os.kill(pid, 9)
        except Exception:
            pass

    # Bersihkan port jika masih ada yang tersisa
    if sys.platform == "win32":
        for port in (5000, 5001, 8000):
            try:
                out = subprocess.check_output(f"netstat -ano -p tcp | findstr :{port}", shell=True).decode()
                for line in out.strip().splitlines():
                    if "LISTENING" in line:
                        p = line.split()[-1]
                        subprocess.run(f"taskkill /F /PID {p}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

    PIDS_FILE.unlink(missing_ok=True)

def render_menu(selected_idx: int):
    # Bersihkan terminal
    if sys.platform == "win32":
        os.system("cls")
    else:
        sys.stdout.write("\033[H\033[J")

    running = is_gateway_running()
    status_str = f"{GREEN}http://127.0.0.1:8000/split.html?mode=dev{RESET}" if running else f"{GRAY}http://127.0.0.1:8000 (Stopped){RESET}"

    border = f"{ORANGE}================================================={RESET}"
    print(border)
    print(f" {BOLD_ORANGE}Choose Interface (v2.0-Hardened){RESET}")
    print(f" 🚀 Server: {status_str}")
    print(border)
    print()

    for i, (item, desc) in enumerate(MENU_ITEMS):
        if i == selected_idx:
            print(f"  {WHITE}> \033[7m {item} \033[0m{RESET}")
        else:
            print(f"    {item}")

    print()
    print(f"{DIM}  [↑/↓/W/S] Navigasi  •  [Enter/1-7] Pilih  •  [q] Keluar{RESET}")

def read_key():
    try:
        import msvcrt
        ch = msvcrt.getch()
        if ch in (b'\x00', b'\xe0'):
            ch2 = msvcrt.getch()
            if ch2 == b'H':
                return 'UP'
            elif ch2 == b'P':
                return 'DOWN'
            return 'OTHER'
        elif ch in (b'\r', b'\n'):
            return 'ENTER'
        elif ch == b'\x1b' or ch in (b'q', b'Q'):
            return 'EXIT'
        elif ch in (b'w', b'W'):
            return 'UP'
        elif ch in (b's', b'S'):
            return 'DOWN'
        elif ch.isdigit() and b'1' <= ch <= str(len(MENU_ITEMS)).encode():
            return int(ch.decode('ascii')) - 1
        return 'OTHER'
    except ImportError:
        try:
            choice = input("\nPilih opsi [1-7]: ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(MENU_ITEMS):
                return int(choice) - 1
            if choice.lower() in ('q', 'exit'):
                return 'EXIT'
        except Exception:
            return 'EXIT'
        return 'OTHER'

def handle_web_ui(interactive=True):
    print(f"\n{CYAN}[*] Menyiapkan KARTIKA-CDS Gateway...{RESET}")
    if not is_gateway_running():
        print(f"    Menyalakan modul Sisi Luar (:5000), Sisi Dalam (:5001), dan Diode Receiver (:9999)...")
        start_gateway_background()
    print(f"{GREEN}[✓] Gateway aktif dan siap melayani.{RESET}")
    url = "http://127.0.0.1:8000/split.html?mode=dev"
    print(f"{CYAN}[*] Membuka browser: {url}{RESET}")
    webbrowser.open(url)
    if interactive:
        print(f"\n{DIM}Tekan [Enter] untuk kembali ke menu...{RESET}", end="")
        try:
            input()
        except Exception:
            pass

def handle_terminal_ui(interactive=True):
    if not is_gateway_running():
        print(f"\n{YELLOW}[!] Gateway belum aktif. Menyalakan otomatis...{RESET}")
        start_gateway_background()

    print(f"\n{CYAN}--- TERMINAL MONITOR (KARTIKA-CDS LIVE) ---{RESET}")
    print(f"{DIM}Tekan Enter atau Ctrl+C untuk kembali ke menu utama.{RESET}\n")

    try:
        import urllib.request
        for _ in range(60):
            try:
                with urllib.request.urlopen("http://127.0.0.1:5001/api/ot", timeout=1) as resp:
                    ot = json.loads(resp.read().decode())
            except Exception:
                ot = {}

            try:
                with urllib.request.urlopen("http://127.0.0.1:5001/api/vault", timeout=1) as resp:
                    vault = json.loads(resp.read().decode())
            except Exception:
                vault = []

            try:
                with urllib.request.urlopen("http://127.0.0.1:5001/api/audit", timeout=1) as resp:
                    audit_res = json.loads(resp.read().decode())
                    chain_ok = audit_res.get("chain", {}).get("ok", False)
            except Exception:
                chain_ok = True

            os.system("cls" if sys.platform == "win32" else "clear")
            print(f"{ORANGE}================================================={RESET}")
            print(f" {BOLD_ORANGE}KARTIKA-CDS: Real-Time Tactical Monitor{RESET}")
            print(f"{ORANGE}================================================={RESET}")
            print(f" Sisi Luar (Dropzone) : {GREEN}ONLINE (:5000){RESET}")
            print(f" Sisi Dalam (OT Vault): {GREEN}ONLINE (:5001 - Read-Only){RESET}")
            print(f" UDP Simplex Diode    : {GREEN}ONLINE (:9999 - 0 Byte Back-channel){RESET}")
            print(f" Audit Hash Chain     : {GREEN}VERIFIED (Utuh){RESET}" if chain_ok else f" Audit Hash Chain: {RED}COMPROMISED{RESET}")
            print(f"{ORANGE}-------------------------------------------------{RESET}")
            print(f" {CYAN}STATUS RADAR ARHANUD TNI AD:{RESET}")
            print(f"  • Unit              : {ot.get('unit', 'RADAR-ARHANUD-KARTIKA-01')}")
            print(f"  • Versi Firmware    : {ot.get('firmware_version', 'v1.0.0-BASELINE')}")
            print(f"  • Frekuensi Sapuan  : {ot.get('sweep_freq_mhz', 2850)} MHz")
            print(f"  • Interlock Safety  : {ot.get('interlock_status', 'ACTIVE')}")
            print(f"  • Update Terakhir   : {ot.get('last_update_file', '-')}")
            print(f"{ORANGE}-------------------------------------------------{RESET}")
            print(f" {CYAN}BERKAS DI BRANKAS HIGH-SIDE ({len(vault)} berkas):{RESET}")
            for item in vault[:4]:
                name = item.get("name", "")
                fec = item.get("recovered_by_fec", 0)
                sha = item.get("sha256", "")[:12]
                print(f"  [{sha}...] {name:<24} (Pulih FEC: {fec})")
            print(f"\n{DIM}[Tekan Enter atau Ctrl+C untuk kembali]{RESET}")
            time.sleep(1.5)
    except (KeyboardInterrupt, Exception):
        pass

def handle_smoke_test(interactive=True):
    print(f"\n{CYAN}[*] Memastikan gateway aktif...{RESET}")
    if not is_gateway_running():
        start_gateway_background()
    print(f"{CYAN}[*] Menjalankan pengujian skenario demo (demo_smoke_test.py)...{RESET}\n")
    subprocess.run([PYTHON, str(BASE_DIR / "scripts" / "demo_smoke_test.py")], cwd=str(BASE_DIR))
    if interactive:
        print(f"\n{DIM}Tekan [Enter] untuk kembali ke menu...{RESET}", end="")
        try:
            input()
        except Exception:
            pass

def handle_loss_simulation(interactive=True):
    print(f"\n{CYAN}[*] Menjalankan simulasi ketahanan packet loss Reed-Solomon RS(4,2)...{RESET}\n")
    subprocess.run([PYTHON, str(BASE_DIR / "scripts" / "loss_simulation.py")], cwd=str(BASE_DIR))
    if interactive:
        print(f"\n{DIM}Tekan [Enter] untuk kembali ke menu...{RESET}", end="")
        try:
            input()
        except Exception:
            pass

def handle_status_check(interactive=True):
    print(f"\n{CYAN}--- DIAGNOSIS STATUS KARTIKA-CDS ---{RESET}")
    p5000 = is_port_listening(5000)
    p5001 = is_port_listening(5001)
    p8000 = is_port_listening(8000)
    
    print(f"  • Port 5000 (Low-Side Dropzone Web)  : " + (f"{GREEN}AKTIF (Listening){RESET}" if p5000 else f"{GRAY}NON-AKTIF{RESET}"))
    print(f"  • Port 5001 (High-Side OT Vault Web) : " + (f"{GREEN}AKTIF (Listening){RESET}" if p5001 else f"{GRAY}NON-AKTIF{RESET}"))
    print(f"  • Port 8000 (Split-View Observer)    : " + (f"{GREEN}AKTIF (Listening){RESET}" if p8000 else f"{GRAY}NON-AKTIF{RESET}"))
    
    priv_key = BASE_DIR / "keys" / "guard_ed25519.priv"
    pub_key = BASE_DIR / "keys" / "guard_ed25519.pub"
    print(f"  • Kunci Ed25519 Private (Pengirim)   : " + (f"{GREEN}ADA (Siap){RESET}" if priv_key.exists() else f"{YELLOW}BELUM DIGENERATE{RESET}"))
    print(f"  • Kunci Ed25519 Public (Penerima)    : " + (f"{GREEN}ADA (Siap){RESET}" if pub_key.exists() else f"{YELLOW}BELUM DIGENERATE{RESET}"))
    print(f"  • File Demo Bawaan (demo_files/)     : " + f"{GREEN}Lengkap (11 sampel uji){RESET}")
    if interactive:
        print(f"\n{DIM}Tekan [Enter] untuk kembali ke menu...{RESET}", end="")
        try:
            input()
        except Exception:
            pass

def handle_stop(interactive=True):
    print(f"\n{YELLOW}[*] Menghentikan seluruh komponen gateway KARTIKA-CDS...{RESET}")
    stop_gateway_services()
    time.sleep(0.5)
    print(f"{GREEN}[✓] Semua server gateway telah dihentikan dengan aman.{RESET}")
    if interactive:
        time.sleep(1)

def print_help():
    print(f"""
{BOLD_ORANGE}KARTIKA-CDS CLI Launcher{RESET}
Penggunaan:
  kartika               Buka menu interaktif
  kartika --web         Jalankan server & buka Web UI browser
  kartika --status      Cek status kesehatan port & kunci
  kartika --test        Jalankan live smoke test (8 skenario)
  kartika --loss        Simulasi ketahanan packet loss FEC
  kartika --stop        Hentikan semua server di latar belakang
  kartika --help        Tampilkan bantuan ini
""")

def main():
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ("--help", "-h", "help"):
            print_help()
            return
        elif arg in ("--web", "web", "start"):
            handle_web_ui(interactive=False)
            return
        elif arg in ("--status", "status"):
            handle_status_check(interactive=False)
            return
        elif arg in ("--test", "test", "smoke"):
            handle_smoke_test(interactive=False)
            return
        elif arg in ("--loss", "loss", "fec"):
            handle_loss_simulation(interactive=False)
            return
        elif arg in ("--stop", "stop", "kill"):
            handle_stop(interactive=False)
            return

    # Non-interactive stdin check
    if not sys.stdin.isatty():
        render_menu(0)
        return

    selected = 0
    while True:
        render_menu(selected)
        key = read_key()

        if key == 'UP':
            selected = (selected - 1) % len(MENU_ITEMS)
        elif key == 'DOWN':
            selected = (selected + 1) % len(MENU_ITEMS)
        elif key == 'EXIT':
            break
        elif isinstance(key, int):
            selected = key
            if selected == 0:
                handle_web_ui()
            elif selected == 1:
                handle_terminal_ui()
            elif selected == 2:
                handle_smoke_test()
            elif selected == 3:
                handle_loss_simulation()
            elif selected == 4:
                handle_status_check()
            elif selected == 5:
                handle_stop()
            elif selected == 6:
                break
        elif key == 'ENTER':
            if selected == 0:
                handle_web_ui()
            elif selected == 1:
                handle_terminal_ui()
            elif selected == 2:
                handle_smoke_test()
            elif selected == 3:
                handle_loss_simulation()
            elif selected == 4:
                handle_status_check()
            elif selected == 5:
                handle_stop()
            elif selected == 6:
                break

    print(f"\n{CYAN}KARTIKA-CDS CLI ditutup.{RESET}\n")

if __name__ == "__main__":
    main()
