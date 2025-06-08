#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import secrets
import string
import argparse
import time
import requests

# --- 脚本元数据 ---
# 确保这里是你自己的 GitHub Raw 链接
SCRIPT_URL = "https://raw.githubusercontent.com/your_username/your_repo/main/hysteria_installer.py"

# --- Hysteria 默认配置 ---
DEFAULT_PORT = 443
HYSTERIA_LATEST_RELEASE_URL = "https://api.github.com/repos/apernet/hysteria/releases/latest"
HYSTERIA_INSTALL_DIR = "/usr/local/bin"
HYSTERIA_CONFIG_DIR = "/etc/hysteria"
HYSTERIA_EXECUTABLE = os.path.join(HYSTERIA_INSTALL_DIR, "hysteria")
CONFIG_PATH = os.path.join(HYSTERIA_CONFIG_DIR, "config.json")
SYSTEMD_SERVICE_FILE = "/etc/systemd/system/hysteria-server.service"

# --- 颜色定义 ---
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[1;36m'
NC = '\033[0m'

# ==================== FIX STARTS HERE ====================
# 修正 run_command 函数
def run_command(command, check=True, text=True, capture_output=True, shell=False):
    """执行 shell 命令。可以接收列表或字符串形式的命令。"""
    display_command = command if isinstance(command, str) else ' '.join(command)
    print(f"[*] 正在执行: {display_command}")

    try:
        # 当 shell=True 时，命令必须是字符串。
        # 当 shell=False 时，命令应该是列表。
        result = subprocess.run(
            command,
            check=check,
            text=text,
            capture_output=capture_output,
            encoding='utf-8',
            shell=shell
        )
        if result.stdout and capture_output:
            # 避免打印过多acme.sh安装日志
            if "acme.sh" not in display_command:
                print(result.stdout)
        if result.stderr and capture_output:
            print(result.stderr)
        return result
    except FileNotFoundError:
        cmd_name = command.split()[0] if isinstance(command, str) else command[0]
        print(f"[!] 错误: 命令 '{cmd_name}' 未找到。请确保它已安装并位于 PATH 中。")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[!] 命令执行失败，返回码: {e.returncode}")
        if capture_output:
            print(f"--- STDOUT ---\n{e.stdout}")
            print(f"--- STDERR ---\n{e.stderr}")
        sys.exit(1)
# ===================== FIX ENDS HERE =====================

def check_root():
    """检查是否以 root 权限运行"""
    if os.geteuid() != 0:
        print("[!] 请以 root 权限运行此脚本。")
        sys.exit(1)

def get_system_arch():
    """获取系统架构"""
    arch = os.uname().machine
    if arch == "x86_64":
        return "amd64"
    elif arch == "aarch64":
        return "arm64"
    else:
        print(f"[!] 不支持的架构: {arch}")
        sys.exit(1)

def get_latest_hysteria_url():
    """从 GitHub API 获取最新的 Hysteria 2 版本下载链接"""
    print("\n--- 获取 Hysteria 最新版本 ---")
    try:
        response = requests.get(HYSTERIA_LATEST_RELEASE_URL, timeout=15)
        response.raise_for_status()
        release_info = response.json()
        target_arch = get_system_arch()
        for asset in release_info["assets"]:
            asset_name = asset["name"]
            if "linux" in asset_name and target_arch in asset_name:
                print(f"[*] 找到适合的版本: {asset_name}")
                return asset["browser_download_url"]
        print("[!] 未找到适合当前架构的 Hysteria 版本。")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[!] 获取最新版本失败: {e}")
        fallback_arch = get_system_arch()
        fallback_url = f"https://github.com/apernet/hysteria/releases/download/v2.4.0/hysteria-linux-{fallback_arch}"
        print(f"[*] 尝试使用备用下载链接: {fallback_url}")
        return fallback_url

def install_hysteria(args):
    """安装 Hysteria"""
    print(f"{CYAN}--- 开始安装 Hysteria 2 ---{NC}")
    check_root()

    # 1. 安装依赖
    print("\n--- 1. 安装依赖 (curl, wget, socat, ufw) ---")
    run_command(["apt-get", "update"])
    run_command(["apt-get", "install", "-y", "curl", "wget", "socat", "ufw"])

    # 2. 下载并安装 Hysteria 主程序
    print("\n--- 2. 下载并安装 Hysteria ---")
    hysteria_url = get_latest_hysteria_url()
    run_command(["wget", "-O", HYSTERIA_EXECUTABLE, hysteria_url])
    run_command(["chmod", "+x", HYSTERIA_EXECUTABLE])
    print(f"[*] Hysteria 已安装到 {HYSTERIA_EXECUTABLE}")
    run_command([HYSTERIA_EXECUTABLE, "version"])

    # 3. 配置 TLS
    print("\n--- 3. 配置 TLS 证书 ---")
    # 如果参数未提供，则进入交互模式
    domain = args.domain if args.domain else input("👉 请输入你的域名或服务器IP: ")
    port_str = str(args.port) if args.port else input(f"👉 请输入端口 (回车默认 {DEFAULT_PORT}): ")
    port = int(port_str) if port_str else DEFAULT_PORT
    password = args.password if args.password else ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(20))

    cert_path, key_path = None, None
    is_ip_address = all(c in '0123456789.' for c in domain) and len(domain.split('.')) == 4

    if is_ip_address:
        print("[*] 检测到使用的是 IP 地址，将使用自签名证书。")
    else:
        print(f"[*] 为域名 {domain} 申请 Let's Encrypt 证书...")
        run_command(["apt-get", "install", "-y", "cron"])
        
        print("[*] 正在安装 acme.sh...")
        acme_install_cmd = "curl https://get.acme.sh | sh -s email=my@example.com"
        run_command(acme_install_cmd, shell=True) # 使用 shell=True 执行字符串命令

        acme_sh_path = os.path.expanduser("~/.acme.sh/acme.sh")
        if not os.path.exists(acme_sh_path):
            print(f"[!] acme.sh 安装失败，未在 {acme_sh_path} 找到。")
            sys.exit(1)

        print("[*] 临时开放 80 端口用于 Let's Encrypt 验证...")
        run_command(["ufw", "allow", "80/tcp"])
        issue_cmd = [
            acme_sh_path, "--issue", "-d", domain, "--standalone",
            "--keylength", "ec-256", "--server", "letsencrypt", "--force"
        ]
        run_command(issue_cmd)
        run_command(["ufw", "delete", "allow", "80/tcp"])
        
        cert_path = f"/root/.acme.sh/{domain}_ecc/fullchain.cer"
        key_path = f"/root/.acme.sh/{domain}_ecc/{domain}.key"
        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            print("[!] 证书申请失败，请检查域名解析和防火墙设置。")
            sys.exit(1)
        print("[*] 证书申请成功！")

    # 4. 创建配置文件
    print("\n--- 4. 创建 Hysteria 配置文件 ---")
    os.makedirs(HYSTERIA_CONFIG_DIR, exist_ok=True)
    config = {
        "listen": f":{port}",
        "auth": {"type": "password", "password": password},
        "masquerade": {
            "type": "proxy",
            "proxy": {"url": "https://bing.com", "rewriteHost": True}
        }
    }
    if cert_path and key_path:
        config["tls"] = {"cert": cert_path, "key": key_path}
    
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)
    print(f"[*] 配置文件已创建: {CONFIG_PATH}")

    # 5. 配置 Systemd 服务
    print("\n--- 5. 配置 Systemd 服务 ---")
    service_content = f"""
[Unit]
Description=Hysteria 2 Service
After=network.target
[Service]
Type=simple
ExecStart={HYSTERIA_EXECUTABLE} server --config {CONFIG_PATH}
WorkingDirectory={HYSTERIA_CONFIG_DIR}
User=root
Group=root
Environment="HYSTERIA_LOG_LEVEL=info"
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
"""
    with open(SYSTEMD_SERVICE_FILE, 'w') as f:
        f.write(service_content)

    # 6. 配置防火墙并启动服务
    print("\n--- 6. 配置防火墙并启动服务 ---")
    run_command(["systemctl", "daemon-reload"])
    run_command(["systemctl", "enable", "hysteria-server"])
    run_command(["ufw", "allow", f"{port}/udp"], check=False)
    run_command(["ufw", "allow", f"{port}/tcp"], check=False)
    run_command(["ufw", "allow", "ssh"], check=False)
    run_command(["ufw", "--force", "enable"])
    run_command(["systemctl", "restart", "hysteria-server"])
    
    print("[*] 等待服务启动...")
    time.sleep(3)
    run_command(["systemctl", "status", "hysteria-server"], check=False, capture_output=False)

    print(f"\n{GREEN}🎉 Hysteria 2 节点部署完成! 🎉{NC}")
    display_info(domain, port, password, bool(cert_path))

# (其余函数：uninstall_hysteria, update_hysteria 等保持不变)
# ...
def uninstall_hysteria(args):
    """卸载 Hysteria"""
    print(f"{YELLOW}--- 开始卸载 Hysteria 2 ---{NC}")
    check_root()
    
    run_command(["systemctl", "stop", "hysteria-server"], check=False)
    run_command(["systemctl", "disable", "hysteria-server"], check=False)
    print("[*] Hysteria 服务已停止并禁用。")

    if os.path.exists(SYSTEMD_SERVICE_FILE):
        os.remove(SYSTEMD_SERVICE_FILE)
        print(f"[*] 已删除文件: {SYSTEMD_SERVICE_FILE}")
    if os.path.exists(HYSTERIA_EXECUTABLE):
        os.remove(HYSTERIA_EXECUTABLE)
        print(f"[*] 已删除文件: {HYSTERIA_EXECUTABLE}")

    if os.path.exists(HYSTERIA_CONFIG_DIR):
        config_file_path = os.path.join(HYSTERIA_CONFIG_DIR, "config.json")
        port_to_delete = None
        if os.path.exists(config_file_path):
            try:
                with open(config_file_path, 'r') as f:
                    config = json.load(f)
                    port_to_delete = config.get("listen", f":{DEFAULT_PORT}").split(':')[-1]
            except Exception:
                 print("[!] 无法读取旧的端口配置。")
        
        import shutil
        shutil.rmtree(HYSTERIA_CONFIG_DIR)
        print(f"[*] 已删除目录及其内容: {HYSTERIA_CONFIG_DIR}")
        
        if port_to_delete:
            run_command(["ufw", "delete", "allow", f"{port_to_delete}/udp"], check=False)
            run_command(["ufw", "delete", "allow", f"{port_to_delete}/tcp"], check=False)
            print(f"[*] 已删除端口 {port_to_delete} 的防火墙规则。")

    acme_uninstall_cmd = os.path.expanduser("~/.acme.sh/acme.sh")
    if os.path.exists(acme_uninstall_cmd):
        print("[*] 正在卸载 acme.sh...")
        run_command([acme_uninstall_cmd, "--uninstall"], check=False)
        shutil.rmtree(os.path.expanduser("~/.acme.sh"), ignore_errors=True)
        print("[*] acme.sh 已卸载。")


    run_command(["systemctl", "daemon-reload"])
    print(f"{GREEN}✅ Hysteria 卸载完成。{NC}")


def update_hysteria(args):
    """更新 Hysteria 到最新版本"""
    print(f"{CYAN}--- 开始更新 Hysteria 2 ---{NC}")
    check_root()
    if not os.path.exists(HYSTERIA_EXECUTABLE):
        print("[!] Hysteria 未安装，请先执行 install 命令。")
        return
        
    hysteria_url = get_latest_hysteria_url()
    run_command(["wget", "-O", HYSTERIA_EXECUTABLE, hysteria_url])
    run_command(["chmod", "+x", HYSTERIA_EXECUTABLE])
    print("[*] Hysteria 主程序已更新。")
    restart_service({})
    run_command([HYSTERIA_EXECUTABLE, "version"])
    print(f"{GREEN}✅ Hysteria 更新完成。{NC}")

def restart_service(args):
    """重启服务"""
    print(f"{CYAN}--- 重启 Hysteria 服务 ---{NC}")
    check_root()
    run_command(["systemctl", "restart", "hysteria-server"])
    time.sleep(2)
    run_command(["systemctl", "status", "hysteria-server"], check=False, capture_output=False)
    print(f"{GREEN}✅ Hysteria 服务已重启。{NC}")

def view_log(args):
    """查看日志"""
    print(f"{CYAN}--- 查看 Hysteria 实时日志 (按 Ctrl+C 退出) ---{NC}")
    check_root()
    try:
        run_command(["journalctl", "-u", "hysteria-server", "-f", "--no-pager"], capture_output=False)
    except KeyboardInterrupt:
        print("\n[*] 已退出日志查看。")

def display_info(domain=None, port=None, password=None, is_tls=None):
    """显示配置信息"""
    print(f"{CYAN}--- 当前 Hysteria 配置信息 ---{NC}")
    config_file_path = os.path.join(HYSTERIA_CONFIG_DIR, "config.json")
    if not os.path.exists(config_file_path):
        print("[!] 未找到配置文件，请先执行 install 命令。")
        return

    try:
        if all(v is None for v in [domain, port, password, is_tls]):
            with open(config_file_path, 'r') as f:
                config = json.load(f)
            
            listen_address = config.get("listen", "N/A")
            port = listen_address.split(':')[-1]
            password = config.get("auth", {}).get("password", "N/A")
            is_tls = "tls" in config

            if is_tls:
                cert_path = config["tls"]["cert"]
                domain = cert_path.split('/')[3].replace('_ecc', '')
            else:
                # 无法从自签名证书中获取IP，只能提示用户
                domain = "服务器IP (请自行确认)"

        tls_type_str = "Let's Encrypt" if is_tls else "自签名证书"
        insecure_flag = "" if is_tls else "?insecure=1"
        display_domain = domain
        if not is_tls:
            display_domain = f"{domain} (Self-signed)"

        url = f"hysteria2://{password}@{domain}:{port}{insecure_flag}#Hysteria"
        
        print(f"  {YELLOW}服务器地址:{NC} {display_domain}")
        print(f"  {YELLOW}端口:{NC} {port}")
        print(f"  {YELLOW}密码:{NC} {password}")
        print(f"  {YELLOW}TLS:{NC} {tls_type_str}")
        print(f"\n{GREEN}连接 URL:{NC}\n{url}")

    except Exception as e:
        print(f"[!] 读取配置失败: {e}")

def main():
    parser = argparse.ArgumentParser(description="Hysteria 2 一键安装管理脚本", formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(dest="action", help="可执行的操作")
    subparsers.required = True

    parser_install = subparsers.add_parser("install", help="安装 Hysteria 2")
    parser_install.add_argument("-d", "--domain", type=str, help="你的域名或服务器 IP")
    parser_install.add_argument("-p", "--port", type=int, help=f"指定端口 (默认: {DEFAULT_PORT})")
    parser_install.add_argument("--password", type=str, help="指定连接密码 (默认: 随机生成)")
    parser_install.set_defaults(func=install_hysteria)
    
    # 定义其他命令...
    for cmd, (func, help_text) in {
        "uninstall": (uninstall_hysteria, "卸载 Hysteria 2 和 acme.sh"),
        "update": (update_hysteria, "更新 Hysteria 2 到最新版"),
        "restart": (restart_service, "重启 Hysteria 服务"),
        "log": (view_log, "查看 Hysteria 实时日志"),
        "info": (lambda args: display_info(), "显示当前配置信息")
    }.items():
        p = subparsers.add_parser(cmd, help=help_text)
        p.set_defaults(func=func)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
