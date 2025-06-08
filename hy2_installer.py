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
# 假设你的脚本托管在 'https://raw.githubusercontent.com/your_username/your_repo/main/hysteria_installer.py'
SCRIPT_URL = "https://raw.githubusercontent.com/your_username/your_repo/main/hysteria_installer.py" # <--- !! 请务必修改为你的脚本在 GitHub 上的 RAW 链接 !!

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
NC = '\033[0m' # No Color

def run_command(command, check=True, text=True, capture_output=True):
    """执行 shell 命令"""
    print(f"[*] 正在执行: {' '.join(command)}")
    try:
        result = subprocess.run(
            command, check=check, text=text, capture_output=capture_output, encoding='utf-8'
        )
        if result.stdout and capture_output:
            print(result.stdout)
        if result.stderr and capture_output:
            print(result.stderr)
        return result
    except FileNotFoundError:
        print(f"[!] 错误: 命令 '{command[0]}' 未找到。请确保它已安装并位于 PATH 中。")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[!] 命令执行失败，返回码: {e.returncode}")
        if capture_output:
            print(f"--- STDOUT ---\n{e.stdout}")
            print(f"--- STDERR ---\n{e.stderr}")
        sys.exit(1)

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
        response = requests.get(HYSTERIA_LATEST_RELEASE_URL, timeout=10)
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
        # 提供一个备用下载地址
        fallback_arch = get_system_arch()
        fallback_url = f"https://github.com/apernet/hysteria/releases/download/v2.3.0/hysteria-linux-{fallback_arch}"
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
    domain = args.domain if args.domain else input("请输入你的域名或 IP 地址: ")
    port = args.port if args.port else DEFAULT_PORT
    password = args.password if args.password else ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(20))

    cert_path, key_path = None, None
    is_ip_address = all(c in '0123456789.' for c in domain)

    if is_ip_address:
        print("[*] 检测到使用的是 IP 地址，将使用自签名证书。")
    else:
        print(f"[*] 为域名 {domain} 申请 Let's Encrypt 证书...")
        run_command(["apt-get", "install", "-y", "cron"])
        run_command(["curl", "https://get.acme.sh", "|", "sh"], check=False)
        acme_sh_path = os.path.expanduser("~/.acme.sh/acme.sh")
        print("[*] 临时开放 80 端口用于 Let's Encrypt 验证...")
        run_command(["ufw", "allow", "80/tcp"])
        issue_cmd = [
            acme_sh_path, "--issue", "-d", domain, "--standalone",
            "--keylength", "ec-256", "--server", "letsencrypt"
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
    run_command(["systemctl", "status", "hysteria-server"], check=False)

    print(f"\n{GREEN}🎉 Hysteria 2 节点部署完成! 🎉{NC}")
    display_info()

def uninstall_hysteria(args):
    """卸载 Hysteria"""
    print(f"{YELLOW}--- 开始卸载 Hysteria 2 ---{NC}")
    check_root()
    
    # 停止并禁用服务
    run_command(["systemctl", "stop", "hysteria-server"], check=False)
    run_command(["systemctl", "disable", "hysteria-server"], check=False)
    print("[*] Hysteria 服务已停止并禁用。")

    # 删除文件
    files_to_remove = [HYSTERIA_EXECUTABLE, CONFIG_PATH, SYSTEMD_SERVICE_FILE]
    for f in files_to_remove:
        if os.path.exists(f):
            os.remove(f)
            print(f"[*] 已删除文件: {f}")
    if os.path.exists(HYSTERIA_CONFIG_DIR):
        os.rmdir(HYSTERIA_CONFIG_DIR)
        print(f"[*] 已删除目录: {HYSTERIA_CONFIG_DIR}")
    
    # 清理防火墙规则
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                config = json.load(f)
                port = config.get("listen", f":{DEFAULT_PORT}").split(':')[-1]
                run_command(["ufw", "delete", "allow", f"{port}/udp"], check=False)
                run_command(["ufw", "delete", "allow", f"{port}/tcp"], check=False)
                print(f"[*] 已删除端口 {port} 的防火墙规则。")
        except (FileNotFoundError, json.JSONDecodeError):
             print("[!] 无法读取旧的端口配置，请手动删除防火墙规则。")

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
    run_command(["systemctl", "status", "hysteria-server"], check=False)
    print(f"{GREEN}✅ Hysteria 服务已重启。{NC}")

def view_log(args):
    """查看日志"""
    print(f"{CYAN}--- 查看 Hysteria 实时日志 (按 Ctrl+C 退出) ---{NC}")
    check_root()
    try:
        # 使用 subprocess.run 而不是 os.system，以便在 Ctrl+C 时能正常退出脚本
        run_command(["journalctl", "-u", "hysteria-server", "-f", "--no-pager"], capture_output=False)
    except KeyboardInterrupt:
        print("\n[*] 已退出日志查看。")

def display_info():
    """显示配置信息"""
    print(f"{CYAN}--- 当前 Hysteria 配置信息 ---{NC}")
    if not os.path.exists(CONFIG_PATH):
        print("[!] 未找到配置文件，请先执行 install 命令。")
        return

    try:
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
        
        listen_address = config.get("listen", "N/A")
        port = listen_address.split(':')[-1]
        password = config.get("auth", {}).get("password", "N/A")
        
        domain = "IP Address (Self-signed)"
        insecure_flag = "insecure=1"
        if "tls" in config:
            cert_path = config["tls"]["cert"]
            # 从证书路径中提取域名
            domain = cert_path.split('/')[3].replace('_ecc', '')
            insecure_flag = ""

        print(f"  {YELLOW}服务器地址:{NC} {domain}")
        print(f"  {YELLOW}端口:{NC} {port}")
        print(f"  {YELLOW}密码:{NC} {password}")
        print(f"  {YELLOW}TLS:{NC} {'Let\'s Encrypt' if 'tls' in config else '自签名证书'}")
        
        url = f"hysteria2://{password}@{domain}:{port}?{insecure_flag}#MyHysteriaServer"
        print(f"\n{GREEN}连接 URL:{NC}\n{url.replace('?#', '#')}")

    except (Exception) as e:
        print(f"[!] 读取配置失败: {e}")

def main():
    """主函数，解析命令行参数"""
    parser = argparse.ArgumentParser(description="Hysteria 2 一键安装管理脚本")
    subparsers = parser.add_subparsers(dest="action", help="可执行的操作")
    subparsers.required = True

    # 安装命令
    parser_install = subparsers.add_parser("install", help="安装 Hysteria 2")
    parser_install.add_argument("-d", "--domain", type=str, help="你的域名或服务器 IP")
    parser_install.add_argument("-p", "--port", type=int, help=f"指定端口 (默认: {DEFAULT_PORT})")
    parser_install.add_argument("--password", type=str, help="指定连接密码 (默认: 随机生成)")
    parser_install.set_defaults(func=install_hysteria)

    # 卸载命令
    parser_uninstall = subparsers.add_parser("uninstall", help="卸载 Hysteria 2")
    parser_uninstall.set_defaults(func=uninstall_hysteria)

    # 更新命令
    parser_update = subparsers.add_parser("update", help="更新 Hysteria 2 到最新版")
    parser_update.set_defaults(func=update_hysteria)
    
    # 重启命令
    parser_restart = subparsers.add_parser("restart", help="重启 Hysteria 服务")
    parser_restart.set_defaults(func=restart_service)

    # 日志命令
    parser_log = subparsers.add_parser("log", help="查看 Hysteria 实时日志")
    parser_log.set_defaults(func=view_log)
    
    # 信息命令
    parser_info = subparsers.add_parser("info", help="显示当前配置信息")
    parser_info.set_defaults(func=display_info)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
