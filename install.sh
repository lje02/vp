#!/bin/bash
# 一键部署 VPS 管理面板 (vp)

REPO_URL="https://raw.githubusercontent.com/lje02/vp/main"
INSTALL_DIR="/usr/local/bin"
MODULES_DIR="/usr/local/share/vn_modules"
set -e

# root 检测：安装目标在 /usr/local/bin 和 /usr/local/share，非 root 会在 mkdir/curl -o 处报一堆不明所以的权限错误
if [ "$EUID" -ne 0 ]; then
    echo "错误：此脚本必须以 root 权限运行（例如使用 sudo bash install.sh）。"
    exit 1
fi

# 精简系统自举：这一步 common.sh 还没下载下来，用不了里面的 check_dependencies，
# 所以单独做一次最小化检测，确保 curl 可用（很多精简 Docker/LXC 镜像默认不带 curl）。
ensure_curl() {
    if command -v curl &>/dev/null; then
        return
    fi

    echo "未检测到 curl，尝试自动安装..."

    if [ ! -f /etc/os-release ]; then
        echo "无法识别系统类型，且未安装 curl，请手动安装 curl 后重试。"
        exit 1
    fi
    . /etc/os-release
    local os_id="$ID"
    local os_like="$ID_LIKE"

    if [[ "$os_id" =~ ^(debian|ubuntu|kali|raspbian)$ ]] || [[ "$os_like" =~ (debian|ubuntu) ]]; then
        apt-get update -qq && apt-get install -y curl
    elif [[ "$os_id" =~ ^(centos|rhel|fedora|rocky|alma)$ ]] || [[ "$os_like" =~ (rhel|fedora|centos) ]]; then
        if command -v dnf &>/dev/null; then
            dnf install -y curl
        else
            yum install -y curl
        fi
    else
        echo "不支持的系统：$os_id，且未安装 curl，请手动安装 curl 后重试。"
        exit 1
    fi

    if ! command -v curl &>/dev/null; then
        echo "curl 自动安装失败，请手动安装后重试。"
        exit 1
    fi
    echo "curl 安装完成。"
}

ensure_curl

mkdir -p "$MODULES_DIR"

# 下载公共库和主控
echo "下载公共库和主控..."
curl -fsSL "$REPO_URL/common.sh" -o "$MODULES_DIR/common.sh" || { echo "公共库下载失败"; exit 1; }
curl -fsSL "$REPO_URL/vn" -o "$INSTALL_DIR/vn" || { echo "主控下载失败"; exit 1; }
chmod +x "$INSTALL_DIR/vn"

# 静态后备模块列表
BASE_MODULES=(
    "firewall_fail2ban.sh"
    "system_optimize.sh"
    "remote_jump.sh"
    "singbox.sh"
    "monitor.sh"
    "ssh_harden.sh"
    "traffic_monitor.sh"
    "logs.sh"
    "wireguard-mesh.sh"
    "nginx-gateway.sh"
    "vps-security-check.sh"
)

# 动态提取主控中的 MODULES_LIST
modules=()
if [ -f "$INSTALL_DIR/vn" ]; then
    modules=($(awk '/^MODULES_LIST=\(/ {flag=1; next} /^\)/ {flag=0} flag {gsub(/"/, ""); if ($1 ~ /\.sh$/) print $1}' "$INSTALL_DIR/vn"))
fi

# 提取为空时使用静态列表
if [ ${#modules[@]} -eq 0 ]; then
    modules=("${BASE_MODULES[@]}")
    echo "使用静态模块列表"
fi

echo -n "下载模块中"
for mod in "${modules[@]}"; do
    # 增加 -f 参数并在下载后校验文件是否为空
    if curl -fsSL "$REPO_URL/modules/$mod" -o "$MODULES_DIR/$mod" 2>/dev/null && [ -s "$MODULES_DIR/$mod" ]; then
        chmod +x "$MODULES_DIR/$mod" 2>/dev/null
        echo -n "."
    else
        echo -n "!"
        rm -f "$MODULES_DIR/$mod" # 清理下载失败或为空的文件
    fi
done
echo " 完成"

echo ""
echo "安装完成！输入 'vn' 即可启动管理面板。"
