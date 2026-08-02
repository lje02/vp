#!/bin/bash
# 公共库

# 颜色
CYAN='\033[1;36m'
PURPLE='\033[1;35m'
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
PLAIN='\033[0m'
NC='\033[0m'

# 资源路径
GITHUB_RAW_URL="https://raw.githubusercontent.com/lje02/vp/main/vn"

# 临时文件清理
cleanup() {
    rm -f /tmp/vn_latest.sh
}
trap cleanup EXIT

# 提权检测
check_root() {
    if [[ $EUID -ne 0 ]]; then
        printf "${RED}错误：此脚本必须由 root 用户执行。${PLAIN}\n"
        exit 1
    fi
}

# 系统识别
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_LIKE=$ID_LIKE
    else
        printf "${RED}无法检测系统类型${PLAIN}\n"
        exit 1
    fi

    case "$OS" in
        debian|ubuntu|kali|raspbian) OS_FAMILY="debian" ;;
        centos|rhel|fedora|rocky|alma) OS_FAMILY="rhel" ;;
        *)
            if [[ "$OS_LIKE" =~ (debian|ubuntu) ]]; then OS_FAMILY="debian"
            elif [[ "$OS_LIKE" =~ (rhel|fedora|centos) ]]; then OS_FAMILY="rhel"
            else printf "${RED}不支持的系统：$OS${PLAIN}\n"; exit 1; fi
            ;;
    esac
}

# 依赖补齐
# 精简系统（如 Docker/LXC 最小化镜像）常缺 procps/iproute2/util-linux 等基础包，
# 会导致 free/ps/uptime/lscpu/ip 等命令直接不存在，所以这里统一补齐。
check_dependencies() {
    # 格式: "命令:debian包名:rhel包名"（部分工具两边包名不同，如 openssh-client/openssh-clients）
    local deps=(
        "curl:curl:curl"
        "jq:jq:jq"
        "openssl:openssl:openssl"
        "ss:iproute2:iproute"
        "ip:iproute2:iproute"
        "gawk:gawk:gawk"
        "realpath:coreutils:coreutils"
        "diff:diffutils:diffutils"
        "ssh-copy-id:openssh-client:openssh-clients"
        "free:procps:procps-ng"
        "ps:procps:procps-ng"
        "uptime:procps:procps-ng"
        "lscpu:util-linux:util-linux"
        "hostname:hostname:hostname"
    )
    local missing_packages=()
    for item in "${deps[@]}"; do
        local cmd="${item%%:*}"
        local rest="${item#*:}"
        local deb_pkg="${rest%%:*}"
        local rhel_pkg="${rest#*:}"
        if ! command -v "$cmd" &>/dev/null; then
            if [ "$OS_FAMILY" = "debian" ]; then
                missing_packages+=("$deb_pkg")
            else
                missing_packages+=("$rhel_pkg")
            fi
        fi
    done

    if [ ${#missing_packages[@]} -ne 0 ]; then
        # 去重（比如 ss/ip 都映射到 iproute2，free/ps/uptime 都映射到 procps）
        local unique_packages
        IFS=$'\n' read -r -d '' -a unique_packages < <(printf "%s\n" "${missing_packages[@]}" | sort -u && printf '\0')

        printf "${BLUE}检测到精简系统，正在补齐必要工具: ${unique_packages[*]}...${PLAIN}\n"
        if [ "$OS_FAMILY" = "debian" ]; then
            apt-get update -qq && apt-get install -y "${unique_packages[@]}" || {
                printf "${RED}依赖安装失败，请手动安装后重试${PLAIN}\n"
                exit 1
            }
        else
            local pm="yum"
            command -v dnf &>/dev/null && pm="dnf"
            "$pm" install -y "${unique_packages[@]}" || {
                printf "${RED}依赖安装失败，请手动安装后重试${PLAIN}\n"
                exit 1
            }
        fi
    fi
}

# 获取 SSH 端口
get_ssh_port() {
    local port
    port=$(ss -tlnp | grep -Po ':\d+ (?=.*sshd)' | head -1 | grep -Po '\d+')
    if [ -z "$port" ]; then
        port=$(grep -E "^#?Port " /etc/ssh/sshd_config | awk '{print $2}' | head -1)
    fi
    echo "${port:-22}"
}

# 标记已加载
VPS_COMMON_LOADED=true
