#!/usr/bin/env bash
# ============================================================
# wireguard-mesh.sh — WireGuard 纯交互式组网管理面板 v3.1
# ============================================================
set -euo pipefail

# ── 常量 ────────────────────────────────────────────────────
readonly WG_IFACE="${WG_IFACE:-wg0}"
readonly WG_PORT="${WG_PORT:-52018}"
readonly WG_DIR="/etc/wireguard"
readonly WG_CONF="${WG_DIR}/${WG_IFACE}.conf"
readonly WG_KEY_DIR="${WG_DIR}/keys"
readonly PRIV_KEY_FILE="${WG_KEY_DIR}/privatekey"
readonly PUB_KEY_FILE="${WG_KEY_DIR}/publickey"
readonly BACKUP_DIR="/root/wg-backups"
readonly WG_TOOLS_REPO="https://git.zx2c4.com/wireguard-tools"
readonly WG_TOOLS_REPO_MIRROR="https://github.com/WireGuard/wireguard-tools.git"
readonly WG_BUILD_DIR="/usr/local/src/wireguard-tools-build"
readonly WG_BUILD_LOG="/tmp/wg-build.log"

# ── 颜色输出 ────────────────────────────────────────────────
if [[ -t 1 ]] && command -v tput &>/dev/null && tput colors &>/dev/null; then
    C_OK="\e[32m"; C_INFO="\e[36m"; C_WARN="\e[33m"; C_ERR="\e[31m"
    C_BOLD="\e[1;34m"; C_RESET="\e[0m"
else
    C_OK=""; C_INFO=""; C_WARN=""; C_ERR=""; C_BOLD=""; C_RESET=""
fi

log()    { printf "${C_OK}[OK]  %s${C_RESET}\n" "$*"; }
info()   { printf "${C_INFO}[..] %s${C_RESET}\n" "$*"; }
warn()   { printf "${C_WARN}[!!] %s${C_RESET}\n" "$*" >&2; }
error()  { printf "${C_ERR}[EE] %s${C_RESET}\n" "$*" >&2; exit 1; }
header() { printf "\n${C_BOLD}══ %s ══${C_RESET}\n" "$*"; }

# ── 前置检查 ────────────────────────────────────────────────
require_root() {
    [[ $EUID -eq 0 ]] || error "需要 root 权限，请用 sudo 执行"
}

require_conf() {
    [[ -f "$WG_CONF" ]] || error "配置文件不存在: $WG_CONF，请先执行初始化"
}

require_key() {
    [[ -f "$PRIV_KEY_FILE" && -f "$PUB_KEY_FILE" ]] || error "密钥不存在，请先生成密钥对"
}

# ── 输入校验 ─────────────────────────────────────────────────
is_valid_ipv4() {
    local ip="${1%%/*}"
    local IFS='.'
    read -ra octets <<< "$ip"
    [[ ${#octets[@]} -eq 4 ]] || return 1
    for o in "${octets[@]}"; do
        [[ "$o" =~ ^[0-9]+$ ]] || return 1
        (( 10#$o >= 0 && 10#$o <= 255 )) || return 1
    done
    return 0
}

is_valid_ipv6() {
    local ip="${1%%/*}"
    [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]] || return 1
    return 0
}

is_valid_cidr() {
    local ips
    IFS=',' read -ra ips <<< "$1"
    for current_ip in "${ips[@]}"; do
        local addr="${current_ip%%/*}"
        local mask="${current_ip##*/}"
        if [[ "$current_ip" == *:* ]]; then
            is_valid_ipv6 "$addr" || return 1
            [[ "$mask" =~ ^[0-9]+$ ]] && (( 10#$mask >= 0 && 10#$mask <= 128 )) || return 1
        else
            is_valid_ipv4 "$addr" || return 1
            [[ "$mask" =~ ^[0-9]+$ ]] && (( 10#$mask >= 0 && 10#$mask <= 32 )) || return 1
        fi
    done
    return 0
}

is_valid_endpoint() {
    local ep="$1"
    [[ "$ep" =~ ^.+:[0-9]{1,5}$ ]] || return 1
    local port="${ep##*:}"
    (( 10#$port >= 1 && 10#$port <= 65535 )) || return 1
    return 0
}

is_valid_pubkey() {
    [[ "${#1}" -eq 44 ]] && [[ "$1" =~ ^[A-Za-z0-9+/]{43}=$ ]]
}

# ── systemd 可用性检测 ────────────────────────────────────────
_has_systemd() {
    command -v systemctl &>/dev/null || return 1
    # /run/systemd/system 存在即说明当前系统由 systemd 管理且可正常使用
    # 不要依赖 is-system-running 的退出码：degraded/starting/maintenance
    # 等状态下 systemctl enable/disable 依然完全正常，但该命令会返回非 0，
    # 导致误判为"无 systemd"，从而跳过 enable，导致开机自启没有真正设置成功
    [[ -d /run/systemd/system ]]
}

# ── 配置文件安全写入（tmp 失败自动清理）────────────────────────
# 用法: awk_cmd | _safe_rewrite_conf
_safe_rewrite_conf() {
    local tmp
    tmp=$(mktemp "${WG_CONF}.tmp.XXXXXX")
    chmod 600 "$tmp"
    if cat > "$tmp"; then
        mv "$tmp" "$WG_CONF"
    else
        rm -f "$tmp"
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════
# 核心功能函数
# ═══════════════════════════════════════════════════════════


# ── 安装 iptables（防火墙规则依赖，与 wireguard-tools 版本无关，仍走包管理器）─
_install_iptables_pkg() {
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y iptables
    elif command -v dnf &>/dev/null; then
        dnf install -y iptables
    elif command -v yum &>/dev/null; then
        yum install -y epel-release
        yum install -y iptables
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm iptables
    else
        warn "不支持的包管理器，请手动安装 iptables"
        return 1
    fi
}

# ── 安装编译依赖（gcc/make/git/pkg-config）────────────────────
_install_build_deps() {
    command -v gcc &>/dev/null && command -v make &>/dev/null && command -v git &>/dev/null && return 0

    info "安装编译依赖 (gcc/make/git)..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential git pkg-config
    elif command -v dnf &>/dev/null; then
        dnf install -y gcc make git pkg-config
    elif command -v yum &>/dev/null; then
        yum groupinstall -y "Development Tools" 2>/dev/null || true
        yum install -y gcc make git pkg-config
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm base-devel git
    else
        warn "不支持的包管理器，请手动安装 gcc make git"
        return 1
    fi
}

# ── 从源码拉取最新 tag 并编译安装 wireguard-tools ──────────────
# 成功返回 0；失败返回 1 且不改变已安装版本（构建目录/失败产物自动清理）
_build_and_install_wg_tools() {
    _install_build_deps || return 1

    rm -rf "$WG_BUILD_DIR"
    mkdir -p "$(dirname "$WG_BUILD_DIR")"

    info "克隆 wireguard-tools 源码..."
    if ! git clone --quiet "$WG_TOOLS_REPO" "$WG_BUILD_DIR" >"$WG_BUILD_LOG" 2>&1; then
        warn "官方仓库克隆失败，尝试 GitHub 镜像..."
        if ! git clone --quiet "$WG_TOOLS_REPO_MIRROR" "$WG_BUILD_DIR" >>"$WG_BUILD_LOG" 2>&1; then
            warn "源码克隆失败（网络问题？），日志见 $WG_BUILD_LOG"
            rm -rf "$WG_BUILD_DIR"
            return 1
        fi
    fi

    local latest_tag
    latest_tag=$(git -C "$WG_BUILD_DIR" tag -l 'v*' --sort=-v:refname | head -1)
    if [[ -n "$latest_tag" ]]; then
        git -C "$WG_BUILD_DIR" checkout --quiet "$latest_tag"
        info "已切换到最新版本标签: $latest_tag"
    else
        warn "未找到版本标签，使用 master 最新提交编译"
    fi

    info "编译中（日志: $WG_BUILD_LOG）..."
    if ! make -C "${WG_BUILD_DIR}/src" -j"$(nproc)" >"$WG_BUILD_LOG" 2>&1; then
        warn "编译失败，日志见 $WG_BUILD_LOG"
        rm -rf "$WG_BUILD_DIR"
        return 1
    fi

    info "安装到 /usr ..."
    if ! make -C "${WG_BUILD_DIR}/src" install PREFIX=/usr >>"$WG_BUILD_LOG" 2>&1; then
        warn "安装失败，日志见 $WG_BUILD_LOG"
        rm -rf "$WG_BUILD_DIR"
        return 1
    fi

    rm -rf "$WG_BUILD_DIR"
    return 0
}

cmd_install() {
    header "安装 WireGuard"

    _install_iptables_pkg || warn "iptables 安装失败，防火墙/NAT 规则可能无法生效"

    if command -v wg &>/dev/null; then
        info "检测到已安装: $(wg --version 2>&1 | head -1)，将编译安装最新版覆盖"
    fi

    if _build_and_install_wg_tools; then
        modprobe wireguard 2>/dev/null || warn "wireguard 内核模块加载失败（内核 <5.6 需另装 DKMS 模块，或非特权容器环境可忽略）"
        log "WireGuard 安装完成: $(wg --version 2>&1 | head -1)"
    else
        error "wireguard-tools 编译安装失败，请查看 $WG_BUILD_LOG"
    fi
}

cmd_update() {
    header "更新 WireGuard"
    command -v wg &>/dev/null || { warn "WireGuard 未安装，请先执行安装"; return 1; }

    info "当前版本: $(wg --version 2>&1 | head -1)"

    local was_up=false
    _iface_is_up && was_up=true && info "接口运行中，更新前将临时停止"
    $was_up && _stop_iface_safe || true

    if _build_and_install_wg_tools; then
        log "更新完成: $(wg --version 2>&1 | head -1)"
    else
        warn "更新失败，已保留原版本: $(wg --version 2>&1 | head -1)"
    fi

    # 无论编译是否成功都要恢复接口，避免更新失败导致断连且不自动恢复
    if $was_up; then
        info "正在重新启动接口..."
        cmd_up || warn "接口重启失败，请手动执行「启动接口」"
    fi
}

cmd_uninstall() {
    header "卸载 WireGuard"
    warn "此操作将停止接口、删除配置、密钥、sysctl 规则"
    local _confirm
    read -r -t 30 -p "  确认卸载? 输入 YES 继续: " _confirm || true
    [[ "$_confirm" == "YES" ]] || { info "已取消"; return 0; }

    _stop_iface_safe

    local default_iface
    default_iface=$(ip route show default | awk '/default/{print $5}' | head -1 || echo "")

    if _ufw_active; then
        _ufw_teardown_forwarding "$default_iface"
    fi

    # 兼容非 UFW 模式下手动加的裸 iptables 规则，尽力清理，失败可忽略
    iptables -D INPUT   -p udp --dport "${WG_PORT}" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "${WG_IFACE}" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "${WG_IFACE}" -j ACCEPT 2>/dev/null || true
    if [[ -n "$default_iface" ]]; then
        iptables -t nat -D POSTROUTING -o "${default_iface}" -j MASQUERADE 2>/dev/null || true
    fi

    if which ip6tables >/dev/null 2>&1; then
        ip6tables -D FORWARD -i "${WG_IFACE}" -j ACCEPT 2>/dev/null || true
        ip6tables -D FORWARD -o "${WG_IFACE}" -j ACCEPT 2>/dev/null || true
        if [[ -n "$default_iface" ]]; then
            ip6tables -t nat -D POSTROUTING -o "${default_iface}" -j MASQUERADE 2>/dev/null || true
        fi
    fi

    rm -f /etc/sysctl.d/99-wireguard.conf
    sysctl -p -q 2>/dev/null || true

    rm -f "$WG_CONF" "${WG_KEY_DIR}/privatekey" "${WG_KEY_DIR}/publickey"
    rmdir "$WG_KEY_DIR" 2>/dev/null || true

    local _pkg
    read -r -t 30 -p "  同时卸载 wireguard-tools 程序本体? [y/N] " _pkg || true
    if [[ "${_pkg,,}" == "y" ]]; then
        # 本脚本通过源码编译安装（make install PREFIX=/usr），直接删除对应文件
        rm -f /usr/bin/wg /usr/bin/wg-quick
        rm -f /usr/share/man/man8/wg.8 /usr/share/man/man8/wg-quick.8
        rm -f /usr/share/bash-completion/completions/wg /usr/share/bash-completion/completions/wg-quick
        # 兼容此前可能通过包管理器安装的情形，尽力清理，失败可忽略
        if command -v apt-get &>/dev/null; then
            apt-get remove -y wireguard wireguard-tools 2>/dev/null || true
        elif command -v dnf &>/dev/null; then
            dnf remove -y wireguard-tools 2>/dev/null || true
        elif command -v yum &>/dev/null; then
            yum remove -y wireguard-tools 2>/dev/null || true
        elif command -v pacman &>/dev/null; then
            pacman -R --noconfirm wireguard-tools 2>/dev/null || true
        fi
        log "wireguard-tools 程序本体已清理"
    fi

    log "卸载完成"
}

cmd_genkey() {
    header "生成密钥对"
    mkdir -p "$WG_KEY_DIR"
    chmod 700 "$WG_KEY_DIR"

    if [[ -f "$PRIV_KEY_FILE" ]]; then
        warn "密钥已存在，如需重新生成请手动删除 ${WG_KEY_DIR}/ 下的文件"
        return 0
    fi

    local tmp_priv tmp_pub
    tmp_priv=$(mktemp "${WG_KEY_DIR}/privatekey.XXXXXX")
    tmp_pub=$(mktemp  "${WG_KEY_DIR}/publickey.XXXXXX")

    wg genkey > "$tmp_priv"
    wg pubkey < "$tmp_priv" > "$tmp_pub"

    chmod 600 "$tmp_priv"
    chmod 640 "$tmp_pub"
    mv "$tmp_priv" "$PRIV_KEY_FILE"
    mv "$tmp_pub"  "$PUB_KEY_FILE"

    log "私钥与公钥生成完毕"
    info "公钥: $(cat "$PUB_KEY_FILE")"
}


# ═══════════════════════════════════════════════════════════
# UFW 集成（若检测到 UFW 处于 active 状态，优先用 UFW 原生方式
# 管理端口放行/转发/NAT，避免 ufw reload 冲掉裸 iptables 规则）
# ═══════════════════════════════════════════════════════════

_ufw_active() {
    command -v ufw &>/dev/null || return 1
    ufw status 2>/dev/null | grep -q '^Status: active'
}

# 从 "10.10.0.1/24,fd00::1/64" 这种逗号分隔地址串里，取出指定协议族的一段
# 用法: _extract_cidr_family "$WG_ADDR" 4|6
_extract_cidr_family() {
    local addr_list="$1" family="$2" entry
    local -a parts
    IFS=',' read -ra parts <<< "$addr_list"
    for entry in "${parts[@]}"; do
        if [[ "$family" == "6" && "$entry" == *:* ]]; then
            printf '%s' "$entry"; return 0
        elif [[ "$family" == "4" && "$entry" != *:* ]]; then
            printf '%s' "$entry"; return 0
        fi
    done
    return 1
}

# 幂等地把 NAT/MASQUERADE 块插入 ufw 的 before.rules / before6.rules 头部
# （iptables -s A.B.C.D/MASK 会自动按掩码匹配整个网段，无需手动清零主机位）
_ufw_add_nat_block() {
    local rules_file="$1" wg_source="$2" out_iface="$3" marker="$4"
    [[ -f "$rules_file" ]] || return 1
    grep -qF "$marker" "$rules_file" 2>/dev/null && return 0

    local tmp
    tmp=$(mktemp)
    {
        printf '# BEGIN %s（wireguard-mesh.sh 自动生成，勿手动编辑本段）\n' "$marker"
        printf '*nat\n:POSTROUTING ACCEPT [0:0]\n'
        printf -- '-A POSTROUTING -s %s -o %s -j MASQUERADE\n' "$wg_source" "$out_iface"
        printf 'COMMIT\n'
        printf '# END %s\n' "$marker"
        cat "$rules_file"
    } > "$tmp"
    mv "$tmp" "$rules_file"
    chmod 640 "$rules_file"
}

_ufw_remove_nat_block() {
    local rules_file="$1" marker="$2"
    [[ -f "$rules_file" ]] || return 0
    grep -qF "$marker" "$rules_file" 2>/dev/null || return 0
    sed -i "/# BEGIN ${marker}/,/# END ${marker}/d" "$rules_file"
}

# 初始化时调用：用 UFW 原生命令放行端口 + 转发 + NAT，替代裸 iptables PostUp/PostDown
_ufw_setup_forwarding() {
    local default_iface="$1" wg_addr="$2"
    header "检测到 UFW（active），改用 UFW 原生方式管理防火墙规则"

    ufw allow "${WG_PORT}/udp" comment "WireGuard ${WG_IFACE}" >/dev/null
    ufw route allow in on "${WG_IFACE}" out on "${default_iface}" >/dev/null 2>&1 || true
    ufw route allow in on "${default_iface}" out on "${WG_IFACE}" >/dev/null 2>&1 || true
    ufw route allow in on "${WG_IFACE}" out on "${WG_IFACE}" >/dev/null 2>&1 || true

    local v4_src v6_src
    v4_src=$(_extract_cidr_family "$wg_addr" 4) || v4_src=""
    v6_src=$(_extract_cidr_family "$wg_addr" 6) || v6_src=""

    [[ -n "$v4_src" ]] && _ufw_add_nat_block /etc/ufw/before.rules  "$v4_src" "$default_iface" "WIREGUARD-MESH-NAT-${WG_IFACE}-v4"
    if [[ -n "$v6_src" ]]; then
        if [[ -f /etc/ufw/before6.rules ]]; then
            _ufw_add_nat_block /etc/ufw/before6.rules "$v6_src" "$default_iface" "WIREGUARD-MESH-NAT-${WG_IFACE}-v6"
            grep -q '^IPV6=yes' /etc/default/ufw 2>/dev/null || warn "UFW 未启用 IPv6 (/etc/default/ufw IPV6=yes)，IPv6 转发规则可能不生效"
        else
            warn "未找到 /etc/ufw/before6.rules，跳过 IPv6 NAT 规则"
        fi
    fi

    ufw reload >/dev/null 2>&1 || warn "ufw reload 失败，请手动执行 ufw reload 使规则生效"
    log "UFW 规则已配置：端口放行 / 路由转发 / NAT（ufw status verbose 可查看）"
}

# 卸载时调用：撤销上面加的 UFW 规则
_ufw_teardown_forwarding() {
    local default_iface="$1"
    _ufw_active || return 0
    header "清理 UFW 中的 WireGuard 规则"

    ufw --force delete allow "${WG_PORT}/udp" >/dev/null 2>&1 || true
    ufw --force delete route allow in on "${WG_IFACE}" out on "${default_iface}" >/dev/null 2>&1 || true
    ufw --force delete route allow in on "${default_iface}" out on "${WG_IFACE}" >/dev/null 2>&1 || true
    ufw --force delete route allow in on "${WG_IFACE}" out on "${WG_IFACE}" >/dev/null 2>&1 || true

    _ufw_remove_nat_block /etc/ufw/before.rules  "WIREGUARD-MESH-NAT-${WG_IFACE}-v4"
    _ufw_remove_nat_block /etc/ufw/before6.rules "WIREGUARD-MESH-NAT-${WG_IFACE}-v6"

    ufw reload >/dev/null 2>&1 || true
    log "UFW 规则已清理"
}

cmd_init() {
    require_key
    local RAW_IP="$1"
    local WG_ADDR

    if [[ "$RAW_IP" == */* ]]; then
        WG_ADDR="$RAW_IP"
    elif [[ "$RAW_IP" == *:* ]]; then
        WG_ADDR="${RAW_IP}/128"
    else
        WG_ADDR="${RAW_IP}/24"
    fi

    header "初始化 ${WG_IFACE} (${WG_ADDR})"

    if [[ -f "$WG_CONF" ]]; then
        warn "配置文件已存在: $WG_CONF"
        local CONFIRM
        read -rp "  覆盖? [y/N] " CONFIRM || true
        [[ "${CONFIRM,,}" == "y" ]] || return 0
        _stop_iface_safe
    fi

    local default_iface
    default_iface=$(ip route show default | awk '/default/ {print $5}' | head -1)
    if [[ -z "$default_iface" ]]; then
        warn "未找到默认出网网卡，路由转发规则可能失效"
        default_iface="eth0"
    fi

    mkdir -p "$WG_DIR"
    chmod 700 "$WG_DIR"

    cat > /etc/sysctl.d/99-wireguard.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
    sysctl -p /etc/sysctl.d/99-wireguard.conf -q
    info "双栈 ip_forward 已持久化至 /etc/sysctl.d/99-wireguard.conf"

    local tmp
    tmp=$(mktemp "${WG_DIR}/.wg_conf.XXXXXX")
    chmod 600 "$tmp"

    if _ufw_active; then
        # UFW 模式：端口放行/转发/NAT 都交给 UFW 原生规则管理（见下方 _ufw_setup_forwarding），
        # PostUp/PostDown 不再直接操作 iptables，避免 ufw reload 时把裸规则冲掉
        cat > "$tmp" <<EOF
[Interface]
Address = ${WG_ADDR}
PrivateKey = $(cat "$PRIV_KEY_FILE")
ListenPort = ${WG_PORT}
# 防火墙规则由 UFW 管理，见 /etc/ufw/before.rules 与 ufw route 规则（本脚本自动生成）
EOF
        mv "$tmp" "$WG_CONF"
        _ufw_setup_forwarding "$default_iface" "$WG_ADDR"
        log "双栈配置已生成 (出站网卡: ${default_iface}，防火墙: UFW)"
    else
        cat > "$tmp" <<EOF
[Interface]
Address = ${WG_ADDR}
PrivateKey = $(cat "$PRIV_KEY_FILE")
ListenPort = ${WG_PORT}

# 1. 端口放行 (INPUT)
PostUp   = iptables -C INPUT -p udp --dport ${WG_PORT} -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport ${WG_PORT} -j ACCEPT
PostDown = iptables -D INPUT -p udp --dport ${WG_PORT} -j ACCEPT 2>/dev/null || true

# 2. IPv4 转发与 NAT
PostUp   = iptables -C FORWARD -i %i -j ACCEPT 2>/dev/null || iptables -A FORWARD -i %i -j ACCEPT
PostUp   = iptables -C FORWARD -o %i -j ACCEPT 2>/dev/null || iptables -A FORWARD -o %i -j ACCEPT
PostUp   = iptables -t nat -C POSTROUTING -o ${default_iface} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o ${default_iface} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -o %i -j ACCEPT 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -o ${default_iface} -j MASQUERADE 2>/dev/null || true

# 3. IPv6 转发与 NAT（which 兼容 /bin/sh，command -v 不可靠）
PostUp   = which ip6tables >/dev/null 2>&1 && (ip6tables -C FORWARD -i %i -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -i %i -j ACCEPT) || true
PostUp   = which ip6tables >/dev/null 2>&1 && (ip6tables -C FORWARD -o %i -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -o %i -j ACCEPT) || true
PostUp   = which ip6tables >/dev/null 2>&1 && (ip6tables -t nat -C POSTROUTING -o ${default_iface} -j MASQUERADE 2>/dev/null || ip6tables -t nat -A POSTROUTING -o ${default_iface} -j MASQUERADE) || true
PostDown = which ip6tables >/dev/null 2>&1 && ip6tables -D FORWARD -i %i -j ACCEPT 2>/dev/null || true
PostDown = which ip6tables >/dev/null 2>&1 && ip6tables -D FORWARD -o %i -j ACCEPT 2>/dev/null || true
PostDown = which ip6tables >/dev/null 2>&1 && ip6tables -t nat -D POSTROUTING -o ${default_iface} -j MASQUERADE 2>/dev/null || true
EOF
        mv "$tmp" "$WG_CONF"
        log "双栈配置已生成 (出站网卡: ${default_iface}，防火墙: iptables PostUp/PostDown)"
    fi
}

cmd_add_peer() {
    require_conf
    local PUB_KEY="$1" ALLOWED_IPS="$2" ENDPOINT="${3:-}"

    header "添加 Peer: ${ALLOWED_IPS}"

    if ! is_valid_pubkey "$PUB_KEY"; then
        warn "公钥格式不合法（需 44 位 Base64）"; return 1
    fi
    if ! is_valid_cidr "$ALLOWED_IPS" && ! is_valid_ipv4 "$ALLOWED_IPS"; then
        warn "AllowedIPs 格式不合法: $ALLOWED_IPS"; return 1
    fi
    if [[ -n "$ENDPOINT" ]] && ! is_valid_endpoint "$ENDPOINT"; then
        warn "Endpoint 格式不合法: $ENDPOINT（应为 host:port）"; return 1
    fi

    if [[ "$ALLOWED_IPS" == "0.0.0.0/0" || "$ALLOWED_IPS" == "::/0" || "$ALLOWED_IPS" == "0.0.0.0/0,::/0" ]]; then
        warn "AllowedIPs 设置为全路由 (${ALLOWED_IPS})，该 Peer 将接管本机所有出站流量！"
        local _fullroute_confirm
        read -r -t 30 -p "  确认继续? [y/N] " _fullroute_confirm || { echo; warn "输入超时，已取消"; return 1; }
        [[ "${_fullroute_confirm,,}" == "y" ]] || { info "已取消"; return 0; }
    fi

    if grep -qF "PublicKey = ${PUB_KEY}" "$WG_CONF"; then
        warn "该 Peer 公钥已存在"; return 0
    fi

    _backup_conf
    {
        printf '\n[Peer]\n'
        printf 'PublicKey = %s\n' "$PUB_KEY"
        printf 'AllowedIPs = %s\n' "$ALLOWED_IPS"
        if [[ -n "$ENDPOINT" ]]; then
            printf 'Endpoint = %s\n' "$ENDPOINT"
            printf 'PersistentKeepalive = 25\n'
        fi
    } >> "$WG_CONF"

    log "Peer 已追加"
    if _iface_is_up; then
        local -a args=(set "${WG_IFACE}" peer "${PUB_KEY}" allowed-ips "${ALLOWED_IPS}")
        [[ -n "$ENDPOINT" ]] && args+=(endpoint "${ENDPOINT}" persistent-keepalive 25)
        wg "${args[@]}" && log "热更新成功"
    else
        info "接口未运行，配置已更新，启动后生效"
    fi
}


# ── 读取当前所有 Peer 公钥到全局数组 _PEER_KEYS ────────────────
_list_peer_keys() {
    require_conf
    mapfile -t _PEER_KEYS < <(awk '
        BEGIN { in_peer=0 }
        /^\[Peer\]/ { in_peer=1; next }
        /^\[/       { in_peer=0 }
        in_peer && /^[[:space:]]*PublicKey[[:space:]]*=/ {
            eq = index($0, "="); v = substr($0, eq+1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
            print v
        }
    ' "$WG_CONF")
}

# ── 交互式列表选择一个 Peer 公钥，结果写入全局变量 _PICKED_PEER ──
# 返回 1 表示无 Peer 或用户输入无效
_pick_peer_key() {
    _list_peer_keys
    if [[ ${#_PEER_KEYS[@]} -eq 0 ]]; then
        warn "当前无 Peer 节点"; return 1
    fi

    local i=1
    for k in "${_PEER_KEYS[@]}"; do
        printf "  %d. %s...\n" "$i" "${k:0:24}"
        (( i++ ))
    done
    echo

    local sel
    _ask "选择序号" sel ""
    [[ "$sel" =~ ^[0-9]+$ ]] && (( 10#$sel >= 1 && 10#$sel <= ${#_PEER_KEYS[@]} )) || { warn "无效序号"; return 1; }
    _PICKED_PEER="${_PEER_KEYS[$((10#$sel-1))]}"
}

# ── 提取指定 Peer 当前的 AllowedIPs / Endpoint（用于换公钥时热更新）──
_get_peer_field() {
    local target="$1" field="$2"
    awk -v target="$target" -v field="$field" '
        /^\[Peer\]/ { in_peer=1; pk=""; next }
        /^\[/       { in_peer=0 }
        in_peer && /^[[:space:]]*PublicKey/ {
            eq = index($0, "="); pk = substr($0, eq+1)
            gsub(/[[:space:]]/, "", pk)
        }
        in_peer && pk==target && $0 ~ ("^[[:space:]]*" field) {
            eq = index($0, "="); v = substr($0, eq+1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
            print v
        }
    ' "$WG_CONF"
}

cmd_edit_peer() {
    require_conf
    header "编辑 Peer"

    _pick_peer_key || return 1
    local target_key="$_PICKED_PEER"

    local cur_ips cur_ep
    cur_ips="$(_get_peer_field "$target_key" "AllowedIPs")"
    cur_ep="$(_get_peer_field "$target_key" "Endpoint")"

    info "当前公钥: ${target_key}"
    local new_pk new_ips new_ep
    _ask "新公钥        (回车保留原值)" new_pk  ""
    _ask "新 AllowedIPs (回车保留原值)" new_ips ""
    _ask "新 Endpoint   (回车保留原值)" new_ep  ""

    if [[ -n "$new_pk" ]]; then
        if ! is_valid_pubkey "$new_pk"; then
            warn "公钥格式不合法（需 44 位 Base64）"; return 1
        fi
        if [[ "$new_pk" == "$target_key" ]]; then
            new_pk=""
        elif grep -qF "PublicKey = ${new_pk}" "$WG_CONF"; then
            warn "该公钥已被其他 Peer 使用"; return 1
        fi
    fi

    if [[ -z "$new_pk" && -z "$new_ips" && -z "$new_ep" ]]; then
        info "无修改"; return 0
    fi

    _backup_conf

    # [FIX] 新增 Endpoint 时同步写入 PersistentKeepalive（若原块中已有则替换，否则在 Endpoint 行后追加）
    # [NEW] 支持替换 PublicKey 本身
    awk -v target="$target_key" -v new_pk="$new_pk" -v new_ips="$new_ips" -v new_ep="$new_ep" '
        BEGIN { in_target=0; in_peer=0; added_ka=0 }
        /^\[/ {
            # 离开 target 块时：若刚写入了新 Endpoint 且 KA 未写过，补写 KA
            if (in_target && added_ka == 0 && new_ep != "") {
                print "PersistentKeepalive = 25"
            }
            in_target=0; in_peer=0; added_ka=0
        }
        /^\[Peer\]/ { in_peer=1; print; next }
        in_peer && /^[[:space:]]*PublicKey[[:space:]]*=/ {
            eq = index($0, "="); cur_pk = substr($0, eq+1)
            gsub(/[[:space:]]/, "", cur_pk)
            if (cur_pk == target) {
                in_target=1
                if (new_pk != "") { print "PublicKey = " new_pk; next }
            }
            print; next
        }
        in_target && /^[[:space:]]*AllowedIPs/ && new_ips != "" {
            print "AllowedIPs = " new_ips; next
        }
        in_target && /^[[:space:]]*Endpoint/ {
            if (new_ep != "") { print "Endpoint = " new_ep } else { print }
            next
        }
        in_target && /^[[:space:]]*PersistentKeepalive/ {
            # 已有 KA 行：若有新 Endpoint 则顺手保持，否则原样输出
            print "PersistentKeepalive = 25"
            added_ka=1; next
        }
        { print }
        END {
            # 最后一个块是 target 且 KA 未写过（新增 Endpoint 场景）
            if (in_target && added_ka == 0 && new_ep != "") {
                print "PersistentKeepalive = 25"
            }
        }
    ' "$WG_CONF" | _safe_rewrite_conf || { warn "配置写入失败，已保留备份"; return 1; }

    log "Peer 已更新"
    if _iface_is_up; then
        if [[ -n "$new_pk" ]]; then
            # WireGuard 运行时以公钥标识 Peer，换公钥必须先移除旧条目再以新公钥添加
            wg set "${WG_IFACE}" peer "$target_key" remove 2>/dev/null || true
            local final_ips="${new_ips:-$cur_ips}" final_ep="${new_ep:-$cur_ep}"
            if [[ -z "$final_ips" ]]; then
                warn "无法确定 AllowedIPs，热更新已跳过，请手动重启接口生效"
            else
                local -a args=(set "${WG_IFACE}" peer "$new_pk" allowed-ips "$final_ips")
                [[ -n "$final_ep" ]] && args+=(endpoint "$final_ep" persistent-keepalive 25)
                wg "${args[@]}" && log "热更新成功（公钥已切换）"
            fi
        else
            local -a args=(set "${WG_IFACE}" peer "$target_key")
            [[ -n "$new_ips" ]] && args+=(allowed-ips "$new_ips")
            [[ -n "$new_ep"  ]] && args+=(endpoint "$new_ep" persistent-keepalive 25)
            wg "${args[@]}" && log "热更新成功"
        fi
    else
        info "接口未运行，配置已更新，启动后生效"
    fi
}

cmd_remove_peer() {
    require_conf
    local PUB_KEY="$1"

    header "移除 Peer"

    if ! is_valid_pubkey "$PUB_KEY"; then
        warn "公钥格式不合法（需 44 位 Base64）"; return 1
    fi

    if ! grep -qF "PublicKey = ${PUB_KEY}" "$WG_CONF"; then
        warn "未找到该 Peer（配置文件中不存在）"; return 1
    fi

    _backup_conf

    awk -v target="$PUB_KEY" '
        BEGIN { in_peer=0; block=""; found=0 }
        /^\[Peer\]/ {
            if (in_peer && !found) printf "%s", block;
            in_peer=1; block=$0 "\n"; found=0; next
        }
        /^\[/ && !/^\[Peer\]/ {
            if (in_peer && !found) printf "%s", block;
            in_peer=0; print; next
        }
        in_peer {
            block = block $0 "\n"
            eq = index($0, "=")
            fname = (eq > 0) ? substr($0, 1, eq-1) : $0
            fval  = (eq > 0) ? substr($0, eq+1) : ""
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", fname)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", fval)
            if (fname == "PublicKey" && fval == target) found=1
        }
        !in_peer { print }
        END { if (in_peer && !found) printf "%s", block }
    ' "$WG_CONF" | _safe_rewrite_conf || { warn "配置写入失败，已保留备份"; return 1; }

    log "Peer 已从配置移除"

    # [FIX] 热移除前先确认运行时确实存在该 peer，避免误判
    if _iface_is_up; then
        if wg show "${WG_IFACE}" peers 2>/dev/null | grep -qF "$PUB_KEY"; then
            wg set "${WG_IFACE}" peer "$PUB_KEY" remove && log "热移除成功"
        else
            info "运行时未找到该 Peer（可能从未激活），配置已清理"
        fi
    else
        info "接口未运行，配置已更新，启动后生效"
    fi
}

cmd_up() {
    require_conf
    header "启动 ${WG_IFACE}"

    _stop_iface_safe

    if _has_systemd; then
        systemctl enable --now "wg-quick@${WG_IFACE}"
    else
        wg-quick up "$WG_CONF"
    fi

    if _iface_is_up; then
        log "${WG_IFACE} 已成功启动（已设开机自启）"
    else
        error "启动失败，请检查配置或内核支持"
    fi
}

cmd_down() {
    header "停止 ${WG_IFACE}"
    _stop_iface_safe
    log "${WG_IFACE} 已停止（已取消开机自启）"
}

cmd_restart() {
    require_conf
    header "重启 ${WG_IFACE}"
    _stop_iface_safe
    cmd_up
}

cmd_export() {
    require_conf
    require_key
    header "导出本机节点信息"

    local pub_key wg_addr pub_ip
    pub_key=$(cat "$PUB_KEY_FILE")
    wg_addr=$(awk '/^[[:space:]]*Address[[:space:]]*=/{print $3}' "$WG_CONF")
    pub_ip=$(curl -sf --max-time 5 https://api.ipify.org 2>/dev/null || \
             curl -sf --max-time 5 https://ifconfig.me  2>/dev/null || \
             echo "（获取失败，请手动填写）")

    printf "\n"
    printf "  ┌─────────────────────────────────────────────────────┐\n"
    printf "  │  本机节点信息（提供给对端以添加此节点）             │\n"
    printf "  ├─────────────────────────────────────────────────────┤\n"
    printf "  │  PublicKey : %s\n" "$pub_key"
    printf "  │  WG Addr   : %s\n" "$wg_addr"
    printf "  │  Endpoint  : %s:%s\n" "$pub_ip" "$WG_PORT"
    printf "  └─────────────────────────────────────────────────────┘\n\n"

    printf "  对端添加此节点的配置模板：\n\n"
    printf "  [Peer]\n"
    printf "  PublicKey           = %s\n" "$pub_key"
    printf "  AllowedIPs          = %s\n" "$wg_addr"
    printf "  Endpoint            = %s:%s\n" "$pub_ip" "$WG_PORT"
    printf "  PersistentKeepalive = 25\n\n"

    if command -v qrencode &>/dev/null; then
        info "生成二维码（移动端扫码用）..."
        printf "[Peer]\nPublicKey = %s\nAllowedIPs = %s\nEndpoint = %s:%s\nPersistentKeepalive = 25\n" \
            "$pub_key" "$wg_addr" "$pub_ip" "$WG_PORT" | qrencode -t ansiutf8
    else
        info "提示: 安装 qrencode 后可生成二维码 (apt install qrencode)"
    fi
}

cmd_backup() {
    header "备份配置"
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"

    local outfile="${BACKUP_DIR}/wg-backup-$(date +%Y%m%d_%H%M%S).tar.gz"
    local files=()
    [[ -d "$WG_DIR" ]] && files+=("etc/wireguard")
    [[ -f /etc/sysctl.d/99-wireguard.conf ]] && files+=("etc/sysctl.d/99-wireguard.conf")

    if [[ ${#files[@]} -eq 0 ]]; then
        warn "没有可备份的内容"; return 1
    fi

    tar -czf "$outfile" -C / "${files[@]}" 2>/dev/null || true
    chmod 600 "$outfile"
    log "备份完成: $outfile"
    info "备份目录: $BACKUP_DIR"
}

cmd_restore() {
    header "恢复配置"
    mkdir -p "$BACKUP_DIR"

    local -a backups
    mapfile -t backups < <(ls -t "${BACKUP_DIR}"/wg-backup-*.tar.gz 2>/dev/null || true)

    if [[ ${#backups[@]} -eq 0 ]]; then
        warn "未找到备份文件 (${BACKUP_DIR}/wg-backup-*.tar.gz)"
        local custom
        _ask "请手动输入备份文件路径" custom ""
        [[ -f "$custom" ]] || { warn "文件不存在: $custom"; return 1; }
        backups=("$custom")
    else
        local i=1
        for f in "${backups[@]}"; do
            printf "  %d. %s\n" "$i" "$(basename "$f")"
            (( i++ ))
        done
        echo
        local sel
        _ask "选择序号" sel "1"
        [[ "$sel" =~ ^[0-9]+$ ]] && (( 10#$sel >= 1 && 10#$sel <= ${#backups[@]} )) || { warn "无效序号"; return 1; }
        backups=("${backups[$((10#$sel-1))]}")
    fi

    local target="${backups[0]}"
    warn "将从 $(basename "$target") 恢复，当前配置将被覆盖"
    local _confirm
    read -r -t 30 -p "  确认? [y/N] " _confirm || true
    [[ "${_confirm,,}" == "y" ]] || { info "已取消"; return 0; }

    _stop_iface_safe
    tar -xzf "$target" -C /
    log "恢复完成"
    info "请执行「启动接口」使配置生效"
}

cmd_monitor() {
    require_conf
    _iface_is_up || { warn "接口未运行，请先启动"; return 1; }
    header "实时监控 ${WG_IFACE}（Ctrl+C 退出）"
    if command -v watch &>/dev/null; then
        watch -n 2 "wg show ${WG_IFACE}"
    else
        while true; do
            clear
            header "实时监控 ${WG_IFACE}"
            wg show "${WG_IFACE}" || true
            sleep 2
        done
    fi
}

# ═══════════════════════════════════════════════════════════
# 辅助工具函数
# ═══════════════════════════════════════════════════════════

_iface_is_up() {
    ip link show "${WG_IFACE}" &>/dev/null
}

_stop_iface_safe() {
    if _has_systemd; then
        systemctl disable --now "wg-quick@${WG_IFACE}" 2>/dev/null || true
        systemctl reset-failed "wg-quick@${WG_IFACE}" 2>/dev/null || true
    fi
    if ip link show "${WG_IFACE}" &>/dev/null; then
        wg-quick down "${WG_IFACE}" 2>/dev/null || ip link delete "${WG_IFACE}" 2>/dev/null || true
    fi
}

_backup_conf() {
    local bak="${WG_CONF}.bak.$(date +%Y%m%d_%H%M%S).$$"
    cp "$WG_CONF" "$bak"
    chmod 600 "$bak"
    info "配置已备份: $bak"
}

_ask() {
    local prompt="$1" varname="$2" default="${3:-}" val hint=""
    [[ -n "$default" ]] && hint=" [默认: ${default}]"
    if ! read -r -t 120 -p "  ${prompt}${hint}: " val; then
        echo
        error "输入超时（120s），已退出"
    fi
    printf -v "$varname" '%s' "${val:-$default}"
}

_pause() { echo; read -r -t 300 -p "  按 Enter 返回主菜单..." _ || true; }

# ═══════════════════════════════════════════════════════════
# 交互菜单
# ═══════════════════════════════════════════════════════════

_menu_header() {
    clear
    printf "\n${C_BOLD}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║      WireGuard Mesh Panel v3.2 - 交互式管控台       ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    printf "${C_RESET}\n"

    local key_disp conf_disp wg_disp peer_count
    [[ -f "$PUB_KEY_FILE" ]] && key_disp="$(cut -c1-20 "$PUB_KEY_FILE")..." || key_disp="（未生成）"
    if [[ -f "$WG_CONF" ]]; then
        peer_count=$(grep -c '^\[Peer\]' "$WG_CONF" 2>/dev/null || echo 0)
        conf_disp="${WG_CONF} (${peer_count} peers)"
    else
        conf_disp="（未初始化）"
    fi
    _iface_is_up && wg_disp="${C_OK}运行中 ✓${C_RESET}" || wg_disp="${C_WARN}已停止${C_RESET}"

    printf "  本机公钥: ${C_INFO}%s${C_RESET}\n" "$key_disp"
    printf "  配置文件: ${C_INFO}%s${C_RESET}\n" "$conf_disp"
    printf "  接口状态: %b\n\n" "$wg_disp"
}

_run() {
    local title="$1"; shift
    _menu_header
    printf "  ${C_WARN}▶ %s${C_RESET}\n\n" "$title"
    "$@" || true
    _pause
}

menu_main() {
    require_root
    while true; do
        _menu_header
        echo "  [ 安装管理 ]"
        echo "  1.  安装 WireGuard"
        echo "  2.  更新 WireGuard"
        echo "  3.  卸载 WireGuard"
        echo "  "
        echo "  [ 本机配置 ]"
        echo "  4.  生成密钥对"
        echo "  5.  初始化网络配置"
        echo "  6.  查看/导出本机节点信息"
        echo "  "
        echo "  [ 节点管控 ]"
        echo "  7.  添加对端节点"
        echo "  8.  编辑对端节点"
        echo "  9.  移除对端节点"
        echo "  10. 列出所有节点"
        echo "  "
        echo "  [ 启停控制 ]"
        echo "  11. 启动接口"
        echo "  12. 重启接口"
        echo "  13. 停止接口"
        echo "  14. 实时流量监控"
        echo "  "
        echo "  [ 备份恢复 ]"
        echo "  15. 备份配置"
        echo "  16. 恢复配置"
        echo "  "
        echo "  0.  退出面板"
        echo
        local CHOICE
        read -r -t 300 -p "  请输入序号选择: " CHOICE || { echo; continue; }
        case "$CHOICE" in
            1)  _run "安装 WireGuard"     cmd_install ;;
            2)  _run "更新 WireGuard"     cmd_update ;;
            3)  _run "卸载 WireGuard"     cmd_uninstall ;;
            4)  _run "生成密钥对"         cmd_genkey ;;
            5)
                _menu_header
                local MY_IP
                _ask "请输入本机 WG IP (如 10.10.0.1/24 或 fd00::1/64)" MY_IP ""
                if is_valid_cidr "$MY_IP" || is_valid_ipv4 "$MY_IP"; then
                    cmd_init "$MY_IP"
                else
                    warn "IP 格式错误: $MY_IP"
                fi
                _pause
                ;;
            6)  _run "导出本机节点信息"   cmd_export ;;
            7)
                _menu_header
                local P_PK P_IP P_EP
                _ask "对端公钥 (44字符 Base64)"                          P_PK ""
                _ask "对端内网 IP/CIDR (如 10.10.0.2/32 或 fd00::2/128)" P_IP ""
                _ask "对端 Endpoint (如 1.2.3.4:51820，无则回车跳过)"    P_EP ""
                if [[ -n "$P_PK" && -n "$P_IP" ]]; then
                    cmd_add_peer "$P_PK" "$P_IP" "$P_EP"
                else
                    warn "公钥和 IP 不能为空"
                fi
                _pause
                ;;
            8)  _run "编辑对端节点"       cmd_edit_peer ;;
            9)
                _menu_header
                header "移除对端节点"
                if _pick_peer_key; then
                    cmd_remove_peer "$_PICKED_PEER"
                fi
                _pause
                ;;
            10) _run "节点列表"           wg show "${WG_IFACE}" ;;
            11) _run "启动接口"           cmd_up ;;
            12) _run "重启接口"           cmd_restart ;;
            13) _run "停止接口"           cmd_down ;;
            14) _run "实时流量监控"       cmd_monitor ;;
            15) _run "备份配置"           cmd_backup ;;
            16) _run "恢复配置"           cmd_restore ;;
            0)  echo; exit 0 ;;
            *)  ;;
        esac
    done
}

menu_main
