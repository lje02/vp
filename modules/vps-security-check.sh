#!/usr/bin/env bash
#
# vps-security-check.sh — VPS 木马/病毒/rootkit 排查脚本
#
# 用法:
#   交互菜单:   sudo ./vps-security-check.sh
#   命令行模式: sudo ./vps-security-check.sh <subcommand>
#
# 子命令:
#   all         执行全部检测项并生成报告 (默认)
#   process     可疑进程 / CPU & 内存占用异常
#   network     网络连接 & 监听端口
#   cron        定时任务 & 开机启动项
#   users       用户账号 & SSH 密钥 & sudoers
#   hidden      /tmp /dev/shm /var/tmp 下可疑可执行文件
#   preload     LD_PRELOAD / ld.so.preload 劫持检测
#   logs        登录日志 / 日志篡改痕迹
#   rootkit     rkhunter / chkrootkit 扫描 (若未安装会提示)
#   clamav      ClamAV 病毒扫描 (若未安装会提示，扫描耗时较长)
#   botnet      肉鸡/DDoS参与/C2连接/异常出口流量检测
#   report      仅重新生成/查看报告路径
#
set -euo pipefail

# ------------------------- 基础配置 -------------------------
SCRIPT_NAME="$(basename "$0")"
REPORT_DIR="/var/log/vps-security-check"
TS="$(date +%Y%m%d-%H%M%S)"
REPORT_FILE="${REPORT_DIR}/report-${TS}.txt"
FINDINGS=0   # 可疑项计数

# ------------------------- 颜色 & 日志 -------------------------
if [[ -t 1 ]]; then
    C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m'
    C_BLUE='\033[0;34m'; C_BOLD='\033[1m'; C_RESET='\033[0m'
else
    C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_BOLD=''; C_RESET=''
fi

log_info()  { echo -e "${C_BLUE}[信息]${C_RESET} $*"; }
log_ok()    { echo -e "${C_GREEN}[正常]${C_RESET} $*"; }
log_warn()  { echo -e "${C_YELLOW}[可疑]${C_RESET} $*"; FINDINGS=$((FINDINGS+1)); }
log_err()   { echo -e "${C_RED}[错误]${C_RESET} $*"; }
section()   { echo -e "\n${C_BOLD}==== $* ====${C_RESET}"; }

# 同时输出到终端和报告文件
exec > >(tee -a "${REPORT_FILE}") 2>&1

need_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "本脚本需要 root 权限运行，请使用 sudo ${SCRIPT_NAME}"
        exit 1
    fi
}

ensure_report_dir() {
    mkdir -p "${REPORT_DIR}"
    chmod 700 "${REPORT_DIR}"
}

pkg_install() {
    # 简单跨发行版安装封装
    local pkg="$1"
    if command -v apt >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y "$pkg"
    elif command -v yum >/dev/null 2>&1; then
        yum install -y "$pkg"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y "$pkg"
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache "$pkg"
    else
        log_err "未识别的包管理器，请手动安装 $pkg"
        return 1
    fi
}

confirm() {
    local prompt="$1"
    local ans
    read -r -p "$(echo -e "${C_YELLOW}${prompt} [y/N]: ${C_RESET}")" ans
    [[ "$ans" =~ ^[Yy]$ ]]
}

# ------------------------- 检测模块 -------------------------

check_process() {
    section "1. 可疑进程 / CPU & 内存占用"

    log_info "CPU 占用 TOP 15"
    ps aux --sort=-%cpu | head -16

    echo
    log_info "内存占用 TOP 15"
    ps aux --sort=-%mem | head -16

    echo
    log_info "检查进程可执行文件路径是否位于可疑目录 (/tmp /dev/shm /var/tmp)"
    local suspicious=0
    while read -r pid; do
        [[ -z "$pid" ]] && continue
        local exe
        exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
        if [[ "$exe" =~ ^/(tmp|dev/shm|var/tmp) ]]; then
            log_warn "PID ${pid} 的可执行文件位于可疑目录: ${exe}"
            ps -p "$pid" -o pid,ppid,user,cmd --no-headers 2>/dev/null || true
            suspicious=1
        fi
    done < <(ls /proc 2>/dev/null | grep -E '^[0-9]+$')
    [[ $suspicious -eq 0 ]] && log_ok "未发现进程可执行文件位于 /tmp /dev/shm /var/tmp"

    echo
    log_info "检查是否存在已删除但仍在运行的可执行文件 (常见于清理痕迹的木马)"
    local deleted=0
    while read -r pid; do
        [[ -z "$pid" ]] && continue
        if readlink "/proc/${pid}/exe" 2>/dev/null | grep -q '(deleted)'; then
            log_warn "PID ${pid} 正在运行一个已删除的可执行文件"
            ls -la "/proc/${pid}/exe" 2>/dev/null || true
            deleted=1
        fi
    done < <(ls /proc 2>/dev/null | grep -E '^[0-9]+$')
    [[ $deleted -eq 0 ]] && log_ok "未发现运行中的已删除可执行文件"
}

check_network() {
    section "2. 网络连接 & 监听端口"

    log_info "当前监听端口 (含进程)"
    if command -v ss >/dev/null 2>&1; then
        ss -tulnp
    else
        netstat -tulnp 2>/dev/null || log_err "未找到 ss 或 netstat"
    fi

    echo
    log_info "当前已建立的外发连接 (对外连接数按目标 IP 排序 TOP 15，挖矿/C2 回连常见)"
    if command -v ss >/dev/null 2>&1; then
        ss -tnp state established 2>/dev/null | awk 'NR>1{print $4}' | \
            awk -F: '{print $1}' | sort | uniq -c | sort -rn | head -15
    fi

    echo
    log_info "检查是否存在监听在高危端口但非常见服务的进程 (需人工判断)"
    log_ok "以上列表请人工核对：是否所有监听端口/外发连接都能对应到你自己部署的服务"
}

check_cron() {
    section "3. 定时任务 & 开机启动项"

    log_info "root 及所有用户的 crontab"
    for u in $(cut -f1 -d: /etc/passwd); do
        local c
        c="$(crontab -u "$u" -l 2>/dev/null || true)"
        if [[ -n "$c" ]]; then
            echo "--- user: $u ---"
            echo "$c"
        fi
    done

    echo
    log_info "系统级 cron"
    cat /etc/crontab 2>/dev/null || true
    for f in /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
        [[ -f "$f" ]] && { echo "--- $f ---"; cat "$f"; }
    done 2>/dev/null

    echo
    log_info "已启用的 systemd 服务 (人工核对是否有陌生服务名)"
    systemctl list-unit-files --type=service 2>/dev/null | grep enabled || true

    echo
    log_info "systemd timer (crontab 之外的另一种定时任务隐藏方式)"
    systemctl list-timers --all 2>/dev/null || true
}

check_users() {
    section "4. 用户账号 / SSH 密钥 / sudoers"

    log_info "可登录用户 (排除 nologin/false)"
    grep -Ev '/(nologin|false)$' /etc/passwd

    echo
    log_info "UID=0 的账号 (正常应只有 root)"
    local root_accounts
    root_accounts="$(awk -F: '$3==0{print $1}' /etc/passwd)"
    echo "$root_accounts"
    if [[ "$(echo "$root_accounts" | wc -l)" -gt 1 ]]; then
        log_warn "发现多个 UID=0 的账号，请确认是否为你本人添加"
    else
        log_ok "只有 root 一个 UID=0 账号"
    fi

    echo
    log_info "sudoers 配置"
    cat /etc/sudoers 2>/dev/null
    ls /etc/sudoers.d/ 2>/dev/null && for f in /etc/sudoers.d/*; do
        [[ -f "$f" ]] && { echo "--- $f ---"; cat "$f"; }
    done

    echo
    log_info "各用户 authorized_keys (请核对每一条公钥是否为你本人添加)"
    for home in /root /home/*; do
        local akf="${home}/.ssh/authorized_keys"
        if [[ -f "$akf" ]]; then
            echo "--- $akf ---"
            cat "$akf"
        fi
    done
}

check_hidden() {
    section "5. 可疑目录扫描 (/tmp /dev/shm /var/tmp)"

    for dir in /tmp /dev/shm /var/tmp; do
        log_info "扫描 ${dir} 下的可执行文件"
        find "$dir" -maxdepth 3 -type f -perm -u+x 2>/dev/null | while read -r f; do
            log_warn "可执行文件: $f"
            file "$f" 2>/dev/null || true
            ls -la "$f"
        done
    done

    echo
    log_info "检查近 7 天内 /etc /usr/bin /usr/sbin /bin /sbin 下被修改的文件 (可能是被替换的系统命令)"
    find /etc /usr/bin /usr/sbin /bin /sbin -type f -mtime -7 2>/dev/null | head -50
    log_info "以上列表请人工核对：是否为你近期系统更新/自己操作导致的变更"
}

check_preload() {
    section "6. LD_PRELOAD 劫持检测 (常见 rootkit 隐藏手法)"

    if [[ -f /etc/ld.so.preload ]]; then
        log_warn "/etc/ld.so.preload 文件存在，正常系统不应有此文件（除非你自己配置过）："
        cat /etc/ld.so.preload
    else
        log_ok "/etc/ld.so.preload 不存在"
    fi

    if [[ -n "${LD_PRELOAD:-}" ]]; then
        log_warn "当前 shell 环境变量 LD_PRELOAD 被设置为: ${LD_PRELOAD}"
    else
        log_ok "当前环境变量 LD_PRELOAD 未设置"
    fi

    echo
    log_info "检查各用户 shell profile 中是否被注入 LD_PRELOAD"
    grep -l "LD_PRELOAD" /root/.bashrc /root/.profile /etc/profile /etc/bash.bashrc /home/*/.bashrc 2>/dev/null || log_ok "未在常见 profile 文件中发现 LD_PRELOAD 注入"
}

check_logs() {
    section "7. 登录日志 & 日志完整性"

    log_info "最近成功登录记录"
    last -a 2>/dev/null | head -30

    echo
    log_info "最近登录失败记录 (爆破迹象)"
    lastb 2>/dev/null | head -30 || log_info "lastb 不可用或无权限"

    echo
    log_info "auth 日志中的成功登录"
    if [[ -f /var/log/auth.log ]]; then
        grep "Accepted" /var/log/auth.log | tail -30
    elif [[ -f /var/log/secure ]]; then
        grep "Accepted" /var/log/secure | tail -30
    else
        log_info "未找到 auth.log / secure，可能使用 journalctl"
        journalctl -u sshd --since "-7 days" 2>/dev/null | grep -i accepted | tail -30 || true
    fi

    echo
    log_info "日志文件大小/时间检查 (被清空的日志文件体积会异常小)"
    ls -la /var/log/*.log 2>/dev/null | sort -k5 -n | head -10
}

check_rootkit() {
    section "8. rkhunter / chkrootkit 扫描"

    if ! command -v rkhunter >/dev/null 2>&1; then
        if confirm "未检测到 rkhunter，是否现在安装？"; then
            pkg_install rkhunter || log_err "rkhunter 安装失败"
        fi
    fi
    if command -v rkhunter >/dev/null 2>&1; then
        log_info "运行 rkhunter --check --sk (跳过交互确认)"
        rkhunter --update --nocolors 2>/dev/null || true
        rkhunter --check --sk --nocolors 2>&1 | tail -100
    fi

    echo
    if ! command -v chkrootkit >/dev/null 2>&1; then
        if confirm "未检测到 chkrootkit，是否现在安装？"; then
            pkg_install chkrootkit || log_err "chkrootkit 安装失败"
        fi
    fi
    if command -v chkrootkit >/dev/null 2>&1; then
        log_info "运行 chkrootkit"
        chkrootkit 2>&1 | grep -v "not infected" | grep -vE "^Searching|^Checking" | head -100
    fi
}

check_clamav() {
    section "9. ClamAV 病毒扫描 (耗时较长，扫描全盘可能需要数十分钟)"

    if ! command -v clamscan >/dev/null 2>&1; then
        if confirm "未检测到 ClamAV，是否现在安装？"; then
            pkg_install clamav || log_err "clamav 安装失败"
        else
            log_info "跳过 ClamAV 扫描"
            return
        fi
    fi

    if command -v freshclam >/dev/null 2>&1; then
        log_info "更新病毒库..."
        freshclam 2>&1 | tail -20 || true
    fi

    if confirm "是否扫描全盘 (较慢)? 选 N 将只扫描 /tmp /home /root /var/www"; then
        SCAN_PATHS="/"
    else
        SCAN_PATHS="/tmp /home /root /var/www"
    fi

    log_info "开始扫描: ${SCAN_PATHS}"
    clamscan -r ${SCAN_PATHS} \
        --exclude-dir="^/sys" --exclude-dir="^/proc" --exclude-dir="^/dev" \
        -i 2>&1 | tail -200
}

check_botnet() {
    section "10. 肉鸡 / DDoS 参与 / C2 连接检测"

    log_info "网卡是否处于混杂模式 (被用于嗅探流量的迹象)"
    if command -v ip >/dev/null 2>&1; then
        if ip link show 2>/dev/null | grep -qi PROMISC; then
            log_warn "检测到网卡处于混杂(PROMISC)模式："
            ip link show | grep -i -B1 PROMISC
        else
            log_ok "未发现网卡处于混杂模式"
        fi
    fi

    echo
    log_info "出站连接是否集中打向少数几个 IP 的高危端口 (C2/爆破工具特征)"
    if command -v ss >/dev/null 2>&1; then
        log_info "当前建立(ESTABLISHED)的出站连接，按目的 IP:端口 统计 TOP 20"
        ss -tnp state established 2>/dev/null | awk 'NR>1{print $4}' | sort | uniq -c | sort -rn | head -20
    fi

    echo
    log_info "对外发起连接的目的 IP 去重数量 (数值异常大 = 可能在扫描/爆破外部主机)"
    if command -v ss >/dev/null 2>&1; then
        local dest_count
        dest_count="$(ss -tnp state established 2>/dev/null | awk 'NR>1{print $4}' | awk -F: '{print $1}' | sort -u | wc -l)"
        echo "当前不同目的 IP 数量: ${dest_count}"
        if [[ "$dest_count" -gt 50 ]]; then
            log_warn "同时连接的不同目的 IP 数量偏多 (${dest_count})，请核对是否为正常业务(如爬虫/CDN回源)"
        else
            log_ok "目的 IP 数量在正常范围"
        fi
    fi

    echo
    log_info "是否存在到常见 C2/后门端口 (6667 IRC, 6697 IRCS, 4444, 1337, 31337) 的连接"
    if command -v ss >/dev/null 2>&1; then
        local hit
        hit="$(ss -tnp 2>/dev/null | grep -E ':(6667|6697|4444|1337|31337)\b' || true)"
        if [[ -n "$hit" ]]; then
            log_warn "发现可疑端口连接："
            echo "$hit"
        else
            log_ok "未发现到常见 C2 端口的连接"
        fi
    fi

    echo
    log_info "网卡实时流量速览 (观察 10 秒，判断出口带宽是否异常，可能有较高流量的正常业务，请结合自己情况判断)"
    if command -v ip >/dev/null 2>&1; then
        local iface
        iface="$(ip route | awk '/default/ {print $5; exit}')"
        if [[ -n "$iface" ]]; then
            local rx1 tx1 rx2 tx2
            rx1="$(cat /sys/class/net/"$iface"/statistics/rx_bytes 2>/dev/null || echo 0)"
            tx1="$(cat /sys/class/net/"$iface"/statistics/tx_bytes 2>/dev/null || echo 0)"
            sleep 10
            rx2="$(cat /sys/class/net/"$iface"/statistics/rx_bytes 2>/dev/null || echo 0)"
            tx2="$(cat /sys/class/net/"$iface"/statistics/tx_bytes 2>/dev/null || echo 0)"
            local rx_rate=$(( (rx2 - rx1) / 10 / 1024 ))
            local tx_rate=$(( (tx2 - tx1) / 10 / 1024 ))
            echo "网卡: ${iface}  入站: ${rx_rate} KB/s   出站: ${tx_rate} KB/s"
            if [[ $tx_rate -gt 5000 ]]; then
                log_warn "出站流量较高 (${tx_rate} KB/s)，若你没有在主动上传/分发大文件，建议留意是否为 DDoS 参与或数据外传"
            else
                log_ok "出站流量在观测窗口内未见明显异常"
            fi
        else
            log_info "未能识别默认出口网卡，跳过流量测速"
        fi
    fi

    echo
    log_info "SYN 半连接数量 (SYN Flood 参与者常见特征：本机对外发起大量 SYN_SENT)"
    if command -v ss >/dev/null 2>&1; then
        local syn_sent
        syn_sent="$(ss -tn state syn-sent 2>/dev/null | wc -l)"
        echo "当前 SYN_SENT 数量: ${syn_sent}"
        if [[ "$syn_sent" -gt 100 ]]; then
            log_warn "SYN_SENT 数量异常偏高 (${syn_sent})，疑似正在对外发起大量连接尝试(扫描/SYN flood)"
        else
            log_ok "SYN_SENT 数量正常"
        fi
    fi

    echo
    log_info "本机 IP 信誉核对建议"
    local pub_ip
    pub_ip="$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null || curl -s --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    if [[ -n "$pub_ip" ]]; then
        echo "当前出口公网 IP: ${pub_ip}"
        echo "可手动访问以下网站核对该 IP 是否已被标记为恶意/垃圾邮件/DDoS来源:"
        echo "  https://www.abuseipdb.com/check/${pub_ip}"
        echo "  https://check.spamhaus.org/"
    else
        log_info "未能获取公网出口 IP (可能是 curl 不可用或网络受限)，可自行在浏览器查询"
    fi
}

# ------------------------- 汇总 -------------------------

print_summary() {
    section "排查完成"
    echo -e "报告已保存至: ${C_BOLD}${REPORT_FILE}${C_RESET}"
    if [[ $FINDINGS -gt 0 ]]; then
        echo -e "${C_RED}共发现 ${FINDINGS} 处标记为[可疑]的项目，请逐条人工核实。${C_RESET}"
        echo -e "${C_YELLOW}若确认被入侵，建议：断网隔离 -> 保留现场用于取证 -> 重装系统，而非仅删除文件。${C_RESET}"
    else
        echo -e "${C_GREEN}未发现明显异常项，但脚本无法保证 100% 排除隐蔽 rootkit，建议结合 rkhunter/chkrootkit 结果综合判断。${C_RESET}"
    fi
}

run_all() {
    check_process
    check_network
    check_cron
    check_users
    check_hidden
    check_preload
    check_logs
    check_rootkit
    check_botnet
    print_summary
}

# ------------------------- 交互菜单 -------------------------

show_menu() {
    echo -e "${C_BOLD}VPS 木马/病毒排查脚本${C_RESET}  报告目录: ${REPORT_DIR}"
    cat <<EOF
  1) 全部检测 (含 rkhunter/chkrootkit)
  2) 可疑进程
  3) 网络连接 & 端口
  4) 定时任务 & 启动项
  5) 用户账号 & SSH 密钥
  6) 可疑目录扫描 (/tmp /dev/shm /var/tmp)
  7) LD_PRELOAD 劫持检测
  8) 登录日志
  9) rkhunter / chkrootkit
 10) ClamAV 病毒扫描 (较慢，需单独确认)
 11) 肉鸡/DDoS参与/C2连接检测 (含10秒流量测速)
  0) 退出
EOF
    read -r -p "请选择: " choice
    case "$choice" in
        1) run_all ;;
        2) check_process ;;
        3) check_network ;;
        4) check_cron ;;
        5) check_users ;;
        6) check_hidden ;;
        7) check_preload ;;
        8) check_logs ;;
        9) check_rootkit ;;
        10) check_clamav ;;
        11) check_botnet ;;
        0) exit 0 ;;
        *) log_err "无效选项" ;;
    esac
}

# ------------------------- 入口 -------------------------

main() {
    need_root
    ensure_report_dir

    local sub="${1:-}"
    if [[ -z "$sub" ]]; then
        show_menu
        exit 0
    fi

    case "$sub" in
        all)      run_all ;;
        process)  check_process ;;
        network)  check_network ;;
        cron)     check_cron ;;
        users)    check_users ;;
        hidden)   check_hidden ;;
        preload)  check_preload ;;
        logs)     check_logs ;;
        rootkit)  check_rootkit ;;
        clamav)   check_clamav ;;
        botnet)   check_botnet ;;
        report)   echo "${REPORT_FILE}" ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^#//'
            ;;
        *)
            log_err "未知子命令: $sub"
            grep '^#' "$0" | sed 's/^#//'
            exit 1
            ;;
    esac
}

main "$@"
