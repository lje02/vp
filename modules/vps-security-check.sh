#!/usr/bin/env bash
#
# vps-security-check.sh — VPS 木马/病毒/rootkit 排查脚本 (v2.0)
#
# 用法:
#   sudo ./vps-security-check.sh [选项] [子命令]
#   不带子命令: 终端交互时进入菜单; 非交互 (cron/管道) 时执行 all
#
# 子命令:
#   all         执行全部检测项 (默认不含 clamav, 加 --with-clamav 可包含) 并生成报告
#   process     可疑进程 / 隐藏进程 / 无文件木马 / 挖矿特征 / CPU 异常
#   network     监听端口 / 高危服务暴露 / 外联统计 / 防火墙 / hosts & DNS
#   cron        定时任务 / systemd 单元 / 开机与登录脚本 (含恶意命令特征匹配)
#   users       账号 / 空密码 / sudoers / SSH 密钥 / sshd 配置
#   hidden      /tmp /var/tmp /dev/shm /dev 下的可疑文件 (ELF/脚本/隐藏文件)
#   integrity   系统包文件校验 / SUID 基线 / 隐藏内核模块 / 异常文件名
#   preload     LD_PRELOAD / ld.so.preload / 动态库劫持检测
#   logs        登录日志分析 / 爆破成功 / 新来源 IP / 日志篡改痕迹 / 历史命令
#   rootkit     rkhunter / chkrootkit 扫描 (未安装会询问是否安装)
#   clamav      ClamAV 病毒扫描 (耗时较长)
#   botnet      肉鸡 / DDoS / C2 / 挖矿连接 / 异常出口流量
#   web         Web 目录 webshell 特征
#   report      查看最近一次报告路径 & 可疑项清单
#
# 选项:
#   -y, --yes        所有确认默认回答 yes (含自动安装依赖; 不含 ClamAV 全盘扫描)
#       --no-install 不安装任何软件 (应急取证场景推荐)
#       --online     允许访问外网 (获取公网 IP 并给出信誉查询链接)
#       --with-clamav  all 中包含 ClamAV
#       --full-scan  ClamAV 全盘扫描 (默认只扫常见目录)
#   -q, --quiet      终端只输出汇总, 完整内容写入报告 (非交互)
#       --json       额外生成 JSON 格式的可疑项清单
#       --no-color   关闭颜色 (同样支持 NO_COLOR 环境变量)
#   -V, --version    显示版本
#   -h, --help       显示帮助
#
# 退出码: 0 未发现可疑项 | 1 发现可疑项 | 2 参数/运行错误
#
# 可调环境变量 (括号内为默认值):
#   DEST_IP_THRESHOLD(50) SYN_SENT_THRESHOLD(100) TX_KBPS_THRESHOLD(5000)
#   TX_PPS_THRESHOLD(20000) UDP_PPS_THRESHOLD(5000) FANOUT_THRESHOLD(5)
#   SAMPLE_SECONDS(10, 设为 0 跳过流量采样) CPU_THRESHOLD(80)
#   BRUTE_FAIL_THRESHOLD(20) LOG_GAP_HOURS(12) PID_BRUTE_MAX(65536)
#   EXE_ALLOW_REGEX (用户隐藏目录进程白名单正则)
#
# 注意: 若主机已被入侵, ps/ss/ls 等系统命令本身可能被替换, 本脚本结果仅供参考。
#       应急取证建议加 --no-install, 并考虑使用只读介质上的可信工具对照。
#

set -uo pipefail
umask 077
export LC_ALL=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

if (( BASH_VERSINFO[0] < 4 )); then
    echo "本脚本需要 bash >= 4" >&2
    exit 2
fi

# ------------------------- 基础配置 -------------------------
VERSION="2.0.0"
SCRIPT_NAME="$(basename "$0")"
REPORT_DIR="${VPSCHK_REPORT_DIR:-/var/log/vps-security-check}"
STATE_DIR="${VPSCHK_STATE_DIR:-/var/lib/vps-security-check}"
LOG_DIR="${VPSCHK_LOG_DIR:-/var/log}"
LOCK_FILE="${VPSCHK_LOCK_FILE:-/run/vps-security-check.lock}"
TS="$(date +%Y%m%d-%H%M%S)"
REPORT_FILE="${REPORT_DIR}/report-${TS}.txt"
FINDINGS_FILE="${REPORT_DIR}/findings-${TS}.txt"
JSON_FILE="${REPORT_DIR}/findings-${TS}.json"
CURRENT_SECTION=""
TMP_DIR=""
PKG_FAMILY="none"

# 阈值 (可用同名环境变量覆盖)
DEST_IP_THRESHOLD="${DEST_IP_THRESHOLD:-50}"
SYN_SENT_THRESHOLD="${SYN_SENT_THRESHOLD:-100}"
TX_KBPS_THRESHOLD="${TX_KBPS_THRESHOLD:-5000}"
TX_PPS_THRESHOLD="${TX_PPS_THRESHOLD:-20000}"
UDP_PPS_THRESHOLD="${UDP_PPS_THRESHOLD:-5000}"
FANOUT_THRESHOLD="${FANOUT_THRESHOLD:-5}"
SAMPLE_SECONDS="${SAMPLE_SECONDS:-10}"
CPU_THRESHOLD="${CPU_THRESHOLD:-80}"
BRUTE_FAIL_THRESHOLD="${BRUTE_FAIL_THRESHOLD:-20}"
LOG_GAP_HOURS="${LOG_GAP_HOURS:-12}"
PID_BRUTE_MAX="${PID_BRUTE_MAX:-65536}"
EXE_ALLOW_REGEX="${EXE_ALLOW_REGEX:-/\.(vscode-server|cursor-server|nvm|cargo|rustup|pyenv|sdkman|volta|bun|deno|pnpm|config/Code)/}"

# 特征库
MINER_REGEX='xmrig|minerd|cpuminer|kdevtmpfsi|kinsing|cryptonight|stratum\+(tcp|ssl)|--donate-level|nanominer|lolminer|ccminer|ethminer|xmr-stak|kthreaddi|watchdogs'
HIGH_CMD_REGEX='(curl|wget|fetch|lwp-download)[^|;&]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|da|k)?sh([[:space:]]|$)|/dev/(tcp|udp)/|base64[[:space:]]+(-d|--decode)[^|]*\|[[:space:]]*(ba)?sh|(nc|ncat|netcat)[[:space:]].*[[:space:]]-e[[:space:]]|bash[[:space:]]+-i[[:space:]]+>&|stratum\+(tcp|ssl)|xmrig|kinsing|kdevtmpfsi'
SUSP_CMD_REGEX='(curl|wget)[[:space:]].*(-O|-o|>)[[:space:]]*/(tmp|dev/shm|var/tmp)|(^|[^[:alnum:]_./-])/(tmp|dev/shm|var/tmp)/[^[:space:]]+|chmod[[:space:]]+(\+x|[0-7]{3,4})[[:space:]]+/(tmp|dev/shm|var/tmp)|python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e|base64[[:space:]]+(-d|--decode)|\.onion|pastebin\.com|transfer\.sh|history[[:space:]]+-c|unset[[:space:]]+HISTFILE|chattr[[:space:]]+[-+]i'
HIST_REGEX="(${HIGH_CMD_REGEX}|${SUSP_CMD_REGEX}|HISTFILE=/dev/null|HISTSIZE=0|iptables[[:space:]]+-F|insmod[[:space:]])"
WEBSHELL_REGEX='eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|\$_(POST|GET|REQUEST|COOKIE))|assert[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)|(system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)|c99shell|r57shell|b374k|FilesMan|WSO [0-9]|AntSword|@eval\(\$_|Runtime\.getRuntime\(\)\.exec\(request\.getParameter'
C2_PORTS="6667 6697 4444 1337 31337"
MINER_PORTS="3333 5555 7777 14433 14444 45560 45700 3357"

# 选项默认值
OPT_YES=0; OPT_NO_INSTALL=0; OPT_ONLINE=0; OPT_WITH_CLAMAV=0; OPT_FULL_SCAN=0
OPT_QUIET=0; OPT_JSON=0; OPT_NO_COLOR=0
SUBCMD=""
IS_TTY_IN=0; IS_TTY_OUT=0
[[ -t 0 ]] && IS_TTY_IN=1
[[ -t 1 ]] && IS_TTY_OUT=1

# ------------------------- 颜色 & 日志 -------------------------
C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_BOLD=''; C_RESET=''

init_colors() {
    if (( IS_TTY_OUT )) && (( ! OPT_NO_COLOR )) && [[ -z "${NO_COLOR:-}" ]]; then
        C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m'
        C_BLUE='\033[0;34m'; C_BOLD='\033[1m'; C_RESET='\033[0m'
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# 过滤外部数据中的控制字符 (防止恶意文件名/内容里的转义序列污染终端)
safe() { tr -d '\000-\010\013-\037\177'; }

# 清洗单行消息: 控制字符 -> 空格, 截断到 300 字节 (结果放在 CLEAN)
CLEAN=""
_clean() { CLEAN="$*"; CLEAN=${CLEAN//[[:cntrl:]]/ }; CLEAN=${CLEAN:0:300}; }

record_finding() {
    # $1=严重度(HIGH|MEDIUM) $2=消息
    printf '%s\t%s\t%s\n' "${CURRENT_SECTION}" "$1" "$2" >> "${FINDINGS_FILE}"
}

log_info() { printf '%b[信息]%b %s\n' "$C_BLUE" "$C_RESET" "$*"; }
log_ok()   { printf '%b[正常]%b %s\n' "$C_GREEN" "$C_RESET" "$*"; }
log_err()  { printf '%b[错误]%b %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
log_warn() { _clean "$@"; printf '%b[可疑]%b %s\n' "$C_YELLOW" "$C_RESET" "$CLEAN"; record_finding MEDIUM "$CLEAN"; }
log_high() { _clean "$@"; printf '%b[高危]%b %s\n' "${C_RED}${C_BOLD}" "$C_RESET" "$CLEAN"; record_finding HIGH "$CLEAN"; }
section()  { CURRENT_SECTION="$*"; printf '\n%b==== %s ====%b\n' "$C_BOLD" "$*" "$C_RESET"; }

usage() {
    awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
}

# ------------------------- 通用辅助 -------------------------

need_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "本脚本需要 root 权限运行，请使用 sudo ${SCRIPT_NAME}"
        exit 2
    fi
}

ensure_dirs() {
    mkdir -p "${REPORT_DIR}" "${STATE_DIR}"
    chmod 700 "${REPORT_DIR}" "${STATE_DIR}"
}

acquire_lock() {
    have flock || return 0
    exec 9>"${LOCK_FILE}" 2>/dev/null || return 0
    if ! flock -n 9; then
        log_err "已有另一个实例在运行 (锁文件: ${LOCK_FILE})"
        exit 2
    fi
}

detect_pkg() {
    if have dpkg && have apt-get; then PKG_FAMILY="deb"
    elif have rpm && { have dnf || have yum; }; then PKG_FAMILY="rpm"
    elif have apk; then PKG_FAMILY="apk"
    else PKG_FAMILY="none"
    fi
}

confirm() {
    local prompt="$1" ans
    (( OPT_YES )) && return 0
    (( OPT_QUIET )) && return 1
    [[ -t 0 ]] || return 1
    read -r -p "$(printf '%b%s [y/N]: %b' "$C_YELLOW" "$prompt" "$C_RESET")" ans || return 1
    [[ "$ans" =~ ^[Yy]$ ]]
}

pkg_install() {
    local name="$1" pkgs mgr
    if (( OPT_NO_INSTALL )); then
        log_info "已指定 --no-install，跳过安装 ${name}"
        return 1
    fi
    pkgs="$name"
    [[ "$name:$PKG_FAMILY" == "clamav:rpm" ]] && pkgs="clamav clamav-update"
    log_info "注意: 安装软件会改动系统状态 (应急取证场景建议使用离线/只读介质)"
    case "$PKG_FAMILY" in
        deb)
            DEBIAN_FRONTEND=noninteractive apt-get update -qq &&
                # shellcheck disable=SC2086
                DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $pkgs
            ;;
        rpm)
            have dnf && mgr=dnf || mgr=yum
            # shellcheck disable=SC2086
            if ! "$mgr" install -y $pkgs; then
                log_info "RHEL/CentOS 系的 rkhunter/chkrootkit/clamav 通常需要先启用 EPEL: ${mgr} install -y epel-release"
                return 1
            fi
            ;;
        apk)
            # shellcheck disable=SC2086
            apk add --no-cache $pkgs
            ;;
        *)
            log_err "未识别的包管理器，请手动安装 ${name}"
            return 1
            ;;
    esac
}

ask_install() {
    if (( OPT_NO_INSTALL )); then
        log_info "未检测到 $1 (已指定 --no-install, 不安装)"
        return 1
    fi
    confirm "未检测到 $1，是否现在安装？(会修改系统)" || return 1
    pkg_install "$1"
}

# 打印不属于任何软件包的文件 (批量查询, 兼容 usrmerge 路径差异)
unowned_files() {
    (( $# )) || return 0
    local p alt
    case "$PKG_FAMILY" in
        deb)
            while IFS= read -r p; do
                [[ -z "$p" ]] && continue
                alt=""
                case "$p" in
                    /usr/*) alt=${p#/usr} ;;
                    /lib/*|/bin/*|/sbin/*) alt="/usr$p" ;;
                esac
                if [[ -n "$alt" ]] && dpkg -S -- "$alt" >/dev/null 2>&1; then continue; fi
                printf '%s\n' "$p"
            done < <(dpkg -S -- "$@" 2>&1 >/dev/null | sed -n 's/^dpkg-query: no path found matching pattern //p')
            ;;
        rpm)
            rpm -qf -- "$@" 2>/dev/null | sed -n 's/^file \(.*\) is not owned by any package$/\1/p'
            ;;
        apk)
            for p in "$@"; do
                apk info -W "$p" 2>&1 | grep -q 'owned by' || printf '%s\n' "$p"
            done
            ;;
        *) : ;;
    esac
}

# 目录去重 (按真实路径), 输出存在的目录
uniq_dirs() {
    local d r
    local -A s=()
    for d in "$@"; do
        [[ -d "$d" ]] || continue
        r=$(readlink -f "$d")
        [[ -n "${s[$r]:-}" ]] && continue
        s[$r]=1
        printf '%s\n' "$r"
    done
}

# 输出 user:uid:home:shell (按 home 去重, 排除无意义的 home)
list_homes() {
    getent passwd 2>/dev/null | awk -F: '$6!="" && $6!="/" && $6!="/nonexistent" && $6!="/dev/null" && !seen[$6]++ {print $1":"$3":"$6":"$7}'
}

# 对文件扫描恶意命令特征: mode=full(高危+可疑) | high(仅高危, 用于软件包自带文件)
scan_text_file() {
    local f="$1" mode="${2:-full}" line
    [[ -f "$f" && -r "$f" ]] || return 0
    while IFS= read -r line; do
        log_high "$f: ${line:0:200}"
    done < <(grep -aEv '^[[:space:]]*#' "$f" 2>/dev/null | grep -aE "$HIGH_CMD_REGEX" | head -10)
    [[ "$mode" == "full" ]] || return 0
    while IFS= read -r line; do
        log_warn "$f: ${line:0:200}"
    done < <(grep -aEv '^[[:space:]]*#' "$f" 2>/dev/null | grep -aE "$SUSP_CMD_REGEX" | grep -aEv "$HIGH_CMD_REGEX" | head -10)
}

# 自动判断: 非软件包文件完整扫描, 软件包自带文件只扫高危特征
scan_files_auto() {
    (( $# )) || return 0
    local -A un=()
    local f
    while IFS= read -r f; do [[ -n "$f" ]] && un[$f]=1; done < <(unowned_files "$@")
    for f in "$@"; do
        if [[ -n "${un[$f]:-}" || "$PKG_FAMILY" == "none" ]]; then
            scan_text_file "$f" full
        else
            scan_text_file "$f" high
        fi
    done
}

# 检查 chattr 的 immutable / append-only 属性 (攻击者常用来锁住后门文件)
flag_immutable() {
    (( $# )) || return 0
    have lsattr || return 0
    local flags f
    while read -r flags f; do
        [[ -z "${f:-}" ]] && continue
        if [[ "$flags" =~ [ia] ]]; then
            log_warn "文件设置了不可变/仅追加属性 (${flags}): $f"
        fi
    done < <(lsattr -d -- "$@" 2>/dev/null)
}

show_proc() {
    ps -p "$1" -o pid,ppid,user:12,lstart,args --no-headers 2>/dev/null | safe
}

# ---- 网络辅助 ----

# /proc/net/tcp 中指定状态(十六进制)的本地端口, 例如 0A=LISTEN
proc_ports() {
    local st="$1" h
    shift
    awk -v st="$st" 'FNR>1 && $4==st {n=split($2,a,":"); print a[n]}' "$@" 2>/dev/null |
        while read -r h; do echo $((16#$h)); done
}

# 本机正在监听/绑定的端口 (TCP+UDP)
listen_ports() {
    if have ss; then
        ss -tuln 2>/dev/null | awk 'NR>1{n=split($5,a,":"); if(a[n]!="") print a[n]}'
    else
        proc_ports 0A /proc/net/tcp /proc/net/tcp6
        proc_ports 07 /proc/net/udp /proc/net/udp6
    fi
}

# 已建立连接: 本地端口 对端IP 对端端口 进程信息
established_conns() {
    if have ss; then
        ss -tnp state established 2>/dev/null | awk 'NR>1 && NF>=4 {
            lp=$3; sub(/.*:/,"",lp)
            pp=$4; sub(/.*:/,"",pp)
            ip=$4; sub(/:[0-9]+$/,"",ip); gsub(/\[|\]/,"",ip); sub(/^::ffff:/,"",ip)
            print lp, ip, pp, ($5=="" ? "-" : $5)
        }'
    else
        local lhex rhex lp rp h ip
        while read -r lhex rhex; do
            lp=$((16#${lhex##*:})); rp=$((16#${rhex##*:}))
            h=${rhex%%:*}
            ip=$(printf '%d.%d.%d.%d' "0x${h:6:2}" "0x${h:4:2}" "0x${h:2:2}" "0x${h:0:2}")
            echo "$lp $ip $rp -"
        done < <(awk 'FNR>1 && $4=="01"{print $2, $3}' /proc/net/tcp 2>/dev/null)
    fi
}

# 本机主动发起的外联 (排除本地端口为监听端口的入站连接, 排除回环)
outbound_conns() {
    local lp
    lp=" $(listen_ports | sort -un | tr '\n' ' ') "
    established_conns | awk -v lp="$lp" '{ if (index(lp, " " $1 " ")==0 && $2 !~ /^127\./ && $2 != "::1") print }'
}

risky_port_desc() {
    case "$1" in
        2375)       echo "Docker Engine API (无 TLS 认证, 可直接获得 root)|HIGH" ;;
        10250)      echo "Kubelet API|HIGH" ;;
        23)         echo "Telnet|HIGH" ;;
        6379)       echo "Redis|MEDIUM" ;;
        27017)      echo "MongoDB|MEDIUM" ;;
        9200|9300)  echo "Elasticsearch|MEDIUM" ;;
        11211)      echo "Memcached|MEDIUM" ;;
        3306)       echo "MySQL/MariaDB|MEDIUM" ;;
        5432)       echo "PostgreSQL|MEDIUM" ;;
        5984)       echo "CouchDB|MEDIUM" ;;
        2181)       echo "ZooKeeper|MEDIUM" ;;
        2379|2380)  echo "etcd|MEDIUM" ;;
        5900|5901)  echo "VNC|MEDIUM" ;;
        873)        echo "rsync|MEDIUM" ;;
        3389)       echo "RDP|MEDIUM" ;;
        1433)       echo "MSSQL|MEDIUM" ;;
        *)          return 1 ;;
    esac
}

default_iface() {
    local i
    i=$(awk 'NR>1 && $2=="00000000"{print $1; exit}' /proc/net/route 2>/dev/null)
    if [[ -z "$i" ]] && have ip; then
        i=$(ip route show default 2>/dev/null | awk '{for(k=1;k<NF;k++) if($k=="dev"){print $(k+1); exit}}')
    fi
    printf '%s' "$i"
}

# 输出: rx_bytes rx_packets tx_bytes tx_packets
net_counters() {
    sed 's/:/ /' /proc/net/dev 2>/dev/null | awk -v i="$1" '$1==i {print $2, $3, $10, $11}'
}

udp_out() {
    awk '/^Udp:/{n++; if(n==1){for(i=2;i<=NF;i++) if($i=="OutDatagrams") c=i} else print $c}' /proc/net/snmp 2>/dev/null
}

# ------------------------- 检测模块 -------------------------

# 1 ---------------------------------------------------------
detect_hidden_pids() {
    log_info "隐藏进程检测: 对比 /proc 与 ps 输出, 并用 kill -0 暴力探测 PID 空间"
    local d p max found=0
    local -a procs=() cands=()
    local -A pspids=() tids=()

    procs=(/proc/[0-9]*)
    for p in $(ps -e -o pid= 2>/dev/null); do pspids[$p]=1; done
    if (( ${#pspids[@]} == 0 )); then
        log_info "ps 无输出, 跳过 /proc 对比"
    else
        for d in "${procs[@]}"; do
            p=${d#/proc/}
            [[ -z "${pspids[$p]:-}" ]] && cands+=("$p")
        done
        sleep 0.5
        for p in "${cands[@]+"${cands[@]}"}"; do
            if [[ -d "/proc/$p" ]] && [[ -z "$(ps -p "$p" -o pid= 2>/dev/null)" ]]; then
                log_high "PID $p 存在于 /proc 但 ps 看不到 (进程被隐藏, 或 ps 已被替换)"
                found=1
            fi
        done
    fi

    for d in /proc/[0-9]*/task/*; do tids[${d##*/}]=1; done
    max=$(<"/proc/sys/kernel/pid_max")
    (( max > PID_BRUTE_MAX )) && max=$PID_BRUTE_MAX
    cands=()
    for (( p=1; p<=max; p++ )); do
        if kill -0 "$p" 2>/dev/null; then
            [[ -d "/proc/$p" || -n "${tids[$p]:-}" ]] && continue
            cands+=("$p")
        fi
    done
    sleep 0.5
    for p in "${cands[@]+"${cands[@]}"}"; do
        [[ -d "/proc/$p" ]] && continue
        if kill -0 "$p" 2>/dev/null; then
            log_high "PID $p 存活 (kill -0 成功) 但 /proc 中不可见 (疑似内核/用户态 rootkit 隐藏进程)"
            found=1
        fi
    done
    (( found )) || log_ok "未发现隐藏进程 (PID 探测范围 1-${max})"
}

check_process() {
    section "1. 可疑进程 / 隐藏进程 / CPU & 内存占用"

    log_info "CPU 占用 TOP 15"
    ps -eo pid,user:12,pcpu,pmem,etime,args --sort=-pcpu 2>/dev/null | head -16 | safe
    echo
    log_info "内存占用 TOP 15"
    ps -eo pid,user:12,pcpu,pmem,etime,args --sort=-pmem 2>/dev/null | head -16 | safe

    echo
    log_info "逐进程检查: 临时目录 / memfd / 已删除二进制 / 伪装内核线程 / 挖矿特征"
    local d pid exe path cmd flagged found=0
    local -a upgraded=()
    for d in /proc/[0-9]*; do
        pid=${d#/proc/}
        [[ "$pid" == "$$" || "$pid" == "$BASHPID" ]] && continue
        exe=$(readlink "$d/exe" 2>/dev/null) || continue
        [[ -z "$exe" ]] && continue
        cmd=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)
        cmd=${cmd:0:160}
        path=${exe% (deleted)}
        flagged=0

        if [[ "$exe" == /memfd:* ]]; then
            log_high "PID $pid 从 memfd 运行 (无文件落地木马特征): $exe | $cmd"; flagged=1
        elif [[ "$path" =~ ^/(tmp|var/tmp|dev/shm|run/shm)(/|$) ]]; then
            log_high "PID $pid 的可执行文件位于临时目录: $exe | $cmd"; flagged=1
        elif [[ "$path" =~ ^/(root|home/[^/]+)/\.[^/]+/ ]] && ! [[ "$path" =~ $EXE_ALLOW_REGEX ]]; then
            log_warn "PID $pid 从用户隐藏目录运行: $exe | $cmd"; flagged=1
        fi

        if [[ "$exe" == *" (deleted)" && $flagged -eq 0 ]]; then
            if [[ "$path" =~ ^/(usr|bin|sbin|lib|lib64|opt)/ && -e "$path" ]]; then
                upgraded+=("$pid:${path##*/}")    # 多半是升级后未重启, 不作为告警
            else
                log_high "PID $pid 运行的可执行文件已被删除: $exe | $cmd"; flagged=1
            fi
        fi

        if [[ "$cmd" == "["*"]"* ]]; then
            log_high "PID $pid 命令行伪装成内核线程 (${cmd}) 但有真实可执行文件: $exe"; flagged=1
        fi
        if [[ -n "$cmd" && "$cmd" =~ $MINER_REGEX ]]; then
            log_high "PID $pid 命令行匹配挖矿/僵尸网络特征: $cmd"; flagged=1
        fi
        if (( flagged )); then found=1; show_proc "$pid"; fi
    done
    (( found )) || log_ok "未发现位于临时目录/memfd/已删除/伪装内核线程/挖矿特征的进程"
    if (( ${#upgraded[@]} )); then
        log_info "以下进程仍在运行升级前的旧二进制 (已被新版本替换, 建议重启服务/系统): ${upgraded[*]:0:30}"
    fi

    echo
    log_info "持续高 CPU 占用进程 (阈值 ${CPU_THRESHOLD}%, ps 为生命周期平均值)"
    ps -eo pid=,user=,pcpu=,etime=,comm= --sort=-pcpu 2>/dev/null |
        awk -v t="$CPU_THRESHOLD" '$3+0>=t && $5 !~ /^(ps|awk|bash|sh|tee|head|sort|sed|tr|grep)$/ {print $1, $2, $3, $4, $5}' |
        head -10 |
        while read -r pid user cpu et comm; do
            log_warn "PID $pid ($comm, 用户 $user) CPU ${cpu}% 已运行 $et — 挖矿木马常见特征, 请确认是否为正常业务"
        done

    echo
    detect_hidden_pids
}

# 2 ---------------------------------------------------------
check_network() {
    section "2. 网络连接 & 监听端口"

    log_info "当前监听端口 (含进程)"
    if have ss; then
        ss -tulnp 2>/dev/null | safe
    elif have netstat; then
        netstat -tulnp 2>/dev/null | safe
    else
        log_info "未找到 ss/netstat, 使用 /proc/net 读取监听端口:"
        listen_ports | sort -un | tr '\n' ' '; echo
    fi

    echo
    log_info "高危服务是否对外暴露 (监听在非回环/非内网地址)"
    if have ss; then
        local proto addr port proc desc sev found=0
        local -A reported=()
        while read -r proto addr port proc; do
            [[ -z "${port:-}" ]] && continue
            case "$addr" in
                127.*|::1|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|fe80:*) continue ;;
            esac
            [[ -n "${reported[$proto:$port]:-}" ]] && continue
            if desc=$(risky_port_desc "$port"); then
                reported[$proto:$port]=1
                sev=${desc##*|}; desc=${desc%|*}
                found=1
                if [[ "$sev" == "HIGH" ]]; then
                    log_high "${desc} 端口 ${port}/${proto} 监听在 ${addr} (对外暴露) 进程: ${proc}"
                else
                    log_warn "${desc} 端口 ${port}/${proto} 监听在 ${addr} (对外暴露, 请确认有防火墙/认证) 进程: ${proc}"
                fi
            fi
        done < <(ss -tulnp 2>/dev/null | awk 'NR>1 {a=$5; p=a; sub(/.*:/,"",p); sub(/:[0-9]+$/,"",a); gsub(/\[|\]/,"",a); sub(/%.*/,"",a); print $1, a, p, ($7=="" ? "-" : $7)}')
        (( found )) || log_ok "未发现常见高危服务对外暴露"
    else
        log_info "缺少 ss, 跳过暴露检查"
    fi

    echo
    log_info "对比 ss 与 /proc/net/tcp 的监听端口 (检测 ss 被替换/端口被隐藏)"
    if have ss; then
        local missing p hit=0
        missing=$(comm -13 \
            <(ss -tln 2>/dev/null | awk 'NR>1{n=split($4,a,":"); print a[n]}' | sort -u) \
            <(proc_ports 0A /proc/net/tcp /proc/net/tcp6 | sort -u))
        for p in $missing; do
            log_high "/proc/net/tcp 显示端口 ${p} 处于监听, 但 ss 未列出 (ss 可能被替换, 或存在被隐藏的监听端口)"
            hit=1
        done
        (( hit )) || log_ok "ss 与 /proc/net/tcp 的监听端口一致"
    else
        log_info "缺少 ss, 跳过对比"
    fi

    echo
    log_info "本机主动发起的外联 — 按目的 IP 统计 TOP 15 (已排除入站连接与回环)"
    outbound_conns | awk '{print $2}' | sort | uniq -c | sort -rn | head -15

    echo
    log_info "防火墙状态"
    local fw=0 n
    if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then fw=1; log_ok "ufw 已启用"; fi
    if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then fw=1; log_ok "firewalld 运行中"; fi
    if have iptables; then
        n=$(iptables -S 2>/dev/null | grep -vc '^-P')
        (( n > 0 )) && { fw=1; log_info "iptables 规则数: $n"; }
        iptables -t nat -S 2>/dev/null | grep -E 'DNAT|REDIRECT' | head -10 | safe
    fi
    if have nft; then
        n=$(nft list ruleset 2>/dev/null | grep -cE '(accept|drop|reject|dnat|redirect)')
        (( n > 0 )) && { fw=1; log_info "nftables 规则条目数: $n"; }
    fi
    (( fw )) || log_info "[建议] 未检测到活动的防火墙规则, 建议用 ufw/firewalld 或云安全组限制入站"

    echo
    log_info "/etc/hosts 自定义条目 & DNS 配置"
    grep -Ev '^[[:space:]]*(#|$)' /etc/hosts 2>/dev/null | grep -Ev '^(127\.|::1|fe00::|ff0[0-9]::|ff02::)' | safe
    if grep -qiE 'clamav|rkhunter|chkrootkit|virustotal|abuseipdb|security\.(ubuntu|debian)\.org' /etc/hosts 2>/dev/null; then
        log_warn "/etc/hosts 中存在屏蔽/重定向安全软件更新或信誉站点的条目 (木马常用手法)"
    fi
    grep -E '^(nameserver|search|options)' /etc/resolv.conf 2>/dev/null | safe
}

# 3 ---------------------------------------------------------
check_cron() {
    section "3. 定时任务 & 启动项 & 登录脚本"
    local f user uid home shell n
    local -a cron_files=() startup_files=() units=() libunits=() rcfiles=()

    for f in /etc/crontab /etc/anacrontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* /var/spool/at/* /var/spool/cron/atjobs/*; do
        [[ -f "$f" ]] && cron_files+=("$f")
    done
    for f in /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* \
             /etc/rc.local /etc/rc.d/rc.local /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /etc/zsh/zshrc /etc/zsh/zshenv; do
        [[ -f "$f" ]] && startup_files+=("$f")
    done

    log_info "crontab 内容 (直接读取 /etc 与 spool 目录, 不依赖 crontab 命令; 已去除注释)"
    for f in "${cron_files[@]+"${cron_files[@]}"}"; do
        case "$f" in /var/spool/at/*|/var/spool/cron/atjobs/*) printf -- '--- %s (at 任务) ---\n' "$f"; continue ;; esac
        printf -- '--- %s ---\n' "$f"
        grep -Ev '^[[:space:]]*(#|$)' "$f" 2>/dev/null | safe
    done
    if have atq; then
        n=$(atq 2>/dev/null | wc -l)
        (( n > 0 )) && log_warn "存在 ${n} 个 at 一次性任务, 请核对 (atq)"
    fi

    echo
    log_info "cron.hourly/daily/weekly/monthly 脚本清单"
    ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null | safe

    echo
    log_info "扫描定时任务/启动脚本中的恶意命令特征 (非软件包文件完整扫描, 软件包自带文件只扫高危特征)"
    scan_files_auto "${cron_files[@]+"${cron_files[@]}"}" "${startup_files[@]+"${startup_files[@]}"}"
    flag_immutable "${cron_files[@]+"${cron_files[@]}"}"

    echo
    log_info "已启用的 systemd 服务 (人工核对是否有陌生服务名)"
    systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null | safe

    echo
    log_info "systemd timer (crontab 之外的另一种定时任务隐藏方式)"
    systemctl list-timers --all --no-pager 2>/dev/null | safe

    echo
    log_info "自定义 systemd 单元 (/etc/systemd/system 下的普通文件, 用户级单元, 以及系统目录中不属于任何软件包的单元)"
    for f in /etc/systemd/system/*.service /etc/systemd/system/*.timer; do
        [[ -f "$f" && ! -L "$f" ]] && units+=("$f")
    done
    while IFS=: read -r -u 3 user uid home shell; do
        for f in "$home"/.config/systemd/user/*.service "$home"/.config/systemd/user/*.timer; do
            [[ -f "$f" ]] && units+=("$f")
        done
    done 3< <(list_homes)
    local sd
    while IFS= read -r sd; do
        for f in "$sd"/*.service; do [[ -f "$f" ]] && libunits+=("$f"); done
    done < <(uniq_dirs /usr/lib/systemd/system /lib/systemd/system)
    if [[ "$PKG_FAMILY" != "none" ]] && (( ${#libunits[@]} )); then
        while IFS= read -r f; do
            [[ -n "$f" ]] && { log_warn "系统目录中的 systemd 单元不属于任何软件包: $f"; units+=("$f"); }
        done < <(unowned_files "${libunits[@]}")
    fi
    for f in "${units[@]+"${units[@]}"}"; do
        printf '  %s\n' "$f"
        scan_text_file "$f" full
    done

    echo
    log_info "各用户 shell 启动文件中的恶意命令特征"
    while IFS=: read -r -u 3 user uid home shell; do
        for n in .bashrc .bash_profile .bash_login .profile .bash_logout .zshrc .zprofile .zshenv; do
            [[ -f "$home/$n" ]] && rcfiles+=("$home/$n")
        done
    done 3< <(list_homes)
    for f in "${rcfiles[@]+"${rcfiles[@]}"}"; do scan_text_file "$f" full; done
}

# 4 ---------------------------------------------------------
check_users() {
    section "4. 用户账号 / SSH 密钥 / sudoers / sshd 配置"
    local user uid home shell line f

    log_info "可登录用户 (排除 nologin/false)"
    grep -Ev '/(nologin|false)$' /etc/passwd | safe

    echo
    log_info "UID=0 的账号 (正常应只有 root)"
    local root_accounts
    root_accounts="$(awk -F: '$3==0{print $1}' /etc/passwd)"
    echo "$root_accounts"
    if [[ "$(echo "$root_accounts" | wc -l)" -gt 1 ]]; then
        log_high "发现多个 UID=0 的账号 ($(echo "$root_accounts" | tr '\n' ' ')), 请确认是否为你本人添加"
    else
        log_ok "只有 root 一个 UID=0 账号"
    fi

    echo
    log_info "空密码账号 (/etc/shadow)"
    local empty
    empty="$(awk -F: '$2==""{print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')"
    if [[ -n "$empty" ]]; then log_high "以下账号密码为空: $empty"; else log_ok "没有空密码账号"; fi

    echo
    log_info "账号文件近 7 天变更"
    local changed
    changed="$(find /etc/passwd /etc/shadow /etc/group /etc/gshadow -mtime -7 2>/dev/null | tr '\n' ' ')"
    if [[ -n "$changed" ]]; then log_info "近 7 天被修改: $changed (若不是你操作的, 请核对新增账号)"; else log_ok "近 7 天无变更"; fi

    echo
    log_info "具备管理员权限的组成员"
    getent group sudo wheel admin 2>/dev/null | safe

    echo
    log_info "sudoers 有效配置 (已去除注释)"
    for f in /etc/sudoers /etc/sudoers.d/*; do
        [[ -f "$f" ]] || continue
        printf -- '--- %s ---\n' "$f"
        grep -Ev '^[[:space:]]*(#|$)' "$f" 2>/dev/null | safe
        while IFS= read -r line; do
            log_warn "$f 含 NOPASSWD (云镜像默认账号常见, 其余请核对): ${line:0:160}"
        done < <(grep -E 'NOPASSWD' "$f" 2>/dev/null | grep -Ev '^[[:space:]]*#')
    done
    flag_immutable /etc/sudoers /etc/passwd /etc/shadow

    echo
    log_info "各用户 authorized_keys (指纹 + 备注; 请核对每一条是否为你本人添加)"
    local akf perm
    while IFS=: read -r -u 3 user uid home shell; do
        for akf in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
            [[ -f "$akf" ]] || continue
            printf -- '--- %s (用户: %s) ---\n' "$akf" "$user"
            if have ssh-keygen; then
                ssh-keygen -lf "$akf" 2>/dev/null | safe
            else
                awk '!/^[[:space:]]*(#|$)/{print substr($0,1,80) "..."}' "$akf" | safe
            fi
            if grep -Eq '(^|[[:space:]])command=' "$akf" 2>/dev/null; then
                log_warn "$akf 含 command= 强制命令的密钥, 请核对 (可能是后门)"
            fi
            if [[ -n "$(find "$akf" -mtime -7 2>/dev/null)" ]]; then
                log_warn "$akf 近 7 天被修改过, 请核对新增密钥"
            fi
            if [[ "$uid" =~ ^[0-9]+$ ]] && (( uid != 0 && uid < 1000 )); then
                log_warn "系统账号 ${user}(uid=${uid}) 配置了 SSH 密钥: $akf"
            fi
            perm=$(stat -c %a "$akf" 2>/dev/null || echo 600)
            if (( 8#$perm & 8#022 )); then
                log_warn "$akf 权限过宽 ($perm), 其他用户可修改"
            fi
            flag_immutable "$akf"
        done
    done 3< <(list_homes)

    echo
    log_info "sshd 有效配置"
    local cfg=""
    cfg="$(sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|permitemptypasswords|authorizedkeysfile|authorizedkeyscommand|pubkeyauthentication|port|allowusers) ' || true)"
    if [[ -z "$cfg" ]]; then
        cfg="$(grep -hEi '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|AuthorizedKeysFile|AuthorizedKeysCommand|PubkeyAuthentication|Port|AllowUsers)[[:space:]]' \
            /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{k=tolower($1); $1=""; sub(/^ /,""); print k, $0}' || true)"
    fi
    if [[ -z "$cfg" ]]; then
        log_info "未能读取 sshd 配置 (可能未安装 openssh-server)"
    else
        printf '%s\n' "$cfg" | safe
        cfg_get() { printf '%s\n' "$cfg" | awk -v k="$1" '$1==k{$1=""; sub(/^ /,""); print; exit}'; }
        local prl pa pe akfile akcmd
        prl=$(cfg_get permitrootlogin); pa=$(cfg_get passwordauthentication); pe=$(cfg_get permitemptypasswords)
        akfile=$(cfg_get authorizedkeysfile); akcmd=$(cfg_get authorizedkeyscommand)
        [[ "$pe" == "yes" ]] && log_high "sshd 允许空密码登录 (PermitEmptyPasswords yes)"
        if [[ "$prl" == "yes" && "$pa" == "yes" ]]; then
            log_warn "sshd 允许 root 使用密码直接登录 (PermitRootLogin yes + PasswordAuthentication yes), 极易被爆破"
        elif [[ "$pa" == "yes" ]]; then
            log_info "[建议] 已开启 SSH 密码登录, 建议改为仅密钥登录 (PasswordAuthentication no)"
        fi
        if [[ -n "$akfile" && ! "$akfile" =~ ^\.ssh/authorized_keys2?( \.ssh/authorized_keys2?)?$ && "$akfile" != "none" ]]; then
            log_warn "sshd 的 AuthorizedKeysFile 被改为非默认值: $akfile (后门常用手法)"
        fi
        if [[ -n "$akcmd" && "$akcmd" != "none" ]]; then
            log_warn "sshd 配置了 AuthorizedKeysCommand: $akcmd, 请核对"
        fi
    fi
    if have systemctl && ! systemctl is-active --quiet fail2ban 2>/dev/null; then
        log_info "[建议] 未检测到运行中的 fail2ban, 建议安装以自动封禁 SSH 爆破来源"
    fi
}

# 5 ---------------------------------------------------------
check_hidden() {
    section "5. 可疑目录扫描 (/tmp /var/tmp /dev/shm /dev)"
    local dir f magic kind base n
    for dir in /tmp /var/tmp /dev/shm; do
        [[ -d "$dir" ]] || continue
        log_info "扫描 ${dir} (深度 ≤5, 最多检查 5000 个文件): ELF / 脚本 / 可执行位文件"
        n=0
        while IFS= read -r -d '' f; do
            if (( n++ >= 5000 )); then log_info "文件过多, 仅检查前 5000 个"; break; fi
            kind=""; magic=""
            LC_ALL=C IFS= read -r -N 4 magic < "$f" 2>/dev/null
            if [[ "$magic" == $'\x7f'ELF ]]; then kind="ELF 二进制"
            elif [[ "${magic:0:2}" == '#!' ]]; then kind="脚本(shebang)"
            elif [[ -x "$f" ]]; then kind="可执行位文件"
            fi
            if [[ -n "$kind" ]]; then
                if [[ "$kind" == "ELF 二进制" ]]; then log_high "${dir} 下存在 ${kind}: $f"
                else log_warn "${dir} 下存在 ${kind}: $f"; fi
                ls -la -- "$f" 2>/dev/null | safe
                have sha256sum && sha256sum -- "$f" 2>/dev/null | safe
            fi
        done < <(find "$dir" -xdev -maxdepth 5 -type f -print0 2>/dev/null)

        while IFS= read -r -d '' f; do
            base=${f##*/}
            case "$base" in
                .X11-unix|.ICE-unix|.font-unix|.XIM-unix|.Test-unix|.X[0-9]*-lock|.s.PGSQL.*|.vscode*|.org.chromium*) continue ;;
            esac
            log_warn "${dir} 下存在隐藏文件/目录: $f"
        done < <(find "$dir" -xdev -mindepth 1 -maxdepth 2 -name '.*' -print0 2>/dev/null)
    done

    echo
    log_info "/dev 下的普通文件 (rootkit 常把文件藏在 /dev)"
    local devfound=0
    while IFS= read -r f; do
        log_warn "/dev 下存在普通文件: $f"; devfound=1
    done < <(find /dev -xdev -type f -not -path '/dev/.udev/*' -not -path '/dev/.lxc/*' -not -path '/dev/.lxd-mounts/*' 2>/dev/null | head -20)
    (( devfound )) || log_ok "/dev 下没有普通文件"
}

# 6 ---------------------------------------------------------
verify_packages() {
    log_info "关键软件包文件完整性校验 (对比包管理器记录的校验和)"
    local p flags path base out
    local -a pk=() cand=()
    local runner=()
    have timeout && runner=(timeout 600)

    case "$PKG_FAMILY" in
        deb)
            cand=(coreutils procps net-tools iproute2 openssh-server openssh-client util-linux login passwd bash findutils grep sed gawk mawk cron systemd sudo libc-bin libc6 e2fsprogs lsof)
            for p in "${cand[@]}"; do dpkg -s "$p" >/dev/null 2>&1 && pk+=("$p"); done
            out=$("${runner[@]+"${runner[@]}"}" dpkg -V "${pk[@]}" 2>/dev/null | awk 'NF>=2 { if ($2=="c") next; print $1, $NF }')
            ;;
        rpm)
            cand=(coreutils procps-ng net-tools iproute openssh-server openssh-clients util-linux shadow-utils bash findutils grep sed gawk e2fsprogs cronie systemd sudo glibc lsof)
            for p in "${cand[@]}"; do rpm -q "$p" >/dev/null 2>&1 && pk+=("$p"); done
            out=$("${runner[@]+"${runner[@]}"}" rpm -V "${pk[@]}" 2>/dev/null | awk 'NF>=2 { if ($2=="c"||$2=="d"||$2=="g"||$2=="l"||$2=="r") next; print $1, $NF }')
            ;;
        apk)
            out=$(apk verify 2>&1 | head -30 | sed 's/^/APK /')
            ;;
        *)
            log_info "未识别包管理器, 跳过包校验"
            return 0
            ;;
    esac

    local found=0
    while read -r flags path; do
        [[ -z "${path:-}" ]] && continue
        if [[ "$flags" != *5* && "$flags" != "missing" && "$flags" != "APK" ]]; then continue; fi
        base=${path##*/}
        found=1
        case "$base" in
            ps|ss|netstat|ls|top|lsof|sshd|ssh|login|find|ifconfig|passwd|sudo|crontab|su|bash|sh|systemctl|cat|ip)
                log_high "核心系统文件与软件包记录不一致 (${flags}): $path (可能被木马替换)" ;;
            *)
                log_warn "软件包文件与记录不一致 (${flags}): $path" ;;
        esac
    done <<<"$out"
    (( found )) || log_ok "已校验的关键软件包文件均与包管理器记录一致"
}

check_suid() {
    log_info "SUID/SGID 文件清单与基线对比"
    local cur="${TMP_DIR}/suid.cur" base="${STATE_DIR}/suid-baseline.txt" mp f n
    : > "$cur"
    local mounts
    mounts=$(awk '$3 ~ /^(ext[234]|xfs|btrfs|f2fs|zfs|reiserfs|jfs|overlay)$/ {print $2}' /proc/mounts | sort -u)
    [[ -z "$mounts" ]] && mounts="/"
    while read -r mp; do
        find "$mp" -xdev \( -path /proc -o -path /sys \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null >> "$cur"
    done <<<"$mounts"
    sort -u "$cur" -o "$cur"
    n=$(wc -l < "$cur")
    log_info "当前共 ${n//[[:space:]]/} 个 SUID/SGID 文件"

    while IFS= read -r f; do
        case "$f" in
            /tmp/*|/var/tmp/*|/dev/shm/*|/var/www/*|/run/*) log_high "SUID/SGID 文件位于异常目录: $f" ;;
            /home/*|/root/*|/opt/*|/srv/*|/mnt/*)           log_warn "SUID/SGID 文件位于非标准目录: $f" ;;
        esac
        case "${f##*/}" in
            bash|sh|dash|zsh|ksh|python*|perl*|ruby*|node|php*|lua*|find|vim|vi|nano|nmap|cp|mv|awk|gawk|less|more|env|tar|rsync|socat|nc|ncat|busybox|tclsh|wget|curl)
                log_high "危险程序被设置 SUID/SGID (提权后门常见手法): $f" ;;
        esac
    done < "$cur"

    if [[ ! -f "$base" ]]; then
        cp "$cur" "$base"
        log_info "首次运行: 已保存 SUID/SGID 基线 ($base), 之后新增的文件会被标记"
    else
        local newf=0
        while IFS= read -r f; do
            [[ -n "$f" ]] && { log_warn "相对基线新增的 SUID/SGID 文件: $f"; newf=1; }
        done < <(comm -13 "$base" "$cur")
        (( newf )) && log_info "确认新增文件无误后, 删除 ${base} 即可在下次运行时重建基线"
        (( newf )) || log_ok "SUID/SGID 文件与基线一致"
    fi
}

check_kernel_modules() {
    log_info "内核模块一致性 (检测从模块链表中摘除自身的 LKM rootkit)"
    if [[ ! -d /sys/module || ! -r /proc/modules ]]; then
        log_info "当前环境不支持 (容器或无内核模块接口), 跳过"
        return 0
    fi
    local m _rest d name state hit=0 t
    local -A loaded=()
    while read -r m _rest; do loaded[$m]=1; done < /proc/modules
    for d in /sys/module/*; do
        [[ -e "$d/initstate" ]] || continue
        name=${d##*/}
        [[ -n "${loaded[$name]:-}" ]] && continue
        state=$(<"$d/initstate")
        [[ "$state" == "live" ]] || continue
        log_high "内核模块 ${name} 存在于 /sys/module 但不在 /proc/modules (疑似隐藏的内核 rootkit)"
        hit=1
    done
    (( hit )) || log_ok "已加载模块与 /sys/module 一致"
    t=$(<"/proc/sys/kernel/tainted" 2>/dev/null || echo "?")
    log_info "内核 tainted 值: ${t} (0=未污染; 4096=外部模块; 8192=未签名模块; 如不是你加载的请核对 lsmod)"
}

check_odd_names() {
    log_info "异常文件名 (以 '.. ' '...' '. ' 开头, 常用于藏匿后门)"
    local f found=0
    local -a dirs=()
    mapfile -t dirs < <(uniq_dirs /usr /bin /sbin /lib /lib64 /etc /var /opt /root /home)
    (( ${#dirs[@]} )) || return 0
    while IFS= read -r f; do
        log_warn "异常文件名: $f"; found=1
    done < <(find "${dirs[@]}" -xdev \( -name '.. *' -o -name '...*' -o -name '. *' -o -name '.. ' -o -name '. ' \) 2>/dev/null | head -20)
    (( found )) || log_ok "未发现异常文件名"
}

check_integrity() {
    section "6. 系统完整性 (包校验 / SUID 基线 / 内核模块 / 异常文件名)"
    verify_packages

    echo
    log_info "近 7 天内被修改的系统二进制 (仅供参考, 请对照你的更新/操作记录)"
    local -a bindirs=()
    mapfile -t bindirs < <(uniq_dirs /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin)
    if (( ${#bindirs[@]} )); then
        find "${bindirs[@]}" -xdev -type f -mtime -7 2>/dev/null | sort -u | head -30 | safe
    fi

    echo
    check_suid
    echo
    check_kernel_modules
    echo
    check_odd_names
}

# 7 ---------------------------------------------------------
check_preload() {
    section "7. LD_PRELOAD / 动态库劫持检测 (常见 rootkit 隐藏手法)"
    local line f d val pid comm

    if [[ -e /etc/ld.so.preload ]]; then
        if grep -Eqv '^[[:space:]]*(#|$)' /etc/ld.so.preload 2>/dev/null; then
            log_high "/etc/ld.so.preload 存在且非空 (正常系统不应有, 除非你自己配置过):"
            grep -Ev '^[[:space:]]*(#|$)' /etc/ld.so.preload | safe
        else
            log_warn "/etc/ld.so.preload 文件存在但内容为空/仅注释"
        fi
        flag_immutable /etc/ld.so.preload
    else
        log_ok "/etc/ld.so.preload 不存在"
    fi

    echo
    log_info "所有运行中进程的环境变量中是否带有 LD_PRELOAD / LD_AUDIT"
    local found=0
    for d in /proc/[0-9]*; do
        pid=${d#/proc/}
        [[ "$pid" == "$$" || "$pid" == "$BASHPID" ]] && continue
        [[ -r "$d/environ" ]] || continue
        val=$(tr '\0' '\n' < "$d/environ" 2>/dev/null | grep -m1 -E '^LD_(PRELOAD|AUDIT)=')
        [[ -z "$val" ]] && continue
        comm=$(tr -d '\n' < "$d/comm" 2>/dev/null)
        found=1
        if [[ "$val" =~ =(/tmp|/var/tmp|/dev/shm|/home|/root) ]]; then
            log_high "PID $pid ($comm) 环境变量: $val (指向可写目录)"
        else
            log_warn "PID $pid ($comm) 环境变量: $val (jemalloc/tcmalloc/proxychains 等可能是正常用途)"
        fi
    done
    (( found )) || log_ok "没有进程设置 LD_PRELOAD / LD_AUDIT"

    echo
    log_info "/etc/ld.so.conf(.d) 中是否有指向可写目录的库路径"
    found=0
    while IFS= read -r line; do
        log_warn "动态库搜索路径指向可写目录: $line"; found=1
    done < <(cat /etc/ld.so.conf /etc/ld.so.conf.d/*.conf 2>/dev/null | grep -Ev '^[[:space:]]*(#|include|$)' | grep -E '^/(tmp|var/tmp|dev/shm|home|root)(/|$)')
    (( found )) || log_ok "ld.so.conf 未发现异常路径"

    echo
    log_info "检查 shell 启动文件中是否被注入 LD_PRELOAD / LD_AUDIT / ld.so.preload"
    local -a rcs=(/etc/profile /etc/bash.bashrc /etc/environment /etc/zsh/zshenv /etc/zsh/zshrc)
    local user uid home shell n
    for f in /etc/profile.d/*; do [[ -f "$f" ]] && rcs+=("$f"); done
    while IFS=: read -r -u 3 user uid home shell; do
        for n in .bashrc .bash_profile .bash_login .profile .zshrc .zprofile .zshenv; do
            [[ -f "$home/$n" ]] && rcs+=("$home/$n")
        done
    done 3< <(list_homes)
    found=0
    for f in "${rcs[@]}"; do
        [[ -f "$f" ]] || continue
        while IFS= read -r line; do
            log_high "$f 中存在预加载注入: ${line:0:160}"; found=1
        done < <(grep -nE 'LD_PRELOAD|LD_AUDIT|ld\.so\.preload' "$f" 2>/dev/null | grep -v '^[0-9]*:[[:space:]]*#')
    done
    (( found )) || log_ok "未在 shell 启动文件中发现预加载注入"

    echo
    log_info "ldd /bin/ls 加载的动态库是否都来自标准目录 (预加载型 rootkit 会混入额外的库)"
    found=0
    if have ldd; then
        while IFS= read -r line; do
            log_high "/bin/ls 加载了非标准目录的动态库: $line"; found=1
        done < <(ldd /bin/ls 2>/dev/null | awk '$3 ~ /^\//{print $3}' | grep -Ev '^/(usr/)?(lib|lib64|lib32|libexec)/|^/usr/local/lib/|^/nix/store/')
        (( found )) || log_ok "ldd /bin/ls 的动态库均来自标准目录"
    fi

    echo
    log_info "当前 shell 进程已映射的非标准目录动态库"
    found=0
    while IFS= read -r line; do
        log_warn "当前进程映射了非标准目录的动态库: $line"; found=1
    done < <(awk '$6 ~ /\.so/ {print $6}' "/proc/$$/maps" 2>/dev/null | sort -u | grep -Ev '^/(usr/)?(lib|lib64|lib32|libexec)/|^/usr/local/lib/|^/nix/store/')
    (( found )) || log_ok "未发现异常映射库"
}

# 8 ---------------------------------------------------------
ssh_log_stream() {
    local f
    local -a files=()
    for f in "$LOG_DIR"/auth.log "$LOG_DIR"/auth.log.* "$LOG_DIR"/secure "$LOG_DIR"/secure-* "$LOG_DIR"/secure.*; do
        [[ -f "$f" ]] && files+=("$f")
    done
    if (( ${#files[@]} )); then
        # 按修改时间从旧到新, 保证时间顺序
        ls -1tr -- "${files[@]}" 2>/dev/null | while IFS= read -r f; do zcat -f -- "$f" 2>/dev/null; done
    elif have journalctl; then
        journalctl -u ssh -u sshd --since "-14 days" --no-pager -o short-iso 2>/dev/null
    fi
}

check_auth_gaps() {
    local f s="${TMP_DIR}/authall" hours="${TMP_DIR}/hours"
    local -a files=()
    for f in "$LOG_DIR"/auth.log "$LOG_DIR"/auth.log.*; do [[ -f "$f" ]] && files+=("$f"); done
    (( ${#files[@]} )) || return 0
    date --version 2>/dev/null | grep -q GNU || { log_info "非 GNU date, 跳过日志断档检测"; return 0; }
    ls -1tr -- "${files[@]}" | while IFS= read -r f; do zcat -f -- "$f" 2>/dev/null; done > "$s"
    if ! head -1 "$s" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T'; then
        log_info "auth.log 时间戳非 ISO 格式, 跳过日志断档检测"
        return 0
    fi
    cut -c1-13 "$s" | grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}$' | uniq |
        sed 's/T/ /; s/$/:00:00/' | date -f - +%s 2>/dev/null > "$hours"
    local a b gap=0
    while read -r a b; do
        log_warn "auth 日志在 $(date -d "@$a" '+%F %H:%M') 与 $(date -d "@$b" '+%F %H:%M') 之间无任何记录 (≥${LOG_GAP_HOURS} 小时), 可能被清理/篡改"
        gap=1
    done < <(awk -v g=$(( LOG_GAP_HOURS * 3600 )) 'NR>1 && $1-p>g {print p, $1} {p=$1}' "$hours")
    (( gap )) || log_ok "auth.log 没有明显的时间断档"
}

analyze_ssh_log() {
    local stream="$1"
    local acc="${TMP_DIR}/accepted.tsv" fail="${TMP_DIR}/failed_ips.txt" cur="${TMP_DIR}/cur_ips.txt"
    local known="${STATE_DIR}/known-login-ips.txt" cnt ip n

    log_info "最近 30 条成功登录"
    grep -a 'Accepted' "$stream" | tail -30 | cut -c1-200 | safe

    awk '/sshd\[[0-9]+\]: Accepted /{m="";u="";ip="";for(i=1;i<=NF;i++){if($i=="Accepted")m=$(i+1);else if($i=="for")u=$(i+1);else if($i=="from")ip=$(i+1)} print m, u, ip}' "$stream" > "$acc"
    echo
    log_info "成功登录统计 (次数 方式 用户 来源IP, TOP 20)"
    sort "$acc" | uniq -c | sort -rn | head -20 | safe

    n=$(awk '$1=="password" && $2=="root"' "$acc" | wc -l)
    n=${n//[[:space:]]/}
    (( n > 0 )) && log_warn "root 通过密码方式成功登录 ${n} 次 (建议禁用 root 密码登录并改用密钥)"

    # 爆破统计
    awk '/sshd\[[0-9]+\]: (Failed password|Invalid user|Failed none|Failed publickey)/{for(i=1;i<=NF;i++) if($i=="from"){print $(i+1);break}}' "$stream" |
        sort | uniq -c | sort -rn > "$fail"
    echo
    log_info "登录失败来源 IP TOP 10 (次数 IP)"
    head -10 "$fail" | safe
    while read -r cnt ip; do
        [[ -z "${ip:-}" ]] && continue
        (( cnt >= BRUTE_FAIL_THRESHOLD )) || continue
        if awk -v ip="$ip" '$3==ip{f=1} END{exit !f}' "$acc"; then
            log_high "IP ${ip} 先后有 ${cnt} 次登录失败与成功登录记录 (疑似 SSH 爆破成功)"
        fi
    done < "$fail"

    # 新来源 IP (相对上次运行)
    awk 'NF>=3 && $3!=""{print $3}' "$acc" | sort -u > "$cur"
    if [[ ! -f "$known" ]]; then
        cp "$cur" "$known"
        log_info "首次运行: 已记录 $(wc -l < "$cur" | tr -d ' ') 个成功登录来源 IP 作为基线 ($known)"
    else
        local newf=0
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            log_warn "出现此前未记录的成功登录来源 IP: ${ip} (用户: $(awk -v ip="$ip" '$3==ip{print $2}' "$acc" | sort -u | tr '\n' ',' ))"
            newf=1
        done < <(comm -13 <(sort -u "$known") "$cur")
        sort -u "$known" "$cur" -o "$known"
        (( newf )) || log_ok "没有新的成功登录来源 IP"
    fi
}

check_logs() {
    section "8. 登录日志 & 日志完整性 & 历史命令"
    local f user uid home shell h line

    log_info "最近成功登录 (last)"
    last -a 2>/dev/null | head -30 | safe
    echo
    log_info "最近登录失败 (lastb 前 20 条)"
    lastb 2>/dev/null | head -20 | safe

    echo
    local stream="${TMP_DIR}/sshlog"
    ssh_log_stream > "$stream" 2>/dev/null
    if [[ -s "$stream" ]]; then
        analyze_ssh_log "$stream"
    else
        log_info "未找到 auth.log / secure / journald 中的 sshd 日志"
    fi

    echo
    log_info "日志文件完整性 (被清空的日志大小为 0)"
    for f in auth.log secure syslog messages kern.log wtmp lastlog; do
        if [[ -e "$LOG_DIR/$f" && ! -s "$LOG_DIR/$f" ]]; then
            log_warn "日志文件为空 (可能被清空): $LOG_DIR/$f"
        fi
    done
    ls -la "$LOG_DIR"/*.log 2>/dev/null | sort -k5 -n | head -10 | safe
    check_auth_gaps

    echo
    log_info "各用户 shell 历史中的可疑命令 (每个文件最多 5 条)"
    while IFS=: read -r -u 3 user uid home shell; do
        for h in "$home/.bash_history" "$home/.zsh_history"; do
            if [[ -L "$h" ]]; then
                [[ "$(readlink "$h")" == "/dev/null" ]] && log_warn "$h 链接到 /dev/null (历史记录被刻意关闭)"
            elif [[ -f "$h" ]]; then
                grep -anE "$HIST_REGEX" "$h" 2>/dev/null | tail -5 | cut -c1-200 |
                    while IFS= read -r line; do log_warn "$h: $line"; done
            fi
        done
    done 3< <(list_homes)
}

# 9 ---------------------------------------------------------
check_rootkit() {
    section "9. rkhunter / chkrootkit 扫描"
    local out="${TMP_DIR}/rk.out" line

    have rkhunter || ask_install rkhunter || true
    if have rkhunter; then
        local rklog="${REPORT_DIR}/rkhunter-${TS}.log"
        log_info "运行 rkhunter (完整日志: ${rklog})"
        rkhunter --update --nocolors >/dev/null 2>&1 || true
        rkhunter --check --sk --nocolors --rwo --logfile "$rklog" > "$out" 2>&1
        if grep -aq '^Warning' "$out"; then
            while IFS= read -r line; do log_warn "rkhunter: ${line:0:200}"; done < <(grep -a '^Warning' "$out" | head -50)
        else
            log_ok "rkhunter 未报告警告"
        fi
        grep -av '^Warning' "$out" | head -20 | safe
        log_info "提示: rkhunter 存在已知误报 (如被替换为脚本的 egrep/lwp-request、/dev 下的文件), 请结合日志判断"
    fi

    echo
    have chkrootkit || ask_install chkrootkit || true
    if have chkrootkit; then
        log_info "运行 chkrootkit -q (只输出可疑项)"
        chkrootkit -q > "$out" 2>&1
        if [[ -s "$out" ]]; then
            while IFS= read -r line; do log_warn "chkrootkit: ${line:0:200}"; done < <(head -50 "$out")
            log_info "提示: chkrootkit 的 bindshell 等检测对 465/587 等邮件端口存在已知误报"
        else
            log_ok "chkrootkit 未报告可疑项"
        fi
    fi
}

# 10 --------------------------------------------------------
check_clamav() {
    section "10. ClamAV 病毒扫描 (耗时较长)"
    local avail_mb p out="${TMP_DIR}/clam.out" line
    local -a paths=() excl=() runner=()

    if ! have clamscan; then
        ask_install clamav || { log_info "跳过 ClamAV 扫描"; return 0; }
        have clamscan || { log_err "clamscan 仍不可用, 跳过"; return 0; }
    fi

    if have freshclam; then
        log_info "更新病毒库..."
        if ! freshclam >"${TMP_DIR}/fresh.out" 2>&1; then
            log_info "freshclam 更新失败 (常见原因: clamav-freshclam 守护进程已占用锁, 将使用现有病毒库)"
            tail -3 "${TMP_DIR}/fresh.out" | safe
        fi
    fi
    if ! compgen -G '/var/lib/clamav/*.c[lv]d' >/dev/null; then
        log_err "未找到病毒库 (/var/lib/clamav/*.cvd|cld), 无法扫描"
        return 0
    fi

    avail_mb=$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo 2>/dev/null)
    if (( ${avail_mb:-0} > 0 && ${avail_mb:-0} < 1500 )); then
        log_info "可用内存仅 ${avail_mb} MB, ClamAV 加载病毒库约需 1.2GB+, 可能被 OOM 杀掉"
        confirm "仍要继续扫描吗?" || { log_info "已跳过 ClamAV 扫描"; return 0; }
    fi

    if (( OPT_FULL_SCAN )) || { (( ! OPT_YES )) && confirm "是否扫描全盘 (较慢)? 选 N 将只扫描常见目录"; }; then
        paths=(/)
    else
        for p in /tmp /var/tmp /dev/shm /home /root /var/www /opt /usr/local; do [[ -d "$p" ]] && paths+=("$p"); done
    fi
    for p in /sys /proc /dev /run /snap /mnt /media /var/lib/docker /var/lib/containers /var/lib/clamav "$REPORT_DIR" "$STATE_DIR"; do
        excl+=("--exclude-dir=^${p}")
    done
    have nice && runner+=(nice -n 10)
    have ionice && runner+=(ionice -c3)

    log_info "开始扫描: ${paths[*]}"
    "${runner[@]+"${runner[@]}"}" clamscan -r -i --max-filesize=100M --max-scansize=300M \
        --log="${REPORT_DIR}/clamav-${TS}.log" "${excl[@]}" "${paths[@]}" > "$out" 2>&1
    if grep -aq ' FOUND$' "$out"; then
        while IFS= read -r line; do log_high "ClamAV 命中: ${line:0:240}"; done < <(grep -a ' FOUND$' "$out" | head -100)
    else
        log_ok "ClamAV 未发现感染文件"
    fi
    grep -a -A12 -- '----------- SCAN SUMMARY' "$out" | safe
}

# 11 --------------------------------------------------------
check_botnet() {
    section "11. 肉鸡 / DDoS 参与 / C2 / 挖矿连接检测"
    local n name flags hit=0 oc="${TMP_DIR}/outbound.txt" line

    log_info "网卡是否处于混杂模式 (嗅探迹象)"
    for n in /sys/class/net/*; do
        name=${n##*/}
        case "$name" in lo|veth*|vnet*|tap*|virbr*|docker*|br-*|cni*|flannel*|cali*|fw*) continue ;; esac
        [[ -r "$n/flags" ]] || continue
        flags=$(<"$n/flags")
        if (( flags & 0x100 )); then
            log_warn "网卡 ${name} 处于混杂(PROMISC)模式 (可能在嗅探流量, 也可能是 tcpdump 等抓包工具)"
            hit=1
        fi
    done
    (( hit )) || log_ok "未发现网卡处于混杂模式"

    outbound_conns > "$oc"
    have ss || log_info "缺少 ss, 已回退到 /proc/net/tcp (仅 IPv4, 无进程信息)"

    echo
    log_info "本机主动发起的连接 — 按 目的IP:端口 统计 TOP 20 (已排除入站连接)"
    awk '{print $2":"$3}' "$oc" | sort | uniq -c | sort -rn | head -20

    echo
    local dest_count
    dest_count=$(awk '{print $2}' "$oc" | sort -u | wc -l)
    dest_count=${dest_count//[[:space:]]/}
    log_info "本机主动外联的不同目的 IP 数量: ${dest_count} (阈值 ${DEST_IP_THRESHOLD})"
    if (( dest_count > DEST_IP_THRESHOLD )); then
        log_warn "主动外联的不同目的 IP 数量偏多 (${dest_count}), 请核对是否为正常业务(爬虫/CDN 回源/API 调用)"
    else
        log_ok "目的 IP 数量在正常范围"
    fi

    echo
    log_info "是否存在到常见 C2/后门端口 (${C2_PORTS}) 及矿池端口 (${MINER_PORTS}) 的连接"
    hit=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        log_high "出站连接到常见 C2/后门端口: $line"; hit=1
    done < <(awk -v ports=" ${C2_PORTS} " 'index(ports, " " $3 " ") {print $2":"$3, $4}' "$oc")
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        log_warn "出站连接到常见矿池端口: $line"; hit=1
    done < <(awk -v ports=" ${MINER_PORTS} " 'index(ports, " " $3 " ") {print $2":"$3, $4}' "$oc")
    (( hit )) || log_ok "未发现到常见 C2/矿池端口的连接"

    echo
    log_info "对外扫描/爆破/垃圾邮件特征 (短时间内向大量不同 IP 的同一服务端口发起连接, 阈值 ${FANOUT_THRESHOLD})"
    hit=0
    local p c
    while read -r p c; do
        [[ -z "${c:-}" ]] && continue
        if (( c >= FANOUT_THRESHOLD )); then
            log_warn "同时向 ${c} 个不同 IP 的 ${p} 端口发起连接 (SSH/Telnet 爆破、SMTP 垃圾邮件、RDP/SMB 扫描等特征)"
            hit=1
        fi
    done < <(awk '$3==22||$3==23||$3==25||$3==465||$3==587||$3==3389||$3==445||$3==6379||$3==2375 {print $3, $2}' "$oc" | sort -u | awk '{c[$1]++} END{for(p in c) print p, c[p]}')
    (( hit )) || log_ok "未发现扇出式扫描特征"

    echo
    log_info "SYN_SENT 半连接数量 (SYN Flood/扫描: 本机对外发起大量未完成的连接)"
    local syn
    syn=$(awk 'FNR>1 && $4=="02"' /proc/net/tcp /proc/net/tcp6 2>/dev/null | wc -l)
    syn=${syn//[[:space:]]/}
    echo "当前 SYN_SENT 数量: ${syn}"
    if (( syn > SYN_SENT_THRESHOLD )); then
        log_warn "SYN_SENT 数量异常偏高 (${syn}), 疑似正在对外发起大量连接尝试 (扫描/SYN flood)"
    else
        log_ok "SYN_SENT 数量正常"
    fi

    echo
    if (( SAMPLE_SECONDS > 0 )); then
        log_info "网卡出口流量采样 (观察 ${SAMPLE_SECONDS} 秒; 高流量的正常业务请自行排除)"
        local iface c1 c2 rx1 rxp1 tx1 txp1 rx2 rxp2 tx2 txp2 u1 u2
        iface="$(default_iface)"
        if [[ -n "$iface" ]]; then
            c1=$(net_counters "$iface"); u1=$(udp_out)
            sleep "$SAMPLE_SECONDS"
            c2=$(net_counters "$iface"); u2=$(udp_out)
            read -r rx1 rxp1 tx1 txp1 <<<"${c1:-0 0 0 0}"
            read -r rx2 rxp2 tx2 txp2 <<<"${c2:-0 0 0 0}"
            local rx_kbps tx_kbps tx_pps avg=0 udp_pps
            rx_kbps=$(( (rx2 - rx1) / SAMPLE_SECONDS / 1024 ))
            tx_kbps=$(( (tx2 - tx1) / SAMPLE_SECONDS / 1024 ))
            tx_pps=$(( (txp2 - txp1) / SAMPLE_SECONDS ))
            (( txp2 > txp1 )) && avg=$(( (tx2 - tx1) / (txp2 - txp1) ))
            udp_pps=$(( (${u2:-0} - ${u1:-0}) / SAMPLE_SECONDS ))
            echo "网卡: ${iface}  入站: ${rx_kbps} KB/s  出站: ${tx_kbps} KB/s  出站包速率: ${tx_pps} pps  平均包长: ${avg} B  UDP 发包: ${udp_pps} pps"
            if (( tx_pps >= 5000 && avg > 0 && avg < 120 )); then
                log_high "出站大量小包 (${tx_pps} pps, 平均 ${avg} B), 符合 DDoS 泛洪特征"
            fi
            (( tx_kbps > TX_KBPS_THRESHOLD )) && log_warn "出站带宽较高 (${tx_kbps} KB/s), 若没有在主动分发大文件, 请留意是否为 DDoS 参与或数据外传"
            (( tx_pps > TX_PPS_THRESHOLD )) && log_warn "出站包速率较高 (${tx_pps} pps)"
            (( udp_pps > UDP_PPS_THRESHOLD )) && log_warn "UDP 发包速率较高 (${udp_pps} pps), DNS/NTP 放大类攻击常见"
        else
            log_info "未能识别默认出口网卡, 跳过流量采样"
        fi
    else
        log_info "SAMPLE_SECONDS=0, 跳过流量采样"
    fi

    echo
    log_info "本机 IP 信誉核对"
    if (( OPT_ONLINE )) && have curl; then
        local pub_ip
        pub_ip="$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || curl -s --max-time 5 https://ifconfig.me 2>/dev/null || true)"
        if [[ "$pub_ip" =~ ^[0-9a-fA-F:.]+$ ]]; then
            echo "当前出口公网 IP: ${pub_ip}"
            echo "可手动访问以下网站核对该 IP 是否已被标记为恶意/垃圾邮件/DDoS 来源:"
            echo "  https://www.abuseipdb.com/check/${pub_ip}"
            echo "  https://check.spamhaus.org/"
        else
            log_info "未能获取公网出口 IP (网络受限?), 可自行在浏览器查询"
        fi
    else
        log_info "默认不访问外网。加 --online 可获取本机公网 IP 并生成信誉查询链接"
    fi
}

# 12 --------------------------------------------------------
check_web() {
    section "12. Web 目录 webshell 特征"
    local r f line found=0
    local -a roots=() runner=()
    for r in /var/www /srv/www /srv/http /usr/share/nginx/html /home/*/public_html /home/*/www /opt/lampp/htdocs; do
        [[ -d "$r" ]] && roots+=("$r")
    done
    if (( ${#roots[@]} == 0 )); then
        log_info "未发现常见 Web 根目录, 跳过"
        return 0
    fi
    have timeout && runner=(timeout 180)
    log_info "扫描目录: ${roots[*]}"

    while IFS= read -r line; do
        log_warn "疑似 webshell: ${line:0:240}"; found=1
    done < <("${runner[@]+"${runner[@]}"}" grep -rInE -m1 "$WEBSHELL_REGEX" \
        --include='*.php' --include='*.phtml' --include='*.php[0-9]' --include='*.pht' \
        --include='*.jsp' --include='*.jspx' --include='*.asp' --include='*.aspx' --include='*.cgi' \
        "${roots[@]}" 2>/dev/null | head -50)

    while IFS= read -r f; do
        log_warn "上传目录中存在可执行脚本: $f"; found=1
    done < <(find "${roots[@]}" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php[0-9]' -o -iname '*.pht' -o -iname '*.jsp' \) \
        \( -ipath '*/uploads/*' -o -ipath '*/upload/*' -o -ipath '*/files/*' \) 2>/dev/null | head -30)
    (( found )) || log_ok "未发现 webshell 特征"

    echo
    log_info "近 7 天被修改的脚本文件 (最多 20 个, 仅供参考)"
    find "${roots[@]}" -type f \( -iname '*.php' -o -iname '*.jsp' \) -mtime -7 2>/dev/null | head -20 | safe
}

# ------------------------- 汇总 / 输出 -------------------------

json_escape() { local s="$1"; s=${s//\\/\\\\}; s=${s//\"/\\\"}; printf '%s' "$s"; }

write_json() {
    local first=1 sec sev msg
    {
        printf '{\n  "host": "%s",\n  "time": "%s",\n  "version": "%s",\n  "findings": [' \
            "$(json_escape "$(hostname 2>/dev/null)")" "$(date -Is 2>/dev/null || date)" "$VERSION"
        while IFS=$'\t' read -r sec sev msg; do
            (( first )) || printf ','
            first=0
            printf '\n    {"section": "%s", "severity": "%s", "message": "%s"}' \
                "$(json_escape "$sec")" "$sev" "$(json_escape "$msg")"
        done < "$FINDINGS_FILE"
        printf '\n  ]\n}\n'
    } > "$JSON_FILE"
}

count_findings() {   # 输出: high medium
    local h m
    h=$(awk -F'\t' '$2=="HIGH"' "$FINDINGS_FILE" 2>/dev/null | wc -l)
    m=$(awk -F'\t' '$2=="MEDIUM"' "$FINDINGS_FILE" 2>/dev/null | wc -l)
    echo "${h//[[:space:]]/} ${m//[[:space:]]/}"
}

print_banner() {
    local osname=""
    [[ -r /etc/os-release ]] && osname=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-}")
    printf '%bVPS 安全排查 v%s%b\n' "$C_BOLD" "$VERSION" "$C_RESET"
    echo "主机: $(hostname 2>/dev/null) | 系统: ${osname:-unknown} | 内核: $(uname -r) | 运行: $(uptime -p 2>/dev/null || uptime)"
    echo "时间: $(date '+%F %T %Z') | 报告: ${REPORT_FILE}"
    log_info "提示: 若主机已被入侵, ps/ss/ls 等系统命令可能已被替换, 结果仅供参考; 应急取证建议加 --no-install"
}

print_summary() {
    local high med
    read -r high med <<<"$(count_findings)"
    echo
    printf '%b################ 排查汇总 (放在最后，不会被刷走) ################%b\n' "$C_BOLD" "$C_RESET"
    printf '完整报告: %b%s%b\n' "$C_BOLD" "$REPORT_FILE" "$C_RESET"
    if (( high + med > 0 )); then
        printf '可疑项清单: %b%s%b\n' "$C_BOLD" "$FINDINGS_FILE" "$C_RESET"
        (( OPT_JSON )) && printf 'JSON 清单: %b%s%b\n' "$C_BOLD" "$JSON_FILE" "$C_RESET"
        printf '%b共发现 %s 项高危 / %s 项可疑，请逐条人工核实：%b\n' "$C_RED" "$high" "$med" "$C_RESET"
        awk -F'\t' -v Y="$(printf '%b' "$C_YELLOW")" -v X="$(printf '%b' "${C_RED}${C_BOLD}")" -v B="$(printf '%b' "$C_BOLD")" -v R="$(printf '%b' "$C_RESET")" '
            !($1 in s) { s[$1]=1; ord[++n]=$1 }
            { if ($2=="HIGH") h[$1]=h[$1] $3 "\n"; else m[$1]=m[$1] $3 "\n" }
            END {
                for (i=1;i<=n;i++) {
                    k=ord[i]; printf "\n%s%s%s\n", B, k, R
                    c=split(h[k], a, "\n"); for (j=1;j<c;j++) printf "  %s[高危]%s %s\n", X, R, a[j]
                    c=split(m[k], b, "\n"); for (j=1;j<c;j++) printf "  %s[可疑]%s %s\n", Y, R, b[j]
                }
            }' "$FINDINGS_FILE"
        echo
        printf '%b若确认被入侵，建议：断网隔离 -> 保留现场用于取证 -> 重装系统，而非仅删除文件。%b\n' "$C_YELLOW" "$C_RESET"
    else
        printf '%b未发现标记为[可疑]/[高危]的项目，但脚本无法保证 100%% 排除隐蔽 rootkit，建议结合 rkhunter/chkrootkit 结果综合判断。%b\n' "$C_GREEN" "$C_RESET"
    fi
    printf '%b提示: 首次运行会建立 SUID/登录 IP 基线; ClamAV/rkhunter/chkrootkit 的完整输出见报告目录中的对应日志。%b\n' "$C_BLUE" "$C_RESET"
}

run_all() {
    check_process
    check_network
    check_cron
    check_users
    check_hidden
    check_integrity
    check_preload
    check_logs
    check_rootkit
    check_botnet
    check_web
    (( OPT_WITH_CLAMAV )) && check_clamav
    return 0
}

run_check() {
    case "$1" in
        all)       run_all ;;
        process)   check_process ;;
        network)   check_network ;;
        cron)      check_cron ;;
        users)     check_users ;;
        hidden)    check_hidden ;;
        integrity) check_integrity ;;
        preload)   check_preload ;;
        logs)      check_logs ;;
        rootkit)   check_rootkit ;;
        clamav)    check_clamav ;;
        botnet)    check_botnet ;;
        web)       check_web ;;
    esac
}

# ------------------------- 交互菜单 -------------------------

show_menu() {
    local choice
    while true; do
        printf '\n%bVPS 木马/病毒排查脚本 v%s%b  报告目录: %s\n' "$C_BOLD" "$VERSION" "$C_RESET" "$REPORT_DIR"
        cat <<EOF
  1) 全部检测 (含 rkhunter/chkrootkit, 不含 ClamAV)
  2) 可疑进程 / 隐藏进程
  3) 网络连接 & 端口 & 防火墙
  4) 定时任务 & 启动项 & 登录脚本
  5) 用户账号 & SSH 密钥 & sshd 配置
  6) 可疑目录扫描 (/tmp /var/tmp /dev/shm /dev)
  7) 系统完整性 (包校验 / SUID / 内核模块)
  8) LD_PRELOAD 劫持检测
  9) 登录日志 & 历史命令
 10) rkhunter / chkrootkit
 11) ClamAV 病毒扫描 (较慢，需单独确认)
 12) 肉鸡/DDoS/C2/挖矿检测 (含流量采样)
 13) Web 目录 webshell 特征
  0) 退出并显示汇总
EOF
        read -r -p "请选择: " choice || break
        case "$choice" in
            1) run_check all ;;
            2) run_check process ;;
            3) run_check network ;;
            4) run_check cron ;;
            5) run_check users ;;
            6) run_check hidden ;;
            7) run_check integrity ;;
            8) run_check preload ;;
            9) run_check logs ;;
            10) run_check rootkit ;;
            11) run_check clamav ;;
            12) run_check botnet ;;
            13) run_check web ;;
            0|q|Q) break ;;
            *) log_err "无效选项" ;;
        esac
    done
}

# ------------------------- 入口 -------------------------

parse_args() {
    while (( $# )); do
        case "$1" in
            -y|--yes)        OPT_YES=1 ;;
            --no-install)    OPT_NO_INSTALL=1 ;;
            --online)        OPT_ONLINE=1 ;;
            --with-clamav)   OPT_WITH_CLAMAV=1 ;;
            --full-scan)     OPT_FULL_SCAN=1 ;;
            -q|--quiet)      OPT_QUIET=1 ;;
            --json)          OPT_JSON=1 ;;
            --no-color)      OPT_NO_COLOR=1 ;;
            -V|--version)    SUBCMD="version" ;;
            -h|--help|help)  SUBCMD="help" ;;
            -*)              init_colors; log_err "未知选项: $1"; usage >&2; exit 2 ;;
            *)
                if [[ -n "$SUBCMD" && "$SUBCMD" != "help" && "$SUBCMD" != "version" ]]; then
                    init_colors; log_err "只能指定一个子命令 (已有: $SUBCMD, 又收到: $1)"; exit 2
                fi
                [[ "$SUBCMD" == "help" || "$SUBCMD" == "version" ]] || SUBCMD="$1"
                ;;
        esac
        shift
    done
}

valid_subcmd() {
    case "$1" in
        ""|all|process|network|cron|users|hidden|integrity|preload|logs|rootkit|clamav|botnet|web|report|help|version) return 0 ;;
        *) return 1 ;;
    esac
}

cmd_report() {
    local rf lf jf
    rf="$(ls -1t "${REPORT_DIR}"/report-*.txt 2>/dev/null | head -1)"
    lf="$(ls -1t "${REPORT_DIR}"/findings-*.txt 2>/dev/null | head -1)"
    jf="$(ls -1t "${REPORT_DIR}"/findings-*.json 2>/dev/null | head -1)"
    echo "最近报告: ${rf:-(无)}"
    [[ -n "$jf" ]] && echo "最近 JSON: $jf"
    if [[ -n "$lf" && -s "$lf" ]]; then
        echo "--- $lf ---"
        awk -F'\t' '{printf "[%s] %s: %s\n", ($2=="HIGH"?"高危":"可疑"), $1, $3}' "$lf"
    else
        echo "(无可疑项记录)"
    fi
}

finalize() {
    [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
    # 报告里去掉颜色转义码, 并保证权限为 600
    if [[ -f "$REPORT_FILE" ]]; then
        sed -i "s/$(printf '\033')\[[0-9;]*m//g" "$REPORT_FILE" 2>/dev/null
        chmod 600 "$REPORT_FILE" "$FINDINGS_FILE" 2>/dev/null
    fi
}

run_body() {
    print_banner
    if [[ "$SUBCMD" == "menu" ]]; then show_menu; else run_check "$SUBCMD"; fi
    print_summary
}

main() {
    parse_args "$@"
    init_colors

    case "$SUBCMD" in
        help)    usage; exit 0 ;;
        version) echo "$SCRIPT_NAME $VERSION"; exit 0 ;;
    esac
    if ! valid_subcmd "$SUBCMD"; then
        log_err "未知子命令: $SUBCMD"; usage >&2; exit 2
    fi

    need_root
    ensure_dirs
    if [[ "$SUBCMD" == "report" ]]; then cmd_report; exit 0; fi

    acquire_lock
    detect_pkg
    TMP_DIR="$(mktemp -d "${STATE_DIR}/tmp.XXXXXX")" || { log_err "无法创建临时目录"; exit 2; }
    : > "$REPORT_FILE"
    : > "$FINDINGS_FILE"
    trap finalize EXIT
    trap 'printf "\n"; log_err "收到中断信号，已退出"; exit 130' INT TERM

    if [[ -z "$SUBCMD" ]]; then
        if (( IS_TTY_IN && IS_TTY_OUT && ! OPT_QUIET )); then SUBCMD="menu"; else SUBCMD="all"; fi
    fi

    if (( OPT_QUIET )); then
        # 完整输出写入报告, 终端只显示汇总
        run_body >> "$REPORT_FILE" 2>&1
        print_summary
    else
        # 用管道而不是 exec+进程替换, 保证 tee 在脚本退出前写完 (无竞态)
        run_body 2>&1 | tee -a "$REPORT_FILE"
    fi

    (( OPT_JSON )) && write_json

    local high med
    read -r high med <<<"$(count_findings)"
    (( high + med > 0 )) && exit 1
    exit 0
}

main "$@"
