#!/bin/bash
# 系统信息与优化模块

if [ -z "$VPS_COMMON_LOADED" ]; then
    source /usr/local/share/vn_modules/common.sh 2>/dev/null || {
        echo "无法加载公共函数库"
        exit 1
    }
fi
detect_os
check_dependencies
check_root

show_system_info() {
    clear
    printf "${BLUE}========== 系统信息 ==========${NC}\n"
    printf "主机名       : %s\n" "$(hostname)"
    printf "操作系统     : %s\n" "$(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
    printf "内核版本     : %s\n" "$(uname -r)"
    printf "运行时间     : %s  启动于 %s\n" "$(LC_ALL=C uptime -p)" "$(LC_ALL=C uptime -s)"
    printf "当前用户数   : %s\n" "$(who | wc -l)"
    echo ""

    # CPU
    printf "${YELLOW}--- CPU ---${NC}\n"
    printf "型号         : %s\n" "$(LC_ALL=C lscpu | grep 'Model name' | cut -d: -f2 | xargs)"
    local sockets cores_per_socket total_cores
    sockets=$(LC_ALL=C lscpu | grep '^Socket(s):' | awk '{print $2}')
    cores_per_socket=$(LC_ALL=C lscpu | grep -E '^Core\(s\) per socket' | awk '{print $4}')
    if [[ "$sockets" =~ ^[0-9]+$ && "$cores_per_socket" =~ ^[0-9]+$ ]]; then
        total_cores=$(( sockets * cores_per_socket ))
    else
        # lscpu 字段缺失时退化为逻辑核心数（多数 VPS 场景下二者本就相等）
        total_cores=$(nproc)
    fi
    printf "核心/线程    : %s 核 / %s 线程\n" "$total_cores" "$(nproc)"
    # 1 秒采样计算 CPU 使用率
    read cpu_user1 cpu_nice1 cpu_sys1 cpu_idle1 < <(grep 'cpu ' /proc/stat | awk '{print $2,$3,$4,$5}')
    sleep 1
    read cpu_user2 cpu_nice2 cpu_sys2 cpu_idle2 < <(grep 'cpu ' /proc/stat | awk '{print $2,$3,$4,$5}')
    cpu_total1=$((cpu_user1 + cpu_nice1 + cpu_sys1 + cpu_idle1))
    cpu_total2=$((cpu_user2 + cpu_nice2 + cpu_sys2 + cpu_idle2))
    cpu_diff=$((cpu_total2 - cpu_total1))
    cpu_idle_diff=$((cpu_idle2 - cpu_idle1))
    [ $cpu_diff -eq 0 ] && cpu_usage=0 || cpu_usage=$(( (cpu_diff - cpu_idle_diff) * 100 / cpu_diff ))
    printf "CPU 使用率   : %s%%\n" "$cpu_usage"
    # 负载
    printf "平均负载     : %s\n" "$(LC_ALL=C uptime | awk -F'load average:' '{print $2}' | sed 's/,//g')"
    echo ""

    # 内存
    printf "${YELLOW}--- 内存 ---${NC}\n"
    mem_total=$(free -m | awk 'NR==2{print $2}')
    mem_used=$(free -m | awk 'NR==2{print $3}')
    mem_pct=$(( mem_used * 100 / mem_total ))
    printf "内存使用     : %dMB / %dMB (%d%%)\n" "$mem_used" "$mem_total" "$mem_pct"
    # 显示缓存/可用
    mem_buff=$(free -m | awk 'NR==2{print $6}')
    printf "缓冲/缓存    : %dMB\n" "$mem_buff"
    # Swap
    swap_total=$(free -m | awk 'NR==3{print $2}')
    swap_used=$(free -m | awk 'NR==3{print $3}')
    if [ "$swap_total" -gt 0 ]; then
        swap_pct=$(( swap_used * 100 / swap_total ))
        printf "Swap 使用    : %dMB / %dMB (%d%%)\n" "$swap_used" "$swap_total" "$swap_pct"
    else
        printf "Swap         : 未启用\n"
    fi
    echo ""

    # 磁盘
    printf "${YELLOW}--- 磁盘使用 ---${NC}\n"
    df -h --type=ext4 --type=xfs --type=btrfs --type=ext3 --type=zfs 2>/dev/null || df -h | grep -vE '^(tmpfs|devtmpfs|efivarfs|overlay|none)'
    echo ""

    # 进程
    printf "${YELLOW}--- 进程 ---${NC}\n"
    printf "进程总数     : %s\n" "$(ps aux --no-headers 2>/dev/null | wc -l)"
    zombies=$(ps -eo stat= 2>/dev/null | grep -c '^Z' || true)
    printf "僵尸进程     : %s\n" "$zombies"
    echo ""

    # 网络配置
    printf "${BLUE}========== 网络信息 ==========${NC}\n"
    echo "=== 网卡地址 ==="
    ip -br addr | grep -v "lo"
    echo ""
    echo "=== 默认网关 ==="
    ip route | grep default
    echo ""
    echo "=== DNS 服务器 ==="
    cat /etc/resolv.conf | grep nameserver
    echo ""

    # 公网 IPv4 (可能耗时，主源失败/超时时换备用源重试一次)
    printf "${YELLOW}--- 公网 IP ---${NC}\n"
    pub_ip=$(curl -s4 --max-time 2 ifconfig.me 2>/dev/null)
    [ -z "$pub_ip" ] && pub_ip=$(curl -s4 --max-time 2 ip.sb 2>/dev/null)
    printf "IPv4         : %s\n" "${pub_ip:-无法获取}"
    # IPv6
    pub_ip6=$(curl -s6 --max-time 2 ifconfig.me 2>/dev/null)
    [ -z "$pub_ip6" ] && pub_ip6=$(curl -s6 --max-time 2 ip.sb 2>/dev/null)
    printf "IPv6         : %s\n" "${pub_ip6:-无或超时}"
    echo ""

    # 网络流量 (需要 vnstat)
    if command -v vnstat &>/dev/null; then
        iface=$(ip route | grep default | awk '{print $5}' | head -n1)
        if [ -n "$iface" ]; then
            printf "${YELLOW}--- 网络流量 (%s) ---${NC}\n" "$iface"
            vnstat -i "$iface" -d | tail -3
        fi
    fi

    echo ""
    read -p "按回车键继续..." dummy
}

install_bbr() {
    clear
    printf "${BLUE}===== BBR 加速状态与设置 =====${NC}\n"
    local kernel_full=$(uname -r)
    local kernel_ver=$(echo "$kernel_full" | cut -d. -f1-2)
    printf "当前内核版本: %s\n" "$kernel_full"

    local current_cc
    current_cc=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    printf "当前拥塞控制算法: %s\n" "${current_cc:-未知}"
    printf "当前队列算法: %s\n" "$(sysctl net.core.default_qdisc 2>/dev/null | awk '{print $3}' || echo '未知')"

    if [ "$current_cc" = "bbr" ]; then
        printf "${GREEN}BBR 已启用！${NC}\n"
        read -p "按回车键返回..." dummy
        return
    fi

    if ! printf '%s\n' "$kernel_ver" "4.9" | sort -V | head -1 | grep -q "4.9"; then
        printf "${RED}内核版本过低（当前 %s，需要 >= 4.9），不支持 BBR。${NC}\n" "$kernel_ver"
        read -p "按回车键返回..." dummy
        return
    fi

    if ! confirm_action "BBR 未启用，是否立即开启？" "Y"; then
        return
    fi

    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    if sysctl -p &>/dev/null; then
        printf "${GREEN}BBR 加速已激活！${NC}\n"
        printf "新拥塞控制算法: %s\n" "$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')"
    else
        printf "${RED}sysctl 应用失败，请检查配置。${NC}\n"
    fi
    read -p "按回车键继续..." dummy
}

config_swap() {
    clear
    printf "${BLUE}当前 Swap 状态：${NC}\n"
    swapon --show
    echo ""
    read -p "输入要创建的 Swap 大小 (MB) [例如 1024]，输入 0 取消: " swap_size
    [[ -z "$swap_size" || "$swap_size" -eq 0 ]] && return
    if [[ $swap_size =~ ^[0-9]+$ ]]; then
        # 如果已有 /swapfile，先关闭并删除
        if swapon --show | grep -q "/swapfile"; then
            swapoff /swapfile
            rm -f /swapfile
        fi
        # 创建 swap 文件（修复路径错误）
        printf "${YELLOW}正在创建 swap 文件...${NC}\n"
        if dd if=/dev/zero of=/swapfile bs=1M count="$swap_size" status=progress 2>/dev/null; then
            chmod 600 /swapfile
            mkswap /swapfile
            swapon /swapfile
            # 确保 /etc/fstab 中有记录
            if ! grep -q "/swapfile" /etc/fstab; then
                echo "/swapfile none swap sw 0 0" >> /etc/fstab
            fi
            printf "${GREEN}✔ Swap 创建成功，大小 ${swap_size}MB${NC}\n"
        else
            printf "${RED}✘ dd 创建文件失败，请检查磁盘空间。${NC}\n"
        fi
    else
        printf "${RED}输入的不是有效数字${NC}\n"
    fi
    read -p "按回车键继续..." dummy
}

check_security_updates() {
    clear
    printf "${BLUE}===== 安全更新检查 =====${NC}\n"

    local os_family=""
    if command -v apt-get &>/dev/null; then
        os_family="debian"
    elif command -v dnf &>/dev/null; then
        os_family="dnf"
    elif command -v yum &>/dev/null; then
        os_family="yum"
    else
        printf "${RED}未识别的包管理器，无法检查更新。${NC}\n"
        read -p "按回车键返回..." dummy
        return
    fi

    case "$os_family" in
        debian)
            printf "${YELLOW}正在刷新软件源...${NC}\n"
            local apt_err
            apt_err=$(apt-get update -qq 2>&1)
            if [ $? -ne 0 ]; then
                printf "${RED}软件源刷新失败：${NC}\n%s\n" "$apt_err"
                read -p "按回车键返回..." dummy
                return
            fi

            local upgrade_list upgradable_all upgradable_sec
            upgrade_list=$(apt list --upgradable 2>/dev/null | grep '^[^ ]*/')
            upgradable_all=$(echo "$upgrade_list" | grep -c '^[^ ]*/' || true)
            upgradable_sec=$(echo "$upgrade_list" | grep -c -- '-security' || true)

            printf "可升级软件包总数 : %s\n" "$upgradable_all"
            printf "${YELLOW}其中安全更新     : %s${NC}\n" "$upgradable_sec"

            if [ "$upgradable_sec" -eq 0 ]; then
                printf "${GREEN}✔ 没有待安装的安全更新。${NC}\n"
                read -p "按回车键返回..." dummy
                return
            fi

            echo ""
            printf "${YELLOW}安全更新列表：${NC}\n"
            echo "$upgrade_list" | grep -- '-security' | awk -F/ '{print "  - "$1}'
            echo ""

            if confirm_action "是否立即安装安全更新？"; then
                local sec_pkgs
                sec_pkgs=$(echo "$upgrade_list" | grep -- '-security' | awk -F/ '{print $1}')
                if [ -n "$sec_pkgs" ]; then
                    # shellcheck disable=SC2086
                    if DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y $sec_pkgs; then
                        printf "${GREEN}✔ 安全更新安装完成。${NC}\n"
                    else
                        printf "${RED}✘ 安全更新安装过程中出现错误，请检查日志。${NC}\n"
                    fi
                else
                    printf "${RED}未能获取安全更新包列表。${NC}\n"
                fi
            fi
            ;;
        dnf|yum)
            local pm="$os_family"
            if [ "$pm" = "yum" ] && ! rpm -q yum-plugin-security &>/dev/null; then
                printf "${YELLOW}提示: 未检测到 yum-plugin-security 插件，安全更新识别可能不准确。${NC}\n"
                printf "${YELLOW}建议先执行: yum install -y yum-plugin-security${NC}\n\n"
            fi

            printf "${YELLOW}正在检查更新...${NC}\n"
            local sec_output sec_count
            sec_output=$($pm check-update --security 2>/dev/null | grep -E '^[A-Za-z0-9]')
            sec_count=$(echo "$sec_output" | grep -c . || true)
            [ -z "$sec_output" ] && sec_count=0

            if [ "$sec_count" -eq 0 ]; then
                printf "${GREEN}✔ 没有待安装的安全更新（或当前包管理器不支持安全更新过滤）。${NC}\n"
                read -p "按回车键返回..." dummy
                return
            fi

            printf "${YELLOW}安全更新数量: %s${NC}\n" "$sec_count"
            echo "$sec_output"
            echo ""

            if confirm_action "是否立即安装安全更新？"; then
                if $pm update --security -y; then
                    printf "${GREEN}✔ 安全更新安装完成。${NC}\n"
                else
                    printf "${RED}✘ 安全更新安装过程中出现错误，请检查日志。${NC}\n"
                fi
            fi
            ;;
    esac

    read -p "按回车键继续..." dummy
}

system_opt_menu() {
    while true; do
        clear
        printf "${BLUE}===== 系统信息与优化 =====${NC}\n"
        echo "1. 查看系统与网络信息"
        echo "2. 安装/开启 BBR"
        echo "3. 虚拟内存配置 (Swap)"
        echo "4. 检查/安装安全更新"
        echo "0. 返回上级菜单"
        read -p "请选择: " opt_choice
        case $opt_choice in
            1) show_system_info ;;
            2) install_bbr ;;
            3) config_swap ;;
            4) check_security_updates ;;
            0) break ;;
            *) printf "${RED}无效选项${NC}\n" ;;
        esac
    done
}

system_opt_menu
