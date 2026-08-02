#!/bin/bash
# SSH 安全加固模块（密钥管理 + 关闭密码登录）

# ---------- 0. 权限检查 ----------
if [ "$(id -u)" -ne 0 ]; then
    printf "\033[31m✘ 错误：请使用 root 权限执行此脚本 (可以先使用 sudo -i 切换)\033[0m\n"
    exit 1
fi

if [ -z "$VPS_COMMON_LOADED" ]; then
    source /usr/local/share/vn_modules/common.sh 2>/dev/null || {
        echo "无法加载公共函数库"
        exit 1
    }
fi

LOGIN_LOG_PERSIST="/var/log/vn_ssh_logins.log"
LOGIN_LOG_CURSOR="/usr/local/share/vn_modules/.ssh_login_cursor"

# ---------- 增量同步成功登录记录到持久化文件 ----------
# 供 cron 非交互调用: ssh_harden.sh --sync-login-log
sync_login_log() {
    touch "$LOGIN_LOG_PERSIST"
    chmod 600 "$LOGIN_LOG_PERSIST"

    if command -v journalctl &>/dev/null && [ -n "$(journalctl -u ssh -u sshd --no-pager -n 1 2>/dev/null)" ]; then
        local jq_args=()
        [ -s "$LOGIN_LOG_CURSOR" ] && jq_args=(--after-cursor "$(cat "$LOGIN_LOG_CURSOR")")

        journalctl -u ssh -u sshd --no-pager "${jq_args[@]}" --show-cursor 2>/dev/null | \
        while IFS= read -r line; do
            if [[ "$line" == "-- cursor:"* ]]; then
                echo "${line#-- cursor: }" > "$LOGIN_LOG_CURSOR"
                continue
            fi
            echo "$line" | grep -qE 'Accepted (publickey|password|keyboard-interactive)' && echo "$line" >> "$LOGIN_LOG_PERSIST"
        done
    else
        # 退化方案（无 journald 持久化时）：按行号游标增量读取，文件被 rotate/清空时游标自动重置重新计数
        local src=""
        [ -f /var/log/auth.log ] && src="/var/log/auth.log"
        [ -z "$src" ] && [ -f /var/log/secure ] && src="/var/log/secure"
        [ -z "$src" ] && return

        local last_line=0 total_lines
        [ -s "$LOGIN_LOG_CURSOR" ] && last_line=$(cat "$LOGIN_LOG_CURSOR")
        total_lines=$(wc -l < "$src")
        [ "$total_lines" -lt "$last_line" ] && last_line=0

        tail -n "+$((last_line + 1))" "$src" 2>/dev/null | grep -E 'Accepted (publickey|password|keyboard-interactive)' >> "$LOGIN_LOG_PERSIST"
        echo "$total_lines" > "$LOGIN_LOG_CURSOR"
    fi
}

# cron 非交互调用入口：只做同步，不进菜单，不做 root/依赖检查之外的任何交互
if [ "$1" = "--sync-login-log" ]; then
    sync_login_log
    exit 0
fi

detect_os
check_dependencies

SSH_CONF="/etc/ssh/sshd_config"
SSH_PORT=$(get_ssh_port)

# ---------- 备份 sshd_config ----------
backup_ssh() {
    if [ ! -f "${SSH_CONF}.bak" ]; then
        cp "$SSH_CONF" "${SSH_CONF}.bak"
        printf "${GREEN}已备份配置文件 -> ${SSH_CONF}.bak${NC}\n"
    fi
}

# ---------- 生成密钥对 ----------
generate_key() {
    printf "${BLUE}===== 生成 SSH 密钥对 =====${NC}\n"
    printf "密钥类型: 1. RSA (4096)   2. Ed25519 (推荐)\n"
    read -p "请选择 [1-2，默认2]: " key_type
    key_type=${key_type:-2}

    read -p "密钥保存路径 (默认 ~/.ssh/vps_key): " key_path
    key_path=${key_path:-~/.ssh/vps_key}

    read -p "密钥备注 (默认 vps@$(hostname)): " key_comment
    key_comment=${key_comment:-vps@$(hostname)}

    if [ -f "${key_path}" ]; then
        read -p "文件已存在，是否覆盖？[y/N]: " overwrite
        if [[ ! $overwrite =~ ^[Yy]$ ]]; then
            return
        fi
    fi

    mkdir -p "$(dirname "$key_path")"

    case $key_type in
        1) ssh-keygen -t rsa -b 4096 -f "$key_path" -C "$key_comment" -N "" ;;
        2) ssh-keygen -t ed25519 -f "$key_path" -C "$key_comment" -N "" ;;
        *) ssh-keygen -t ed25519 -f "$key_path" -C "$key_comment" -N "" ;;
    esac

    printf "${GREEN}密钥对已生成:${NC}\n"
    printf "  私钥: %s\n" "$key_path"
    printf "  公钥: %s.pub\n" "$key_path"
    echo ""

    # ===== 打印私钥 =====
    printf "${YELLOW}========== 私钥内容 (请妥善保管，不要泄露) ==========${NC}\n"
    printf "${RED}"
    cat "$key_path"
    printf "${NC}"
    printf "${YELLOW}========== 私钥结束 ==========${NC}\n"
    echo ""

    # ===== 打印公钥 =====
    printf "${GREEN}========== 公钥内容 (用于添加到服务器 authorized_keys) ==========${NC}\n"
    cat "${key_path}.pub"
    printf "${GREEN}========== 公钥结束 ==========${NC}\n"
    echo ""

    printf "${YELLOW}提示：请将私钥下载到本地并妥善保存，然后删除服务器上的私钥文件。${NC}\n"
    read -p "按回车键继续..." dummy
}

# ---------- 添加公钥到当前用户 ----------
add_pubkey_local() {
    printf "${BLUE}===== 添加公钥到本机 =====${NC}\n"
    echo "可添加的公钥来源:"
    echo "1. 粘贴公钥内容"
    echo "2. 从本地文件读取"
    echo "3. 从 ~/.ssh/id_rsa.pub 读取"
    echo "0. 返回"
    read -p "选择: " src_choice

    local pubkey=""
    case $src_choice in
        1)
            printf "请粘贴公钥内容 (以 ssh-rsa/ssh-ed25519/ecdsa-sha2 开头)，粘贴后按 Ctrl+D 结束:\n"
            pubkey=$(cat)
            ;;
        2)
            read -p "输入公钥文件路径: " pubkey_path
            if [ -f "$pubkey_path" ]; then
                pubkey=$(cat "$pubkey_path")
            else
                printf "${RED}文件不存在${NC}\n"
                read -p "按回车键继续..." dummy
                return
            fi
            ;;
        3)
            if [ -f ~/.ssh/id_rsa.pub ]; then
                pubkey=$(cat ~/.ssh/id_rsa.pub)
            elif [ -f ~/.ssh/id_ed25519.pub ]; then
                pubkey=$(cat ~/.ssh/id_ed25519.pub)
            else
                printf "${RED}未找到 ~/.ssh/id_*.pub${NC}\n"
                read -p "按回车键继续..." dummy
                return
            fi
            ;;
        0) return ;;
        *) printf "${RED}无效选项${NC}\n"; read -p "按回车键继续..." dummy; return ;;
    esac

    # 验证公钥格式
    if ! echo "$pubkey" | grep -qE '^(ssh-rsa|ssh-ed25519|ecdsa-sha2)'; then
        printf "${RED}无效的公钥格式${NC}\n"
        read -p "按回车键继续..." dummy
        return
    fi

    # 添加到 authorized_keys
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
    if ! grep -qF "$pubkey" ~/.ssh/authorized_keys 2>/dev/null; then
        echo "$pubkey" >> ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys
        printf "${GREEN}公钥已添加。${NC}\n"
    else
        printf "${YELLOW}公钥已存在，跳过。${NC}\n"
    fi
    read -p "按回车键继续..." dummy
}

# ---------- 关闭密码登录 ----------
disable_password_auth() {
    printf "${RED}⚠ 警告：关闭密码登录后，只能通过密钥登录！${NC}\n"
    printf "${RED}   请确保你已经添加了公钥并测试成功，否则会锁死服务器！${NC}\n"
    echo ""

    # 1. 检查是否有授权密钥 (兼容 RSA, Ed25519, ECDSA)
    if [ ! -f ~/.ssh/authorized_keys ] || [ ! -s ~/.ssh/authorized_keys ]; then
        printf "${RED}✘ 错误：未找到任何授权的公钥！${NC}\n"
        printf "   请先使用菜单选项 2 添加公钥，或手动创建 ~/.ssh/authorized_keys\n"
        read -p "按回车键继续..." dummy
        return
    fi
    local key_count=$(grep -E -c '^(ssh-|ecdsa-sha2-)' ~/.ssh/authorized_keys 2>/dev/null || echo 0)
    if [ "$key_count" -eq 0 ]; then
        printf "${RED}✘ 错误：authorized_keys 中没有有效的公钥！${NC}\n"
        read -p "按回车键继续..." dummy
        return
    fi
    printf "${GREEN}检测到 %d 个有效公钥。${NC}\n" "$key_count"

    read -p "是否继续？[y/N]: " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        return
    fi

    backup_ssh

    # 2. 确保 PubkeyAuthentication 是开启的（关键）
    sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSH_CONF"
    grep -q '^PubkeyAuthentication yes' "$SSH_CONF" || echo "PubkeyAuthentication yes" >> "$SSH_CONF"

    # 3. 关闭密码登录和交互式键盘登录（带保底机制）
    for param in PasswordAuthentication ChallengeResponseAuthentication KbdInteractiveAuthentication; do
        sed -i "s/^#*${param}.*/${param} no/" "$SSH_CONF"
        grep -q "^${param} no" "$SSH_CONF" || echo "${param} no" >> "$SSH_CONF"
    done

    # 4. 处理新版系统及云厂商的附加配置目录覆盖问题
    if [ -d /etc/ssh/sshd_config.d ]; then
        find /etc/ssh/sshd_config.d/ -type f -name "*.conf" -exec sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' {} \;
        find /etc/ssh/sshd_config.d/ -type f -name "*.conf" -exec sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' {} \;
        find /etc/ssh/sshd_config.d/ -type f -name "*.conf" -exec sed -i 's/^#*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' {} \;
    fi

    # 5. 语法检查
    printf "${YELLOW}正在检查配置文件语法...${NC}\n"
    if ! sshd -t 2>/dev/null; then
        printf "${RED}✘ SSH 配置文件语法错误！已中止操作，并恢复备份。${NC}\n"
        cp "${SSH_CONF}.bak" "$SSH_CONF"
        read -p "按回车键继续..." dummy
        return
    fi
    printf "${GREEN}配置语法正确。${NC}\n"

    # 6. 询问重启
    printf "${YELLOW}即将重启 SSH 服务...${NC}\n"
    read -p "继续？[y/N]: " confirm2
    if [[ ! $confirm2 =~ ^[Yy]$ ]]; then
        printf "${YELLOW}已取消重启，配置已写入但未生效。${NC}\n"
        read -p "按回车键继续..." dummy
        return
    fi

    # 7. 尝试重启，同时兼容 ssh / sshd 两种服务名
    local restarted=false
    if systemctl restart ssh 2>/dev/null; then
        restarted=true
    elif systemctl restart sshd 2>/dev/null; then
        restarted=true
    elif service ssh restart 2>/dev/null; then
        restarted=true
    elif service sshd restart 2>/dev/null; then
        restarted=true
    elif /etc/init.d/ssh restart 2>/dev/null; then
        restarted=true
    fi

    if $restarted; then
        printf "${GREEN}✔ SSH 服务已重启，密码登录已关闭。${NC}\n"
        printf "${GREEN}   请保持当前会话不要断开，新开窗口测试密钥登录！${NC}\n"
    else
        printf "${RED}✘ SSH 服务重启失败！配置已写入但未生效，请手动检查。${NC}\n"
    fi
    read -p "按回车键继续..." dummy
}

# ---------- 开启密码登录（恢复） ----------
enable_password_auth() {
    printf "${YELLOW}将重新开启密码登录...${NC}\n"
    read -p "确定？[y/N]: " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        return
    fi

    backup_ssh

    # 恢复主配置
    for param in PasswordAuthentication ChallengeResponseAuthentication KbdInteractiveAuthentication UsePAM; do
        sed -i "s/^#*${param}.*/${param} yes/" "$SSH_CONF"
        grep -q "^${param} yes" "$SSH_CONF" || echo "${param} yes" >> "$SSH_CONF"
    done

    # 恢复目录配置
    if [ -d /etc/ssh/sshd_config.d ]; then
        find /etc/ssh/sshd_config.d/ -type f -name "*.conf" -exec sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' {} \;
        find /etc/ssh/sshd_config.d/ -type f -name "*.conf" -exec sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' {} \;
        find /etc/ssh/sshd_config.d/ -type f -name "*.conf" -exec sed -i 's/^#*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' {} \;
    fi

    systemctl restart sshd 2>/dev/null || service sshd restart 2>/dev/null || /etc/init.d/ssh restart 2>/dev/null
    printf "${GREEN}密码登录已重新开启。${NC}\n"
    read -p "按回车键继续..." dummy
}

# ---------- 查看授权密钥 ----------
list_keys() {
    printf "${BLUE}===== 已授权的公钥 =====${NC}\n"
    if [ -f ~/.ssh/authorized_keys ] && [ -s ~/.ssh/authorized_keys ]; then
        cat -n ~/.ssh/authorized_keys
    else
        printf "${YELLOW}没有已授权的公钥。${NC}\n"
    fi
    echo ""
    read -p "按回车键继续..." dummy
}

# ---------- 查看当前 SSH 配置摘要 ----------
show_config() {
    printf "${BLUE}===== SSH 配置摘要 =====${NC}\n"
    printf "SSH 端口: %s\n" "$SSH_PORT"
    printf "密码登录: %s\n" "$(grep -E '^PasswordAuthentication' "$SSH_CONF" 2>/dev/null | tail -1 || echo '未设置 (默认 yes)')"
    printf "密钥认证: %s\n" "$(grep -E '^PubkeyAuthentication' "$SSH_CONF" 2>/dev/null | tail -1 || echo '未设置 (默认 yes)')"
    printf "Root 登录: %s\n" "$(grep -E '^PermitRootLogin' "$SSH_CONF" 2>/dev/null | tail -1 || echo '未设置 (默认 yes)')"
    printf "已授权密钥数: %s\n" "$(grep -E -c '^(ssh-|ecdsa-sha2-)' ~/.ssh/authorized_keys 2>/dev/null || echo 0)"
    echo ""
    read -p "按回车键继续..." dummy
}

# ---------- 删除指定公钥 ----------
delete_key() {
    if [ ! -f ~/.ssh/authorized_keys ] || [ ! -s ~/.ssh/authorized_keys ]; then
        printf "${YELLOW}没有已授权的公钥。${NC}\n"
        read -p "按回车键继续..." dummy
        return
    fi

    printf "${BLUE}===== 删除公钥 =====${NC}\n"
    cat -n ~/.ssh/authorized_keys
    echo ""
    read -p "输入要删除的行号 (0 取消): " line_num
    if [[ "$line_num" =~ ^[0-9]+$ ]] && [ "$line_num" -gt 0 ]; then
        sed -i "${line_num}d" ~/.ssh/authorized_keys
        printf "${GREEN}已删除第 %s 行的公钥。${NC}\n" "$line_num"
    fi
    read -p "按回车键继续..." dummy
}

# ---------- 修改 SSH 端口 ----------
change_ssh_port() {
    printf "${BLUE}===== 修改 SSH 端口 =====${NC}\n"
    printf "当前端口: ${GREEN}%s${NC}\n" "$SSH_PORT"
    echo ""
    read -p "请输入新的 SSH 端口 (1-65535): " new_port

    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        printf "${RED}✘ 无效端口号${NC}\n"
        read -p "按回车键继续..." dummy
        return
    fi

    if [ "$new_port" -eq "$SSH_PORT" ]; then
        printf "${YELLOW}新端口与当前端口相同，无需修改。${NC}\n"
        read -p "按回车键继续..." dummy
        return
    fi

    if [ "$new_port" -lt 1024 ]; then
        printf "${YELLOW}⚠ 警告：1024 以下为特权端口，部分环境可能有额外限制。${NC}\n"
        read -p "确定继续？[y/N]: " confirm_low
        [[ ! $confirm_low =~ ^[Yy]$ ]] && return
    fi

    # 检测端口是否已被占用
    if command -v ss &>/dev/null; then
        if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${new_port}\$"; then
            printf "${RED}✘ 端口 %s 已被占用！${NC}\n" "$new_port"
            read -p "按回车键继续..." dummy
            return
        fi
    fi

    printf "${RED}⚠ 警告：修改 SSH 端口前，请务必确认防火墙/安全组已放行新端口 %s！${NC}\n" "$new_port"
    printf "${YELLOW}   本操作会同时保留旧端口 %s 作为回退，避免因端口未放行而被锁死。${NC}\n" "$SSH_PORT"
    read -p "是否继续？[y/N]: " confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && return

    backup_ssh

    # 移除主配置文件中已存在的 Port 指令（保留注释行）
    sed -i '/^Port /d' "$SSH_CONF"
    {
        echo "Port ${SSH_PORT}"
        echo "Port ${new_port}"
    } >> "$SSH_CONF"

    # 处理 sshd_config.d 目录下可能覆盖 Port 的配置
    if [ -d /etc/ssh/sshd_config.d ]; then
        find /etc/ssh/sshd_config.d/ -type f -name "*.conf" -exec sed -i '/^Port /d' {} \;
    fi

    printf "${YELLOW}正在检查配置文件语法...${NC}\n"
    if ! sshd -t 2>/dev/null; then
        printf "${RED}✘ SSH 配置文件语法错误！已中止操作，并恢复备份。${NC}\n"
        cp "${SSH_CONF}.bak" "$SSH_CONF"
        read -p "按回车键继续..." dummy
        return
    fi
    printf "${GREEN}配置语法正确。${NC}\n"

    read -p "即将重启 SSH 服务，同时监听新旧两个端口，继续？[y/N]: " confirm2
    if [[ ! $confirm2 =~ ^[Yy]$ ]]; then
        printf "${YELLOW}已取消重启，配置已写入但未生效。${NC}\n"
        read -p "按回车键继续..." dummy
        return
    fi

    local restarted=false
    if systemctl restart ssh 2>/dev/null; then
        restarted=true
    elif systemctl restart sshd 2>/dev/null; then
        restarted=true
    elif service ssh restart 2>/dev/null; then
        restarted=true
    elif service sshd restart 2>/dev/null; then
        restarted=true
    elif /etc/init.d/ssh restart 2>/dev/null; then
        restarted=true
    fi

    if $restarted; then
        printf "${GREEN}✔ SSH 服务已重启，新端口 %s 已生效，旧端口 %s 仍保留作为回退。${NC}\n" "$new_port" "$SSH_PORT"
        printf "${GREEN}   请务必保持当前会话不要断开，新开窗口测试新端口连接成功后，${NC}\n"
        printf "${GREEN}   再使用菜单选项「确认端口切换」移除旧端口。${NC}\n"
        printf "${YELLOW}   提示：如使用了防火墙脚本(如 firewall_fail2ban.sh)，请记得放行 %s/tcp，确认切换后再关闭旧端口 %s。${NC}\n" "$new_port" "$SSH_PORT"
    else
        printf "${RED}✘ SSH 服务重启失败！配置已写入但未生效，请手动检查。${NC}\n"
        read -p "按回车键继续..." dummy
        return
    fi
    read -p "按回车键继续..." dummy
}

# ---------- 确认端口切换（移除多余的 Port 指令） ----------
confirm_ssh_port() {
    printf "${BLUE}===== 确认 SSH 端口切换 =====${NC}\n"
    local ports
    ports=$(grep -E '^Port ' "$SSH_CONF" 2>/dev/null)

    if [ -z "$ports" ]; then
        printf "${YELLOW}未检测到显式 Port 配置（使用默认 22）。${NC}\n"
        read -p "按回车键继续..." dummy
        return
    fi

    local port_count
    port_count=$(echo "$ports" | wc -l)

    if [ "$port_count" -le 1 ]; then
        printf "${GREEN}当前只有一个端口在监听，无需确认。${NC}\n"
        echo "$ports"
        read -p "按回车键继续..." dummy
        return
    fi

    printf "当前监听的端口:\n"
    echo "$ports" | nl
    echo ""
    read -p "请输入要保留的端口号: " keep_port

    if ! echo "$ports" | grep -qE "^Port ${keep_port}\$"; then
        printf "${RED}✘ 输入的端口不在当前监听列表中${NC}\n"
        read -p "按回车键继续..." dummy
        return
    fi

    read -p "确认只保留端口 ${keep_port}，移除其他端口？[y/N]: " confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && return

    backup_ssh
    sed -i '/^Port /d' "$SSH_CONF"
    echo "Port ${keep_port}" >> "$SSH_CONF"

    if [ -d /etc/ssh/sshd_config.d ]; then
        find /etc/ssh/sshd_config.d/ -type f -name "*.conf" -exec sed -i '/^Port /d' {} \;
    fi

    printf "${YELLOW}正在检查配置文件语法...${NC}\n"
    if ! sshd -t 2>/dev/null; then
        printf "${RED}✘ SSH 配置文件语法错误！已中止操作，并恢复备份。${NC}\n"
        cp "${SSH_CONF}.bak" "$SSH_CONF"
        read -p "按回车键继续..." dummy
        return
    fi

    local restarted=false
    if systemctl restart ssh 2>/dev/null; then
        restarted=true
    elif systemctl restart sshd 2>/dev/null; then
        restarted=true
    elif service ssh restart 2>/dev/null; then
        restarted=true
    elif service sshd restart 2>/dev/null; then
        restarted=true
    elif /etc/init.d/ssh restart 2>/dev/null; then
        restarted=true
    fi

    if $restarted; then
        SSH_PORT=$keep_port
        printf "${GREEN}✔ 已确认，SSH 仅监听端口 %s。${NC}\n" "$keep_port"
    else
        printf "${RED}✘ SSH 服务重启失败！配置已写入但未生效，请手动检查。${NC}\n"
    fi
    read -p "按回车键继续..." dummy
}

# ---------- 查看最近成功登录记录 ----------
show_login_history() {
    printf "${BLUE}===== 最近成功登录记录 =====${NC}\n"

    local raw_logs="" log_source=""
    if [ -f "$LOGIN_LOG_PERSIST" ] && [ -s "$LOGIN_LOG_PERSIST" ]; then
        raw_logs=$(cat "$LOGIN_LOG_PERSIST")
        log_source="$LOGIN_LOG_PERSIST (持久化副本，不受系统日志轮转影响)"
    elif command -v journalctl &>/dev/null && [ -n "$(journalctl -u ssh -u sshd --no-pager -n 1 2>/dev/null)" ]; then
        raw_logs=$(journalctl -u ssh -u sshd --no-pager -n 2000 2>/dev/null | grep -E 'Accepted (publickey|password|keyboard-interactive)')
        log_source="journalctl (systemd 日志，未开启持久化，历史长度受日志保留策略限制)"
    elif [ -f /var/log/auth.log ]; then
        raw_logs=$(grep -E 'Accepted (publickey|password|keyboard-interactive)' /var/log/auth.log 2>/dev/null)
        log_source="/var/log/auth.log (未开启持久化，历史长度受 logrotate 限制)"
    elif [ -f /var/log/secure ]; then
        raw_logs=$(grep -E 'Accepted (publickey|password|keyboard-interactive)' /var/log/secure 2>/dev/null)
        log_source="/var/log/secure (未开启持久化，历史长度受 logrotate 限制)"
    fi

    if [ -z "$raw_logs" ]; then
        printf "${YELLOW}未找到登录日志（可能日志已被清理，或系统使用了其他日志路径/日志转发方案）。${NC}\n"
        read -p "按回车键继续..." dummy
        return
    fi

    printf "日志来源: %s\n\n" "$log_source"
    printf "%-16s %-10s %-14s %s\n" "时间" "用户" "认证方式" "来源 IP"
    echo "--------------------------------------------------------------"

    echo "$raw_logs" | tail -n 20 | while IFS= read -r line; do
        local ts user method ip
        ts=$(echo "$line" | awk '{print $1, $2, $3}')
        method=$(echo "$line" | grep -oE 'Accepted [a-z/-]+' | awk '{print $2}')
        user=$(echo "$line" | grep -oE 'for [^ ]+' | head -1 | awk '{print $2}')
        ip=$(echo "$line" | grep -oE 'from [0-9a-fA-F:.]+' | awk '{print $2}')
        if [ "$user" = "root" ]; then
            printf "${RED}%-16s %-10s %-14s %s${NC}\n" "$ts" "${user:-?}" "${method:-?}" "${ip:-?}"
        else
            printf "%-16s %-10s %-14s %s\n" "$ts" "${user:-?}" "${method:-?}" "${ip:-?}"
        fi
    done

    echo ""
    local total_count
    total_count=$(echo "$raw_logs" | grep -c . || true)
    printf "日志范围内共 %s 条成功登录记录，以上显示最近 20 条（${RED}红色${NC}为 root 登录）。\n" "$total_count"
    echo ""
    read -p "按回车键继续..." dummy
}

# ---------- 开启/管理 登录记录持久化 ----------
setup_login_log_persist() {
    printf "${BLUE}===== 登录记录持久化 =====${NC}\n"

    if [ -f "$LOGIN_LOG_PERSIST" ] && [ -s "$LOGIN_LOG_PERSIST" ]; then
        local line_count
        line_count=$(wc -l < "$LOGIN_LOG_PERSIST")
        printf "${GREEN}已开启，当前持久化文件已有 %s 条记录：%s${NC}\n" "$line_count" "$LOGIN_LOG_PERSIST"
        if [ -f /etc/cron.d/vn-ssh-login-sync ]; then
            printf "定时同步任务: ${GREEN}已注册${NC} (/etc/cron.d/vn-ssh-login-sync，每 5 分钟)\n"
        else
            printf "${YELLOW}定时同步任务未注册，记录不会自动更新，是否重新注册？${NC}\n"
        fi
        echo ""
        if ! confirm_action "是否重新执行一次同步 / 重新注册 cron 任务？"; then
            read -p "按回车键继续..." dummy
            return
        fi
    else
        printf "此功能会：\n"
        printf "  1. 把系统日志里的成功登录记录另外抄一份到 %s\n" "$LOGIN_LOG_PERSIST"
        printf "  2. 注册 cron 每 5 分钟增量同步一次，原始系统日志被清理/轮转也不影响这份副本\n"
        echo ""
        if ! confirm_action "是否开启？"; then
            return
        fi
    fi

    printf "${YELLOW}正在同步已有历史记录...${NC}\n"
    sync_login_log

    local script_path
    script_path=$(realpath "$0")
    local cron_file="/etc/cron.d/vn-ssh-login-sync"
    echo "*/5 * * * * root $script_path --sync-login-log >/dev/null 2>&1" > "$cron_file"
    chmod 644 "$cron_file"

    printf "${GREEN}✔ 登录记录持久化已开启。${NC}\n"
    printf "  持久化文件: %s\n" "$LOGIN_LOG_PERSIST"
    printf "  cron 任务  : %s (每 5 分钟同步一次)\n" "$cron_file"
    read -p "按回车键继续..." dummy
}

# ---------- 主菜单 ----------
while true; do
    clear
    printf "${BLUE}===== SSH 安全加固 =====${NC}\n"
    printf "当前端口: ${GREEN}%s${NC}\n" "$SSH_PORT"
    echo "--------------------------------------"
    echo "1. 生成新的密钥对"
    echo "2. 添加公钥到本机授权"
    echo "3. 查看已授权公钥"
    echo "4. 删除指定公钥"
    echo "--------------------------------------"
    echo "5. 关闭密码登录 (仅允许密钥)"
    echo "6. 开启密码登录 (恢复)"
    echo "--------------------------------------"
    echo "7. 查看 SSH 配置摘要"
    echo "8. 修改 SSH 端口 (保留旧端口回退)"
    echo "9. 确认端口切换 (移除旧端口)"
    echo "10. 查看最近成功登录记录"
    echo "11. 开启/管理 登录记录持久化"
    echo "0. 返回主菜单"
    read -p "请选择: " choice

    case $choice in
        1) generate_key ;;
        2) add_pubkey_local ;;
        3) list_keys ;;
        4) delete_key ;;
        5) disable_password_auth ;;
        6) enable_password_auth ;;
        7) show_config ;;
        8) change_ssh_port ;;
        9) confirm_ssh_port ;;
        10) show_login_history ;;
        11) setup_login_log_persist ;;
        0) break ;;
        *) printf "${RED}无效选项${NC}\n"; sleep 1 ;;
    esac
done
