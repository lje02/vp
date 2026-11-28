#!/usr/bin/env bash
# hermes-tg.sh — 在 VPS 上部署 / 管理 Hermes Agent + Telegram 网关
#
# 功能：创建专用非 root 用户 → 安装 Hermes → 写入 Telegram/模型配置
#       → 注册 systemd 服务（开机自启、崩溃重启）→ 状态/日志/更新/卸载
#
# 用法：
#   sudo ./hermes-tg.sh            # 交互菜单
#   sudo ./hermes-tg.sh deploy     # 一键部署
#   sudo ./hermes-tg.sh config|service|status|logs|restart|update|backup|clean|uninstall

set -uo pipefail

HERMES_USER="${HERMES_USER:-hermes}"
SERVICE="hermes-gateway"
UNIT="/etc/systemd/system/${SERVICE}.service"
INSTALL_URL="https://hermes-agent.nousresearch.com/install.sh"

R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'
info() { echo -e "${G}[+]${N} $*"; }
warn() { echo -e "${Y}[!]${N} $*"; }
err()  { echo -e "${R}[x]${N} $*" >&2; }
ask()  { local p="$1" d="${2:-}" v; read -rp "$p${d:+ [$d]}: " v; echo "${v:-$d}"; }
confirm() { local v; read -rp "$1 [y/N]: " v; [[ "$v" =~ ^[Yy]$ ]]; }
pause() { read -rp "按回车继续..." _; }

need_root() {
    [[ $EUID -eq 0 ]] || { err "请用 root 或 sudo 运行"; exit 1; }
    command -v systemctl >/dev/null || { err "需要 systemd"; exit 1; }
}

home_dir() { getent passwd "$HERMES_USER" | cut -d: -f6; }
env_file() { echo "$(home_dir)/.hermes/.env"; }
as_user()  { su - "$HERMES_USER" -c "$*"; }

hermes_bin() {
    local h b; h="$(home_dir)"
    b="$(as_user 'command -v hermes' 2>/dev/null || true)"
    [[ -n "$b" && -x "$b" ]] && { echo "$b"; return; }
    for b in "$h/.local/bin/hermes" "$h/.hermes/hermes-agent/venv/bin/hermes" /usr/local/bin/hermes; do
        [[ -x "$b" ]] && { echo "$b"; return; }
    done
    return 1
}

# ---------- .env 读写 ----------
set_env() {   # set_env KEY VALUE
    local f tmp; f="$(env_file)"
    mkdir -p "$(dirname "$f")"; touch "$f"
    tmp="$(mktemp)"
    grep -v "^$1=" "$f" > "$tmp" || true
    printf '%s=%s\n' "$1" "$2" >> "$tmp"
    install -m 600 -o "$HERMES_USER" -g "$HERMES_USER" "$tmp" "$f"
    rm -f "$tmp"
    chown -R "$HERMES_USER:$HERMES_USER" "$(dirname "$f")"
}
unset_env() {
    local f tmp; f="$(env_file)"; [[ -f "$f" ]] || return 0
    tmp="$(mktemp)"; grep -v "^$1=" "$f" > "$tmp" || true
    install -m 600 -o "$HERMES_USER" -g "$HERMES_USER" "$tmp" "$f"; rm -f "$tmp"
}
get_env() { local f; f="$(env_file)"; [[ -f "$f" ]] && grep "^$1=" "$f" | head -n1 | cut -d= -f2-; }

# ---------- 1. 用户 & 依赖 ----------
ensure_user() {
    if ! id "$HERMES_USER" &>/dev/null; then
        info "创建专用用户 $HERMES_USER"
        useradd -m -s /bin/bash "$HERMES_USER" || { err "创建用户失败"; return 1; }
    fi
    if command -v apt-get >/dev/null; then
        info "安装基础依赖 (curl git ca-certificates)"
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl git ca-certificates >/dev/null
    else
        warn "非 apt 系统，请确认已安装 curl / git"
    fi
}

# ---------- 2. 安装 Hermes ----------
install_hermes() {
    local tmp=/tmp/hermes-install.sh
    info "下载官方安装脚本"
    curl -fsSL "$INSTALL_URL" -o "$tmp" || { err "下载失败，检查网络"; return 1; }
    chmod 755 "$tmp"
    if confirm "先查看安装脚本内容再执行？（推荐）"; then
        ${PAGER:-less} "$tmp"
        confirm "确认执行？" || { warn "已取消"; return 1; }
    fi
    info "以 $HERMES_USER 身份安装（若有交互提示，按提示回答即可）"
    as_user "bash $tmp"
    rm -f "$tmp"
    if hermes_bin >/dev/null; then
        info "Hermes 已安装：$(hermes_bin)"
    else
        err "未找到 hermes 可执行文件，请检查上面的安装输出"; return 1
    fi
}

# ---------- 3. 配置 ----------
valid_token() { [[ "$1" =~ ^[0-9]+:[A-Za-z0-9_-]{20,}$ ]]; }
valid_ids()   { [[ "$1" =~ ^[0-9]+(,[0-9]+)*$ ]]; }

configure() {
    id "$HERMES_USER" &>/dev/null || { err "用户 $HERMES_USER 不存在，请先部署"; return 1; }
    echo -e "${C}—— Telegram ——${N}"
    echo "Bot Token：在 Telegram 找 @BotFather 发 /newbot 获得"
    echo "User ID  ：给 @userinfobot 发消息获得（纯数字，多个用逗号分隔）"
    local token ids
    while true; do
        read -rsp "Bot Token（输入不回显，留空保持现有）: " token; echo
        [[ -z "$token" ]] && { token="$(get_env TELEGRAM_BOT_TOKEN)"; [[ -n "$token" ]] && break; continue; }
        valid_token "$token" || { err "Token 格式不对"; continue; }
        if curl -fsS --max-time 10 "https://api.telegram.org/bot${token}/getMe" >/dev/null 2>&1; then
            info "Token 验证通过"
        else
            warn "Token 验证失败（可能是网络访问不了 Telegram API，或 Token 错误）"
            confirm "仍然使用？" || continue
        fi
        break
    done
    while true; do
        ids="$(ask "允许使用的 Telegram User ID" "$(get_env TELEGRAM_ALLOWED_USERS)")"
        valid_ids "$ids" && break
        err "必须是纯数字，多个用逗号分隔，例如 123456789,987654321"
    done
    set_env TELEGRAM_BOT_TOKEN "$token"
    set_env TELEGRAM_ALLOWED_USERS "$ids"
    unset_env GATEWAY_ALLOW_ALL_USERS   # 安全：确保不开放给所有人
    info "Telegram 配置已写入 $(env_file)（权限 600）"

    echo -e "${C}—— 模型 ——${N}"
    echo "1) OpenRouter API Key"
    echo "2) 自定义 OpenAI 兼容端点（base_url + key）"
    echo "3) 稍后自己配（hermes model / hermes setup --portal）"
    case "$(ask "选择" 3)" in
        1) local k; read -rsp "OPENROUTER_API_KEY: " k; echo
           [[ -n "$k" ]] && set_env OPENROUTER_API_KEY "$k" ;;
        2) local u k; u="$(ask "OPENAI_BASE_URL")"; read -rsp "OPENAI_API_KEY: " k; echo
           [[ -n "$u" && -n "$k" ]] && { set_env OPENAI_BASE_URL "$u"; set_env OPENAI_API_KEY "$k"; } ;;
        *) warn "请稍后切到 $HERMES_USER 运行 hermes model 或 hermes setup --portal" ;;
    esac
}

# ---------- 4. systemd 服务 ----------
install_service() {
    local bin h; bin="$(hermes_bin)" || { err "找不到 hermes，请先安装"; return 1; }
    h="$(home_dir)"
    cat > "$UNIT" <<EOF
[Unit]
Description=Hermes Agent Gateway (Telegram)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${HERMES_USER}
WorkingDirectory=${h}
Environment=HOME=${h}
Environment=PATH=${h}/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=${bin} gateway run
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$SERVICE"
    sleep 3
    if systemctl is-active --quiet "$SERVICE"; then
        info "服务已启动，去 Telegram 给你的 Bot 发条消息测试"
    else
        err "服务未能启动，查看日志：journalctl -u $SERVICE -n 50 --no-pager"
        return 1
    fi
}

# ---------- 其他操作 ----------
do_status()  { systemctl status "$SERVICE" --no-pager -l 2>&1 | head -n 20
               echo; echo "允许的用户：$(get_env TELEGRAM_ALLOWED_USERS)"
               echo "Token：$( [[ -n "$(get_env TELEGRAM_BOT_TOKEN)" ]] && echo 已配置 || echo 未配置 )"; }
do_logs()    { journalctl -u "$SERVICE" -n 80 -f --no-pager; }
do_restart() { systemctl restart "$SERVICE" && info "已重启"; }

do_update() {
    install_hermes && do_restart
}

do_backup() {
    local h dest; h="$(home_dir)"
    [[ -d "$h/.hermes" ]] || { err "找不到 $h/.hermes，没有可备份的数据"; return 1; }
    dest="/root/hermes-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    ( umask 077; tar -czf "$dest" -C "$h" .hermes ) || { err "备份失败"; return 1; }
    info "已备份到 $dest（含 Token / API Key，权限 600，请妥善保管）"
}

do_clean() {
    local h; h="$(home_dir)"
    echo -e "${C}—— 当前占用 ——${N}"
    [[ -n "$h" ]] && du -sh "$h/.hermes" "$h/.cache" 2>/dev/null
    journalctl -u "$SERVICE" --disk-usage 2>/dev/null
    echo
    echo "将执行（不会动配置、.env 和记忆数据）："
    echo "  - 清理 ${SERVICE} 超过 7 天的 journal 日志"
    echo "  - 删除 /tmp 下残留的安装脚本"
    echo "  - 清理 $HERMES_USER 的 apt/pip/uv 下载缓存（~/.cache 下，若存在）"
    confirm "继续？" || return 0
    journalctl --vacuum-time=7d >/dev/null 2>&1 && info "日志已清理"
    rm -f /tmp/hermes-install.sh
    if [[ -n "$h" && -d "$h/.cache" ]]; then
        rm -rf "$h/.cache/pip" "$h/.cache/uv" 2>/dev/null
        info "已清理 ~/.cache 下的 pip/uv 缓存"
    fi
    info "清理完成"
}

do_uninstall() {
    warn "将停止并删除 systemd 服务（默认保留用户和 ~/.hermes 数据）"
    confirm "继续？" || return 0
    if id "$HERMES_USER" &>/dev/null && confirm "卸载前先备份 ~/.hermes？"; then
        do_backup || confirm "备份失败，仍然继续？" || return 1
    fi
    systemctl disable --now "$SERVICE" 2>/dev/null
    rm -f "$UNIT" /tmp/hermes-install.sh
    systemctl daemon-reload
    info "服务已移除"
    if id "$HERMES_USER" &>/dev/null; then
        if confirm "同时删除用户 $HERMES_USER 及其全部数据（含记忆、配置、Hermes 程序）？"; then
            userdel -r "$HERMES_USER" && info "用户已删除"
        fi
    fi
}

deploy() {
    ensure_user      || return 1
    install_hermes   || return 1
    configure        || return 1
    install_service
}

menu() {
    while true; do
        clear
        echo -e "${C}===== Hermes + Telegram 管理 =====${N}"
        echo " 1) 一键部署（用户+安装+配置+服务）"
        echo " 2) 修改 Telegram / 模型配置"
        echo " 3) 安装/重装 systemd 服务"
        echo " 4) 查看状态"
        echo " 5) 查看日志（Ctrl+C 退出）"
        echo " 6) 重启服务"
        echo " 7) 更新 Hermes"
        echo " 8) 备份 ~/.hermes"
        echo " 9) 清理日志/缓存"
        echo "10) 卸载"
        echo " 0) 退出"
        case "$(ask "选择")" in
            1) deploy; pause ;;
            2) configure && do_restart; pause ;;
            3) install_service; pause ;;
            4) do_status; pause ;;
            5) do_logs ;;
            6) do_restart; pause ;;
            7) do_update; pause ;;
            8) do_backup; pause ;;
            9) do_clean; pause ;;
            10) do_uninstall; pause ;;
            0) exit 0 ;;
        esac
    done
}

need_root
case "${1:-menu}" in
    deploy)    deploy ;;
    config)    configure && do_restart ;;
    service)   install_service ;;
    status)    do_status ;;
    logs)      do_logs ;;
    restart)   do_restart ;;
    update)    do_update ;;
    backup)    do_backup ;;
    clean)     do_clean ;;
    uninstall) do_uninstall ;;
    menu)      menu ;;
    *) echo "用法: $0 [deploy|config|service|status|logs|restart|update|backup|clean|uninstall]"; exit 1 ;;
esac
