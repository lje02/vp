#!/usr/bin/env bash
# ============================================================
# pg-redis-shared.sh — 共享 PostgreSQL 18 + Redis（仅监听 WireGuard 网口）
#
# 用法:
#   ./pg-redis-shared.sh                            # 交互菜单
#   ./pg-redis-shared.sh deploy  [DIR] [WG_IP] [db|redis|all]
#   ./pg-redis-shared.sh update  [DIR] [db|redis|all] [--backup] [--encrypt]  # --backup: 拉取镜像前先做全量备份（失败则中止更新）；--encrypt: 备份加密
#   ./pg-redis-shared.sh add-db  [DIR] <DB> <USER> [PW]
#   ./pg-redis-shared.sh del-db  [DIR] <DB> <USER>
#   ./pg-redis-shared.sh clear-db [DIR] <DB>
#   ./pg-redis-shared.sh list-db [DIR]
#   ./pg-redis-shared.sh passwd  [DIR] <USER> [NEW_PW]
#   ./pg-redis-shared.sh backup  [DIR] [DEST] [--webdav] [--encrypt]  # 全量备份（.env+配置+pg_dumpall+Redis数据 → 单个 tar.gz；--webdav 同时上传远端，--encrypt 额外加密；成功后本地只保留最近 LOCAL_BACKUP_KEEP 份，默认 3，0=不清理）
#   ./pg-redis-shared.sh restore [DIR] <备份tar.gz[.enc]|webdav://文件名> [解密密钥]  # 全量恢复（webdav://文件名 = WEBDAV_REMOTE_DIR 下的文件；含 / 则视为相对 WEBDAV_URL 的路径）
#   ./pg-redis-shared.sh tune-db    [DIR]               # 查看/调整 PostgreSQL 性能参数
#   ./pg-redis-shared.sh tune-redis [DIR]               # 查看/调整 Redis 性能参数
#   ./pg-redis-shared.sh webdav-config [DIR]            # 配置/测试 WebDAV 远端（WEBDAV_URL/USER/PASSWORD/REMOTE_DIR）
#   ./pg-redis-shared.sh webdav-list [DIR]              # 列出 WebDAV 远端上的备份文件
#   ./pg-redis-shared.sh status  [DIR]
#   ./pg-redis-shared.sh start   [DIR] [db|redis]
#   ./pg-redis-shared.sh stop    [DIR] [db|redis]
#   ./pg-redis-shared.sh logs    [DIR] <db|redis>
#   ./pg-redis-shared.sh help
#
# 与 MariaDB 版本(infra-shared.sh)的关键差异：
#   - PostgreSQL 角色(role)是集群全局的，不像 MariaDB 那样 'user'@'host' 按来源
#     主机分别建号。网络级访问控制改由 pg_hba.conf 按 WireGuard/Docker 网段限制，
#     换机后只需重写 pg_hba.conf + reload，无需逐个账号重新授权。
#   - 全量备份/恢复用 pg_dumpall（含角色+全部库），而非 mysqldump --all-databases。
# ============================================================
set -euo pipefail
export LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

# ── 默认值 ──────────────────────────────────────────────────
DEFAULT_DIR="${BASE_DIR:-/srv}/pg-infra"
WG_IFACE="${WG_IFACE:-wg0}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
REDIS_PORT="${REDIS_PORT:-6379}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:18-alpine}"
REDIS_IMAGE="${REDIS_IMAGE:-redis:7-alpine}"

# ── 输出 ────────────────────────────────────────────────────
_c()     { printf "\033[%sm%s\033[0m\n" "$1" "$2"; }
log()    { _c "32"   "[OK]  $*"; }
info()   { _c "36"   "[..]  $*"; }
warn()   { _c "33"   "[!!]  $*"; }
error()  { _c "31"   "[EE]  $*"; exit 1; }
header() { echo; _c "1;34" "══ $* ══"; }

# ── 临时目录兜底清理 ──────────────────────────────────────────
_TMP_DIRS=()
_register_tmp() { [[ -n "$1" ]] && _TMP_DIRS+=("$1"); }
_cleanup_tmp() {
    local d
    for d in "${_TMP_DIRS[@]:-}"; do
        [[ -n "$d" && ( -d "$d" || -f "$d" ) ]] && rm -rf "$d" 2>/dev/null
    done
}
trap _cleanup_tmp EXIT

# ── 菜单安全调用包装 ─────────────────────────────────────────
_menu_run() {
    local _exit_code=0
    (
        set -euo pipefail
        "$@"
    ) || _exit_code=$?
    return $_exit_code
}

# ── 工具函数 ─────────────────────────────────────────────────
randpw() {
    local p
    p=$(timeout 5 sh -c "LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32" 2>/dev/null) \
    || p=$(openssl rand -base64 48 | LC_ALL=C tr -dc 'A-Za-z0-9' | head -c 32)
    printf '%s' "$p"
}

get_wg_ip() {
    local ip
    ip=$(ip addr show "${WG_IFACE}" 2>/dev/null \
        | awk '/inet /{gsub(/\/.*/, "", $2); print $2; exit}')
    [[ -n "$ip" ]] || error "无法获取 ${WG_IFACE} IP，请确认 WireGuard 已启动"
    echo "$ip"
}

_check_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || error "IP 格式无效: '${ip}'"
    local IFS='.'; read -ra o <<< "$ip"
    for s in "${o[@]}"; do (( s <= 255 )) || error "IP 段超范围: '${ip}'"; done
}

_check_id()  {
    [[ "$1" =~ ^[A-Za-z_][A-Za-z0-9_]{0,63}$ ]] \
        || error "$2 只能以字母/下划线开头，含字母/数字/下划线，长度 1-64，实际: '$1'"
}

_check_pw() {
    # db_sql()/cmd_add_db() 等直接把密码拼进 SQL 字符串字面量，
    # 依赖这里禁止单引号和反斜杠来防止 SQL 注入。修改此校验前必须确认
    # 所有拼接点都已改为参数化/转义，否则会重新引入注入风险。
    [[ -n "$1" ]]      || error "$2 不能为空"
    [[ "$1" != *"'"* ]] || error "$2 不能含单引号"
    [[ "$1" != *"\\"* ]] || error "$2 不能含反斜杠"
    [[ ${#1} -ge 8 ]]  || error "$2 至少 8 个字符"
}

load_env() {
    [[ -f "$1/.env" ]] || error ".env 不存在: $1/.env"
    chmod 600 "$1/.env" 2>/dev/null || true
    local _ALLOWED_KEYS='WG_IP|POSTGRES_PASSWORD|POSTGRES_DATABASE|POSTGRES_APP_USER|POSTGRES_APP_PASSWORD|REDIS_PASSWORD|DEPLOY_DB|DEPLOY_REDIS|POSTGRES_IMAGE|REDIS_IMAGE|BACKUP_ENC_KEY|WEBDAV_URL|WEBDAV_USER|WEBDAV_PASSWORD|WEBDAV_REMOTE_DIR|WEBDAV_KEEP|LOCAL_BACKUP_KEEP|POSTGRES_SHARED_BUFFERS|POSTGRES_EFFECTIVE_CACHE|POSTGRES_MAINTENANCE_WORK_MEM|POSTGRES_WORK_MEM|POSTGRES_MAX_CONNECTIONS|POSTGRES_WAL_BUFFERS|REDIS_MAXMEMORY'
    local key val line
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            key="${BASH_REMATCH[1]}"
            val="${BASH_REMATCH[2]}"
            if [[ "$key" =~ ^($_ALLOWED_KEYS)$ ]]; then
                printf -v "$key" '%s' "$val"
                export "$key"
            fi
        fi
    done < "$1/.env"
}

_env_set() {   # DIR KEY VAL
    local envfile="$1/.env" key="$2" val="$3" tmp
    tmp="${envfile}.tmp.$$"
    if grep -q "^${key}=" "$envfile" 2>/dev/null; then
        _ENVSET_V="$val" awk -v k="$key" '
            BEGIN { replaced=0; v=ENVIRON["_ENVSET_V"] }
            /^[[:space:]]*#/ { print; next }
            $0 ~ "^" k "=" { print k "=" v; replaced=1; next }
            { print }
            END { if (!replaced) print k "=" v }
        ' "$envfile" > "$tmp" && mv "$tmp" "$envfile"
    else
        printf '%s=%s\n' "$key" "$val" >> "$envfile"
    fi
}

_check_dir_safe() {   # DIR — 防止误传危险路径后被后续 rm -rf "$dir/xxx" 误伤
    local d="$1"
    [[ -n "$d" ]] || error "DIR 不能为空"
    case "$d" in
        /|/root|/root/|/home|/home/|/etc|/etc/|/var|/var/|/usr|/usr/)
            error "DIR 不能是系统关键路径: '${d}'，请指定专用的业务目录" ;;
    esac
}

_svc_exists() {   # DIR SVC
    grep -q "^  $2:" "$1/docker-compose.yml" 2>/dev/null
}

# Docker 网段 CIDR（用于 pg_hba.conf）。
#
# 之前这里探测的是本机（pg-infra 所在机器）自己的 docker 网络子网，但真正
# 需要放行的是各个 app 节点自己机器上的 docker bridge 网段——那些节点的
# docker build/compose 会各自随机分配子网（默认在 172.17.0.0/16 ~
# 172.31.0.0/16 之间跳），跟 pg-infra 本机的网络毫无关系，探测本机网段
# 对远程节点没有任何意义，之前也确实因为这个多次踩坑（子网对不上、
# Docker 重启后又漂移）。
#
# 直接放行 Docker 默认分配池覆盖的整个 172.16.0.0/12（即 172.16.0.0 ~
# 172.31.255.255），不用再逐个节点探测/登记具体子网。这个范围本来就是
# IANA 保留的私有地址段，只要 WireGuard mesh 本身没把外部流量放进来，
# 放宽这段不会引入额外的公网风险。
_docker_subnet_cidr() {
    echo "172.16.0.0/12"
}


# WireGuard 网段 CIDR，假定 /24（与 MariaDB 版本 'IP%' 的假设一致）
_wg_subnet_cidr() {
    local ip="$1"
    echo "${ip%.*}.0/24"
}

# ── 依赖检查 ─────────────────────────────────────────────────
_check_deps() {
    local missing=()
    for cmd in docker ip awk grep tar; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if command -v docker >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then
        missing+=("docker compose (插件)")
    fi
    if [[ ${#missing[@]} -gt 0 ]]; then
        error "缺少依赖命令: ${missing[*]}\n请安装后再运行本脚本。\nDocker 安装参考: curl -fsSL https://get.docker.com | sudo bash"
    fi
}

compose_run() { local d="$1"; shift
    docker compose --project-directory "$d" -f "$d/docker-compose.yml" --env-file "$d/.env" "$@"
}

db_exec() { local d="$1"; shift
    compose_run "$d" exec -T db psql -U postgres -v ON_ERROR_STOP=1 "$@"
}

db_sql() {   # DIR SQL
    compose_run "$1" exec -T \
        db psql -U postgres -v ON_ERROR_STOP=1 < <(printf '%s\n' "$2")
}

db_sql_on() {   # DIR DB SQL — 直接指定目标库
    compose_run "$1" exec -T \
        db psql -U postgres -v ON_ERROR_STOP=1 -d "$2" < <(printf '%s\n' "$3")
}

# ════════════════════════════════════════════════════════════
# 配置文件生成
# ════════════════════════════════════════════════════════════
# ── 自动计算调优默认值 ───────────────────────────────────────
# 输出变量：_AT_SHARED_BUFFERS _AT_EFFECTIVE_CACHE _AT_MAINTENANCE_WORK_MEM
#          _AT_WORK_MEM _AT_MAX_CONN _AT_WAL_BUFFERS _AT_REDIS_MEM
_auto_tune() {
    local total_kb; total_kb=$(awk '/^MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
    local total_mb=$(( total_kb / 1024 ))
    (( total_mb < 512 )) && total_mb=512

    # shared_buffers = 25% 物理内存，最小 128M，最大 8192M
    local sb=$(( total_mb / 4 ))
    (( sb <  128  )) && sb=128
    (( sb > 8192  )) && sb=8192
    _AT_SHARED_BUFFERS="${sb}MB"

    # effective_cache_size = 50% 物理内存，最小 256M
    local ecs=$(( total_mb / 2 ))
    (( ecs < 256 )) && ecs=256
    _AT_EFFECTIVE_CACHE="${ecs}MB"

    # maintenance_work_mem = 6.25% 物理内存，最小 64M，最大 2048M
    local mwm=$(( total_mb * 625 / 10000 ))
    (( mwm <   64 )) && mwm=64
    (( mwm > 2048 )) && mwm=2048
    _AT_MAINTENANCE_WORK_MEM="${mwm}MB"

    # max_connections 按内存档位梯度
    if   (( total_mb >= 16384 )); then _AT_MAX_CONN=400
    elif (( total_mb >=  8192 )); then _AT_MAX_CONN=300
    elif (( total_mb >=  4096 )); then _AT_MAX_CONN=200
    elif (( total_mb >=  2048 )); then _AT_MAX_CONN=100
    else                               _AT_MAX_CONN=50
    fi

    # work_mem ≈ (25% 物理内存) / max_connections，最小 4M，最大 256M
    local wm=$(( total_mb / 4 / _AT_MAX_CONN ))
    (( wm <   4 )) && wm=4
    (( wm > 256 )) && wm=256
    _AT_WORK_MEM="${wm}MB"

    # wal_buffers = shared_buffers / 32，最小 4M，最大 64M
    local wb=$(( sb / 32 ))
    (( wb <  4 )) && wb=4
    (( wb > 64 )) && wb=64
    _AT_WAL_BUFFERS="${wb}MB"

    # redis maxmemory = 15% 物理内存，最小 128M，最大 4096M
    local rm=$(( total_mb * 15 / 100 ))
    (( rm <  128  )) && rm=128
    (( rm > 4096  )) && rm=4096
    _AT_REDIS_MEM="${rm}mb"
}

# 生成 pg_hba.conf（按 WireGuard / Docker 网段限制访问），并在服务已运行时 reload
_write_pg_hba() {
    local dir="$1"
    load_env "$dir"
    mkdir -p "$dir/pg-conf"
    local wg_cidr; wg_cidr=$(_wg_subnet_cidr "${WG_IP}")
    local docker_cidr; docker_cidr=$(_docker_subnet_cidr)
    cat > "$dir/pg-conf/pg_hba.conf" <<HBA
# 自动生成，勿手动编辑；deploy/restore 时会按当前 WG_IP 重写
local   all             all                                     scram-sha-256
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ${wg_cidr}               scram-sha-256
host    all             all             ${docker_cidr}           scram-sha-256
HBA
    log "pg_hba.conf 已生成: WG网段=${wg_cidr}  Docker网段=${docker_cidr}"
    if _svc_exists "$dir" "db" 2>/dev/null; then
        compose_run "$dir" exec -T db \
            psql -U postgres -c "SELECT pg_reload_conf();" >/dev/null 2>&1 \
            && log "已 reload PostgreSQL 配置（pg_hba 生效，无需重启）" \
            || true
    fi
}

_write_redis_conf() {
    local dir="$1"
    mkdir -p "$dir/redis-conf"
    _auto_tune
    load_env "$dir" 2>/dev/null || true
    local maxmem="${REDIS_MAXMEMORY:-${_AT_REDIS_MEM}}"
    cat > "$dir/redis-conf/redis.conf" <<CONF
bind 0.0.0.0
port ${REDIS_PORT}
requirepass ${REDIS_PASSWORD}
save 900 1
save 300 10
save 60 10000
appendonly yes
appendfsync everysec
maxmemory ${maxmem}
maxmemory-policy allkeys-lru
loglevel notice
logfile ""
CONF
    log "Redis 配置: maxmemory=${maxmem}"
}

_write_compose() {
    load_env "$1"
    local has_db="${DEPLOY_DB:-0}" has_redis="${DEPLOY_REDIS:-0}"
    _auto_tune
    local sb="${POSTGRES_SHARED_BUFFERS:-$_AT_SHARED_BUFFERS}"
    local ecs="${POSTGRES_EFFECTIVE_CACHE:-$_AT_EFFECTIVE_CACHE}"
    local mwm="${POSTGRES_MAINTENANCE_WORK_MEM:-$_AT_MAINTENANCE_WORK_MEM}"
    local wm="${POSTGRES_WORK_MEM:-$_AT_WORK_MEM}"
    local conn="${POSTGRES_MAX_CONNECTIONS:-$_AT_MAX_CONN}"
    local wb="${POSTGRES_WAL_BUFFERS:-$_AT_WAL_BUFFERS}"

    : > "$1/docker-compose.yml"
    echo "services:" >> "$1/docker-compose.yml"

    [[ "$has_db" == "1" ]] && cat >> "$1/docker-compose.yml" <<YAML

  db:
    image: ${POSTGRES_IMAGE}
    restart: unless-stopped
    environment:
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
      PGPASSWORD: \${POSTGRES_PASSWORD}
      PGDATA: /var/lib/postgresql/data/pgdata
    volumes:
      - ./db:/var/lib/postgresql/data
      - ./pg-conf/pg_hba.conf:/etc/postgresql-custom/pg_hba.conf:ro
    command:
      - postgres
      - -c
      - hba_file=/etc/postgresql-custom/pg_hba.conf
      - -c
      - listen_addresses=*
      - -c
      - shared_buffers=${sb}
      - -c
      - effective_cache_size=${ecs}
      - -c
      - maintenance_work_mem=${mwm}
      - -c
      - work_mem=${wm}
      - -c
      - max_connections=${conn}
      - -c
      - wal_buffers=${wb}
      - -c
      - checkpoint_completion_target=0.9
      - -c
      - random_page_cost=1.1
      - -c
      - effective_io_concurrency=200
    ports:
      - "\${WG_IP}:${POSTGRES_PORT}:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s
YAML

    [[ "$has_redis" == "1" ]] && cat >> "$1/docker-compose.yml" <<YAML

  redis:
    image: ${REDIS_IMAGE}
    restart: unless-stopped
    environment:
      REDISCLI_AUTH: \${REDIS_PASSWORD}
    volumes:
      - ./redis:/data
      - ./redis-conf/redis.conf:/etc/redis/redis.conf:ro
    command: redis-server /etc/redis/redis.conf
    ports:
      - "\${WG_IP}:${REDIS_PORT}:${REDIS_PORT}"
    healthcheck:
      test: ["CMD", "redis-cli", "-h", "127.0.0.1", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
YAML
}

# ════════════════════════════════════════════════════════════
# deploy [DIR] [WG_IP] [db|redis|all]
# update [DIR] [db|redis|all]
# ════════════════════════════════════════════════════════════
cmd_deploy() {
    [[ $EUID -eq 0 ]] || error "需要 root 权限"
    local dir="${1:-$DEFAULT_DIR}" wg_ip="${2:-$(get_wg_ip)}" target="${3:-all}"
    _check_ipv4 "$wg_ip"
    ip link show "${WG_IFACE}" &>/dev/null || error "${WG_IFACE} 不存在，请先启动 WireGuard"

    local do_db=0 do_redis=0
    case "$target" in
        db)    do_db=1 ;;
        redis) do_redis=1 ;;
        all)   do_db=1; do_redis=1 ;;
        *)     error "target 须为 db / redis / all" ;;
    esac

    mkdir -p "$dir"
    [[ -f "$dir/.env" ]] || { cat > "$dir/.env" <<EOF
# 共享基础设施凭据
WG_IP=${wg_ip}
EOF
        chmod 600 "$dir/.env"; }
    chmod 600 "$dir/.env"
    _env_set "$dir" "WG_IP" "$wg_ip"

    if (( do_db )); then
        mkdir -p "$dir/db" "$dir/backup"
        if ! grep -q "^POSTGRES_PASSWORD=" "$dir/.env" 2>/dev/null; then
            local _root_pw _app_pw
            _root_pw=$(randpw)
            _app_pw=$(randpw)
            [[ -n "$_root_pw" && -n "$_app_pw" ]] || error "随机密码生成失败，请检查 openssl 或 /dev/urandom"
            printf "POSTGRES_PASSWORD=%s\nPOSTGRES_DATABASE=gallery\nPOSTGRES_APP_USER=gallery\nPOSTGRES_APP_PASSWORD=%s\n" \
                "$_root_pw" "$_app_pw" >> "$dir/.env"
            log "PostgreSQL 凭据已生成"
        else
            warn "PostgreSQL 凭据已存在，跳过生成"
        fi
        _env_set "$dir" "DEPLOY_DB" "1"
        grep -q "^POSTGRES_IMAGE=" "$dir/.env" 2>/dev/null || _env_set "$dir" "POSTGRES_IMAGE" "$POSTGRES_IMAGE"
        _write_pg_hba "$dir"
    fi

    if (( do_redis )); then
        mkdir -p "$dir/redis"
        if ! grep -q "^REDIS_PASSWORD=" "$dir/.env" 2>/dev/null; then
            local _redis_pw
            _redis_pw=$(randpw)
            [[ -n "$_redis_pw" ]] || error "随机密码生成失败，请检查 openssl 或 /dev/urandom"
            echo "REDIS_PASSWORD=${_redis_pw}" >> "$dir/.env"
            log "Redis 凭据已生成"
        else
            warn "Redis 凭据已存在，跳过生成"
        fi
        _env_set "$dir" "DEPLOY_REDIS" "1"
        grep -q "^REDIS_IMAGE=" "$dir/.env" 2>/dev/null || _env_set "$dir" "REDIS_IMAGE" "$REDIS_IMAGE"
        load_env "$dir"
        _write_redis_conf "$dir"
    fi

    _write_compose "$dir"

    sysctl -w vm.overcommit_memory=1 >/dev/null 2>&1 || true
    grep -q 'vm.overcommit_memory' /etc/sysctl.conf \
        || echo 'vm.overcommit_memory = 1' >> /etc/sysctl.conf

    local svcs=()
    (( do_db ))    && svcs+=("db")
    (( do_redis )) && svcs+=("redis")

    header "启动: ${svcs[*]}"
    compose_run "$dir" up -d --wait "${svcs[@]}" 2>&1 \
        || error "docker compose up 失败"

    if (( do_db )); then
        load_env "$dir"
        header "初始化应用库/用户: ${POSTGRES_DATABASE} / ${POSTGRES_APP_USER}"
        _ensure_role "$dir" "${POSTGRES_APP_USER}" "${POSTGRES_APP_PASSWORD}"
        _ensure_database "$dir" "${POSTGRES_DATABASE}" "${POSTGRES_APP_USER}"
        # 网络访问由 pg_hba.conf 按 WG/Docker 网段控制，pg_hba 已在上面写好，此处 reload 一次确保生效
        compose_run "$dir" exec -T db \
            psql -U postgres -c "SELECT pg_reload_conf();" >/dev/null 2>&1 || true
    fi

    compose_run "$dir" ps
    log "部署完成"
    _print_creds "$dir"
}

cmd_update() {
    [[ $EUID -eq 0 ]] || error "需要 root 权限"
    local do_backup=0 do_encrypt=0 _pos=() _a
    for _a in "$@"; do
        case "$_a" in
            --backup)  do_backup=1 ;;
            --encrypt) do_encrypt=1 ;;
            *) _pos+=("$_a") ;;
        esac
    done
    (( do_encrypt && ! do_backup )) && warn "--encrypt 仅在配合 --backup 时生效，本次忽略"
    local dir="${_pos[0]:-$DEFAULT_DIR}" target="${_pos[1]:-all}"
    load_env "$dir"

    local svcs=()
    case "$target" in
        db)    _svc_exists "$dir" "db"    || error "PostgreSQL 未部署"; svcs=("db") ;;
        redis) _svc_exists "$dir" "redis" || error "Redis 未部署";      svcs=("redis") ;;
        all)
            _svc_exists "$dir" "db"    && svcs+=("db")
            _svc_exists "$dir" "redis" && svcs+=("redis")
            [[ ${#svcs[@]} -gt 0 ]] || error "没有已部署的服务"
            ;;
        *) error "target 须为 db / redis / all" ;;
    esac

    if (( do_backup )); then
        header "更新前全量备份"
        # 备份失败会直接中止（cmd_backup 内部 error → exit），此时尚未拉取/重建任何镜像
        if (( do_encrypt )); then
            cmd_backup "$dir" "${dir}/backup" --encrypt
        else
            cmd_backup "$dir" "${dir}/backup"
        fi
    fi

    header "拉取最新镜像: ${svcs[*]}"
    compose_run "$dir" pull "${svcs[@]}"

    for svc in "${svcs[@]}"; do
        info "重建 ${svc}..."
        compose_run "$dir" up -d --wait --no-deps "$svc" 2>&1 \
            || error "${svc} 重建失败"
        log "${svc} 已更新"
    done

    compose_run "$dir" ps
    log "更新完成"
}

# ── 角色/库创建（幂等） ──────────────────────────────────────
# CREATE DATABASE 不能在事务块内执行，因此不能包进 DO $$ ... $$；
# 角色的存在性判断可以放进 DO 块（用 EXECUTE format(...) 动态执行）。
_ensure_role() {   # DIR USER PW
    local dir="$1" user="$2" pw="$3"
    db_sql "$dir" "
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${user}') THEN
    EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', '${user}', '${pw}');
  ELSE
    EXECUTE format('ALTER ROLE %I PASSWORD %L', '${user}', '${pw}');
  END IF;
END
\$\$;"
}

_ensure_database() {   # DIR DB OWNER_USER
    local dir="$1" db="$2" owner="$3"
    local exists
    exists=$(db_exec "$dir" -tAc "SELECT 1 FROM pg_database WHERE datname='${db}';" 2>/dev/null | tr -d '[:space:]')
    if [[ "$exists" != "1" ]]; then
        db_exec "$dir" -c "CREATE DATABASE \"${db}\" OWNER \"${owner}\" ENCODING 'UTF8';"
    else
        db_exec "$dir" -c "ALTER DATABASE \"${db}\" OWNER TO \"${owner}\";" 2>/dev/null || true
    fi
    db_exec "$dir" -c "GRANT ALL PRIVILEGES ON DATABASE \"${db}\" TO \"${owner}\";"
    db_sql_on "$dir" "$db" "
GRANT ALL ON SCHEMA public TO \"${owner}\";
ALTER DEFAULT PRIVILEGES FOR ROLE \"${owner}\" IN SCHEMA public GRANT ALL ON TABLES TO \"${owner}\";
ALTER DEFAULT PRIVILEGES FOR ROLE \"${owner}\" IN SCHEMA public GRANT ALL ON SEQUENCES TO \"${owner}\";"
    log "库: ${db}  Owner: ${owner}"
}

# ── 凭据打印 ─────────────────────────────────────────────────
_print_creds() {
    load_env "$1"
    echo ""
    echo "┌─── 连接信息 ───────────────────────────────────────────"
    [[ "${DEPLOY_DB:-0}"    == "1" ]] && printf "│  [PostgreSQL] %s:%s  用户:%s  库:%s\n│  密码: %s\n│  超级用户: postgres  密码: %s\n│\n" \
        "$WG_IP" "$POSTGRES_PORT" "$POSTGRES_APP_USER" "$POSTGRES_DATABASE" "$POSTGRES_APP_PASSWORD" "$POSTGRES_PASSWORD"
    [[ "${DEPLOY_REDIS:-0}" == "1" ]] && printf "│  [Redis]      %s:%s\n│  密码: %s\n│\n" \
        "$WG_IP" "$REDIS_PORT" "$REDIS_PASSWORD"
    echo "│  凭据文件: $1/.env"
    echo "└────────────────────────────────────────────────────────"
    warn "请通过 WireGuard 安全传输 .env 到各节点"
}

# ════════════════════════════════════════════════════════════
# 数据库管理
# ════════════════════════════════════════════════════════════
cmd_add_db() {
    local dir="${1:-$DEFAULT_DIR}" db="${2:?用法: add-db [DIR] <DB> <USER> [PW]}" user="${3:?}" pw="${4:-$(randpw)}"
    _check_id "$db" "数据库名"; _check_id "$user" "用户名"; _check_pw "$pw" "密码"
    _svc_exists "$dir" "db" || error "PostgreSQL 未部署"
    load_env "$dir"
    header "新建数据库: ${db} / 用户: ${user}"
    _ensure_role "$dir" "$user" "$pw"
    _ensure_database "$dir" "$db" "$user"
    log "库: ${db}  用户: ${user}  密码: ${pw}  主机: ${WG_IP}:${POSTGRES_PORT:-5432}"
}

cmd_del_db() {
    local dir="${1:-$DEFAULT_DIR}" db="${2:?用法: del-db [DIR] <DB> <USER>}" user="${3:?}"
    _check_id "$db" "数据库名"; _check_id "$user" "用户名"
    _svc_exists "$dir" "db" || error "PostgreSQL 未部署"
    load_env "$dir"
    warn "即将删除库 ${db} 和用户 ${user}，不可逆！"
    read -rp "输入库名确认: " c; [[ "$c" == "$db" ]] || { info "已取消"; return; }
    db_exec "$dir" -c "DROP DATABASE IF EXISTS \"${db}\" WITH (FORCE);" \
        || warn "DROP DATABASE 失败（当前 PostgreSQL 版本可能不支持 WITH (FORCE)，或仍有连接占用），请手动检查"
    db_exec "$dir" -c "DROP ROLE IF EXISTS \"${user}\";" \
        || warn "DROP ROLE 失败：该角色可能仍拥有其他库/对象的所有权，请手动处理后重试"
    log "已删除库 ${db} 和用户 ${user}"
}

cmd_clear_db() {
    local dir="${1:-$DEFAULT_DIR}" db="${2:?用法: clear-db [DIR] <DB>}"
    _check_id "$db" "数据库名"
    _svc_exists "$dir" "db" || error "PostgreSQL 未部署"
    load_env "$dir"
    warn "即将清空库 ${db} 内所有表（库和权限保留：重建 public schema），不可逆！"
    read -rp "输入库名确认: " c; [[ "$c" == "$db" ]] || { info "已取消"; return; }

    local owner
    owner=$(db_exec "$dir" -tAc "SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_database WHERE datname='${db}';" | tr -d '[:space:]')
    [[ -n "$owner" ]] || { warn "找不到库 ${db}"; return 1; }

    db_sql_on "$dir" "$db" "
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
GRANT ALL ON SCHEMA public TO \"${owner}\";
GRANT ALL ON SCHEMA public TO public;
ALTER DEFAULT PRIVILEGES FOR ROLE \"${owner}\" IN SCHEMA public GRANT ALL ON TABLES TO \"${owner}\";
ALTER DEFAULT PRIVILEGES FOR ROLE \"${owner}\" IN SCHEMA public GRANT ALL ON SEQUENCES TO \"${owner}\";"
    log "已清空库 ${db}（public schema 已重建，owner: ${owner}）"
}

cmd_list_db() {
    local dir="${1:-$DEFAULT_DIR}"
    _svc_exists "$dir" "db" || error "PostgreSQL 未部署"
    load_env "$dir"
    header "数据库列表"
    db_exec "$dir" -c "SELECT datname AS \"数据库\", pg_catalog.pg_get_userbyid(datdba) AS \"Owner\",
        pg_catalog.pg_encoding_to_char(encoding) AS \"编码\"
        FROM pg_database WHERE datname NOT IN ('template0','template1','postgres') ORDER BY datname;"
    header "角色列表"
    db_exec "$dir" -c "SELECT rolname AS \"角色\", rolcanlogin AS \"可登录\", rolsuper AS \"超级用户\"
        FROM pg_roles WHERE rolname NOT LIKE 'pg\_%' ORDER BY rolname;"
}

cmd_passwd() {
    local dir="${1:-$DEFAULT_DIR}" user="${2:?用法: passwd [DIR] <USER> [PW]}" pw="${3:-$(randpw)}"
    _check_id "$user" "用户名"; _check_pw "$pw" "新密码"
    _svc_exists "$dir" "db" || error "PostgreSQL 未部署"
    load_env "$dir"
    local exists
    exists=$(db_exec "$dir" -tAc "SELECT 1 FROM pg_roles WHERE rolname='${user}';" | tr -d '[:space:]')
    [[ "$exists" == "1" ]] || { warn "未找到角色 ${user}"; return 1; }
    db_exec "$dir" -c "ALTER ROLE \"${user}\" PASSWORD '${pw}';"
    log "新密码: ${pw}"
}

# ════════════════════════════════════════════════════════════
# 性能调优子命令
# ════════════════════════════════════════════════════════════
cmd_tune_db() {
    local dir="${1:-$DEFAULT_DIR}"
    [[ -f "$dir/.env" ]] || error ".env 不存在: ${dir}/.env"
    _auto_tune
    load_env "$dir"

    local sb="${POSTGRES_SHARED_BUFFERS:-$_AT_SHARED_BUFFERS}"
    local ecs="${POSTGRES_EFFECTIVE_CACHE:-$_AT_EFFECTIVE_CACHE}"
    local mwm="${POSTGRES_MAINTENANCE_WORK_MEM:-$_AT_MAINTENANCE_WORK_MEM}"
    local wm="${POSTGRES_WORK_MEM:-$_AT_WORK_MEM}"
    local conn="${POSTGRES_MAX_CONNECTIONS:-$_AT_MAX_CONN}"
    local wb="${POSTGRES_WAL_BUFFERS:-$_AT_WAL_BUFFERS}"

    local total_kb; total_kb=$(awk '/^MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
    local total_mb=$(( total_kb / 1024 ))

    header "PostgreSQL 性能参数  （系统内存: ${total_mb}MB）"
    printf "  %-30s %s\n" "shared_buffers"          "${sb}   （自动推荐: ${_AT_SHARED_BUFFERS}）"
    printf "  %-30s %s\n" "effective_cache_size"    "${ecs}  （自动推荐: ${_AT_EFFECTIVE_CACHE}）"
    printf "  %-30s %s\n" "maintenance_work_mem"    "${mwm}  （自动推荐: ${_AT_MAINTENANCE_WORK_MEM}）"
    printf "  %-30s %s\n" "work_mem"                "${wm}   （自动推荐: ${_AT_WORK_MEM}）"
    printf "  %-30s %s\n" "max_connections"         "${conn} （自动推荐: ${_AT_MAX_CONN}）"
    printf "  %-30s %s\n" "wal_buffers"              "${wb}   （自动推荐: ${_AT_WAL_BUFFERS}）"
    echo
    warn "shared_buffers / max_connections / wal_buffers 修改后需重启 PostgreSQL 才生效；work_mem / effective_cache_size / maintenance_work_mem 重启后同样按新 compose 生效（本脚本统一走重启方式，不做 reload 差异化）。"

    read -rp "  是否修改参数？[y/N] " yn
    [[ "${yn,,}" == "y" ]] || return 0

    echo; echo "  提示：留空保持当前值；输入 auto 恢复为自动计算值"; echo

    local val
    read -rp "  shared_buffers          [${sb}]: " val
    case "$val" in
        auto|AUTO) _env_set "$dir" "POSTGRES_SHARED_BUFFERS" "" ;;
        "") : ;;
        *[0-9][MmGg][Bb]) _env_set "$dir" "POSTGRES_SHARED_BUFFERS" "${val^^}" ;;
        *) warn "格式无效（示例: 512MB 1GB），跳过" ;;
    esac

    read -rp "  effective_cache_size    [${ecs}]: " val
    case "$val" in
        auto|AUTO) _env_set "$dir" "POSTGRES_EFFECTIVE_CACHE" "" ;;
        "") : ;;
        *[0-9][MmGg][Bb]) _env_set "$dir" "POSTGRES_EFFECTIVE_CACHE" "${val^^}" ;;
        *) warn "格式无效，跳过" ;;
    esac

    read -rp "  maintenance_work_mem    [${mwm}]: " val
    case "$val" in
        auto|AUTO) _env_set "$dir" "POSTGRES_MAINTENANCE_WORK_MEM" "" ;;
        "") : ;;
        *[0-9][MmGg][Bb]) _env_set "$dir" "POSTGRES_MAINTENANCE_WORK_MEM" "${val^^}" ;;
        *) warn "格式无效，跳过" ;;
    esac

    read -rp "  work_mem                [${wm}]: " val
    case "$val" in
        auto|AUTO) _env_set "$dir" "POSTGRES_WORK_MEM" "" ;;
        "") : ;;
        *[0-9][MmGg][Bb]) _env_set "$dir" "POSTGRES_WORK_MEM" "${val^^}" ;;
        *) warn "格式无效，跳过" ;;
    esac

    read -rp "  max_connections         [${conn}]: " val
    if [[ "$val" == "auto" || "$val" == "AUTO" ]]; then
        _env_set "$dir" "POSTGRES_MAX_CONNECTIONS" ""
    elif [[ -z "$val" ]]; then
        :
    elif [[ "$val" =~ ^[0-9]+$ ]]; then
        local val_dec=$((10#$val))
        if (( val_dec >= 10 && val_dec <= 5000 )); then
            _env_set "$dir" "POSTGRES_MAX_CONNECTIONS" "$val_dec"
        else
            warn "范围 10-5000，跳过"
        fi
    else
        warn "需要数字，跳过"
    fi

    read -rp "  wal_buffers             [${wb}]: " val
    case "$val" in
        auto|AUTO) _env_set "$dir" "POSTGRES_WAL_BUFFERS" "" ;;
        "") : ;;
        *[0-9][MmGg][Bb]) _env_set "$dir" "POSTGRES_WAL_BUFFERS" "${val^^}" ;;
        *) warn "格式无效，跳过" ;;
    esac

    _write_compose "$dir"
    log "配置已写入 compose，重启后生效: ${dir}/docker-compose.yml"

    if _svc_exists "$dir" "db" 2>/dev/null; then
        read -rp "  是否立即重启 PostgreSQL 使配置生效？[y/N] " yn
        if [[ "${yn,,}" == "y" ]]; then
            compose_run "$dir" up -d --wait --force-recreate db \
                && log "PostgreSQL 已重启" \
                || warn "重启失败，请手动执行: docker compose -f ${dir}/docker-compose.yml up -d --force-recreate db"
        else
            warn "配置已写入，请手动重启 PostgreSQL 生效"
        fi
    fi
}

cmd_tune_redis() {
    local dir="${1:-$DEFAULT_DIR}"
    [[ -f "$dir/.env" ]] || error ".env 不存在: ${dir}/.env"
    _auto_tune
    load_env "$dir"

    local maxmem="${REDIS_MAXMEMORY:-${_AT_REDIS_MEM}}"
    local total_kb; total_kb=$(awk '/^MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
    local total_mb=$(( total_kb / 1024 ))

    header "Redis 性能参数  （系统内存: ${total_mb}MB）"
    printf "  %-20s %s\n" "maxmemory" "${maxmem}  （自动推荐: ${_AT_REDIS_MEM}）"
    echo
    printf "  当前配置文件: %s/redis-conf/redis.conf\n" "$dir"
    [[ -f "$dir/redis-conf/redis.conf" ]] && {
        echo; echo "  ── 当前文件内容 ──"
        grep -v "requirepass" "$dir/redis-conf/redis.conf" | sed 's/^/  /'
        echo
    }

    read -rp "  是否修改参数？[y/N] " yn
    [[ "${yn,,}" == "y" ]] || return 0

    echo
    local val
    read -rp "  maxmemory  [${maxmem}]（示例: 256mb 512mb 1gb，auto=自动推荐）: " val
    case "$val" in
        auto|AUTO) _env_set "$dir" "REDIS_MAXMEMORY" "" ;;
        "")        : ;;
        *[0-9][mMgGbB]*)
            _env_set "$dir" "REDIS_MAXMEMORY" "${val,,}" ;;
        *) warn "格式无效（示例: 512mb），跳过" ;;
    esac

    load_env "$dir"
    _write_redis_conf "$dir"
    log "配置文件已更新: ${dir}/redis-conf/redis.conf"

    if _svc_exists "$dir" "redis" 2>/dev/null; then
        read -rp "  是否立即重启 Redis 使配置生效？[y/N] " yn
        if [[ "${yn,,}" == "y" ]]; then
            compose_run "$dir" restart redis \
                && log "Redis 已重启" \
                || warn "重启失败，请手动执行: docker compose -f ${dir}/docker-compose.yml restart redis"
        else
            warn "配置已写入，请手动重启 Redis 生效"
        fi
    fi
}

# ════════════════════════════════════════════════════════════
# WebDAV 远程备份（通用：Nextcloud / ownCloud / AList / 群晖 / 坚果云 / rclone serve webdav 等）
# 仅依赖 curl。配置项（.env 或同名环境变量）：
#   WEBDAV_URL         服务端 WebDAV 根地址，如 https://dav.example.com/remote.php/dav/files/me
#   WEBDAV_USER / WEBDAV_PASSWORD
#   WEBDAV_REMOTE_DIR  备份目录（相对 WEBDAV_URL），默认 /pg-infra-backup
#   WEBDAV_KEEP        上传成功后远端只保留最近 N 份备份，默认 3；0 = 不清理
# ════════════════════════════════════════════════════════════
_BK_NAME_RE='^pg-infra-full-backup_[0-9]{8}_[0-9]{6}\.tar\.gz(\.enc)?$'
_WEBDAV_CFG=""

_check_webdav_deps() { command -v curl >/dev/null 2>&1 || error "未找到 curl，请先安装"; }

_urlencode_path() {   # 逐字节百分号编码，保留 / 与 unreserved 字符
    local LC_ALL=C s="$1" out="" c i
    for (( i=0; i<${#s}; i++ )); do
        c="${s:i:1}"
        case "$c" in
            [A-Za-z0-9._~/-]) out+="$c" ;;
            *) out+=$(printf '%%%02X' "'$c") ;;
        esac
    done
    printf '%s' "$out"
}

_urldecode() { printf '%b' "${1//%/\\x}"; }

# 加载并校验配置；.env 不存在时（如全新机器恢复）可直接用环境变量
_load_webdav_conf() {   # DIR
    local dir="$1"
    if [[ -f "$dir/.env" ]]; then load_env "$dir"; fi
    [[ -n "${WEBDAV_URL:-}"      ]] || error "未配置 WEBDAV_URL，请先运行 webdav-config（全新机器可用环境变量传入 WEBDAV_URL/WEBDAV_USER/WEBDAV_PASSWORD）"
    [[ -n "${WEBDAV_USER:-}"     ]] || error "未配置 WEBDAV_USER，请先运行 webdav-config"
    [[ -n "${WEBDAV_PASSWORD:-}" ]] || error "未配置 WEBDAV_PASSWORD，请先运行 webdav-config"
    WEBDAV_URL="${WEBDAV_URL%/}"
    local rd="${WEBDAV_REMOTE_DIR:-pg-infra-backup}"
    while [[ "$rd" == *//* ]]; do rd="${rd//\/\//\/}"; done   # 合并重复的 /
    while [[ "$rd" == /* ]]; do rd="${rd#/}"; done
    rd="${rd%/}"; [[ -n "$rd" ]] || rd="pg-infra-backup"
    WEBDAV_REMOTE_DIR="/${rd}"
    [[ "$WEBDAV_URL" == https://* ]] || warn "WEBDAV_URL 不是 https：凭据和备份内容将以明文在网络上传输"
    # 凭据写入 0600 临时 curl 配置，避免出现在 ps 参数里；退出时自动清理
    _WEBDAV_CFG=$(mktemp); _register_tmp "$_WEBDAV_CFG"; chmod 600 "$_WEBDAV_CFG"
    local u="${WEBDAV_USER}:${WEBDAV_PASSWORD}"
    u="${u//\\/\\\\}"; u="${u//\"/\\\"}"
    printf 'user = "%s"\n' "$u" > "$_WEBDAV_CFG"
}

_webdav_curl() { curl -sS -K "$_WEBDAV_CFG" --connect-timeout 15 "$@"; }

_webdav_mkcol_p() {   # REMOTE_DIR — 逐级创建（MKCOL 不会自动建父目录）
    local path="$1" cur="" seg code
    local -a segs
    IFS=/ read -ra segs <<< "${path#/}"
    for seg in "${segs[@]}"; do
        [[ -n "$seg" ]] || continue
        cur+="/${seg}"
        code=$(_webdav_curl -o /dev/null -w '%{http_code}' -X MKCOL \
            "${WEBDAV_URL}$(_urlencode_path "$cur")/") || code="000"
        case "$code" in
            201|200|301|302|405) : ;;                       # 新建成功 / 已存在
            401) error "WebDAV 认证失败（HTTP 401），请检查用户名/密码" ;;
            000) error "无法连接 WebDAV: ${WEBDAV_URL}" ;;
            *)   warn "创建目录 ${cur} 返回 HTTP ${code}（可能已存在，继续）" ;;
        esac
    done
}

_webdav_put() {   # LOCAL_FILE REMOTE_DIR
    local f="$1" rdir="$2" name url code lsize rsize
    name=$(basename "$f")
    url="${WEBDAV_URL}$(_urlencode_path "${rdir}/${name}")"
    lsize=$(stat -c%s "$f")
    info "上传 ${name}（$(du -sh "$f" | cut -f1)）→ ${WEBDAV_URL}${rdir}/"
    code=$(_webdav_curl -o /dev/null -w '%{http_code}' -T "$f" "$url") || code="000"
    case "$code" in
        200|201|204) : ;;
        *) error "上传失败，HTTP ${code}（URL: ${url}）" ;;
    esac
    rsize=$(_webdav_curl -I "$url" 2>/dev/null | tr -d '\r' \
        | awk 'tolower($1)=="content-length:"{print $2}' | tail -n1) || rsize=""
    if [[ -z "$rsize" ]]; then
        warn "服务器未返回 Content-Length，跳过上传后大小校验"
    elif [[ "$rsize" != "$lsize" ]]; then
        error "远端文件大小(${rsize})与本地(${lsize})不一致，上传可能不完整: ${url}"
    fi
    log "✓ 已上传并校验: ${rdir}/${name}"
}

_webdav_get() {   # REMOTE_PATH（相对 WEBDAV_URL） LOCAL_DIR
    local rpath="$1" ldir="$2" name out url code
    name=$(basename "$rpath"); out="${ldir}/${name}"
    url="${WEBDAV_URL}$(_urlencode_path "$rpath")"
    info "下载 ${rpath} ..."
    code=$(_webdav_curl -o "$out" -w '%{http_code}' "$url") || code="000"
    [[ "$code" == "200" ]] || { rm -f "$out"; error "下载失败，HTTP ${code}（URL: ${url}）"; }
    log "✓ 下载完成: ${name}（$(du -sh "$out" | cut -f1)）"
}

# 远端只保留最近 KEEP 份（仅处理符合备份命名的文件；列表失败/新文件不在列表中时一律不删）
_webdav_prune() {   # REMOTE_DIR KEEP JUST_UPLOADED_NAME
    local rdir="$1" keep="$2" just="$3" files n=0 f code
    [[ "$keep" =~ ^[0-9]+$ ]] || { warn "WEBDAV_KEEP='${keep}' 不是数字，跳过远端清理"; return 0; }
    (( keep > 0 )) || return 0
    files=$(_webdav_list "$rdir") || { warn "无法列出远端文件，跳过清理"; return 0; }
    grep -qxF -- "$just" <<< "$files" \
        || { warn "远端列表中未找到刚上传的文件，为安全起见跳过清理"; return 0; }
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        n=$((n + 1))
        (( n > keep )) || continue
        [[ "$f" != "$just" ]] || continue
        code=$(_webdav_curl -o /dev/null -w '%{http_code}' -X DELETE \
            "${WEBDAV_URL}$(_urlencode_path "${rdir}/${f}")") || code="000"
        case "$code" in
            200|202|204|404) log "已清理旧备份: ${f}" ;;
            *) warn "清理 ${f} 失败（HTTP ${code}），已保留" ;;
        esac
    done <<< "$files"
    return 0
}

# 列出远端备份文件名（新→旧），每行一个；需先 _load_webdav_conf
_webdav_list() {   # [REMOTE_DIR]
    local rdir="${1:-$WEBDAV_REMOTE_DIR}" url resp code body h n
    url="${WEBDAV_URL}$(_urlencode_path "$rdir")/"
    resp=$(_webdav_curl -X PROPFIND -H "Depth: 1" -H "Content-Type: application/xml" \
        --data '<?xml version="1.0"?><propfind xmlns="DAV:"><prop><getcontentlength/></prop></propfind>' \
        -w $'\n%{http_code}' "$url") || { warn "无法连接 WebDAV: ${url}"; return 1; }
    code="${resp##*$'\n'}"; body="${resp%$'\n'*}"
    case "$code" in
        207) : ;;
        404) warn "远端目录不存在: ${rdir}（首次备份时会自动创建）"; return 0 ;;
        401|403) warn "WebDAV 认证失败或无权限（HTTP ${code}）"; return 1 ;;
        *)   warn "WebDAV 列目录失败（HTTP ${code}）"; return 1 ;;
    esac
    printf '%s' "$body" | { grep -oiE '<([a-z0-9]+:)?href>[^<]+' || true; } | sed -E 's/^<[^>]*>//' \
        | while IFS= read -r h; do
            h="${h%/}"; n=$(_urldecode "${h##*/}")
            if [[ "$n" =~ $_BK_NAME_RE ]]; then printf '%s\n' "$n"; fi
        done | sort -ru
}

cmd_webdav_config() {
    local dir="${1:-$DEFAULT_DIR}"
    [[ -f "$dir/.env" ]] || error ".env 不存在，请先部署: ${dir}/.env"
    load_env "$dir"

    header "当前 WebDAV 配置"
    printf "  WEBDAV_URL        = %s\n" "${WEBDAV_URL:-（未设置）}"
    printf "  WEBDAV_USER       = %s\n" "${WEBDAV_USER:-（未设置）}"
    printf "  WEBDAV_PASSWORD   = %s\n" "${WEBDAV_PASSWORD:+***已设置***}${WEBDAV_PASSWORD:-（未设置）}"
    printf "  WEBDAV_REMOTE_DIR = %s\n" "${WEBDAV_REMOTE_DIR:-/pg-infra-backup}"
    printf "  WEBDAV_KEEP       = %s\n" "${WEBDAV_KEEP:-3}（远端保留最近 N 份，0=不清理）"
    echo

    read -rp "  是否修改配置？[y/N] " yn
    if [[ "${yn,,}" == "y" ]]; then
        local val
        read -rp "  WebDAV 地址（如 https://dav.example.com/remote.php/dav/files/me）[${WEBDAV_URL:-}]: " val
        [[ -n "$val" ]] && _env_set "$dir" "WEBDAV_URL" "${val%/}"
        read -rp "  用户名 [${WEBDAV_USER:-}]: " val
        [[ -n "$val" ]] && _env_set "$dir" "WEBDAV_USER" "$val"
        read -rsp "  密码 / 应用专用密码（不回显，留空保持不变）: " val; echo
        if [[ -n "$val" ]]; then
            [[ "$val" != *$'\n'* ]] || error "密码不能含换行"
            _env_set "$dir" "WEBDAV_PASSWORD" "$val"
        fi
        read -rp "  远端备份目录 [${WEBDAV_REMOTE_DIR:-/pg-infra-backup}]: " val
        if [[ -n "$val" ]]; then _env_set "$dir" "WEBDAV_REMOTE_DIR" "$val"
        elif [[ -z "${WEBDAV_REMOTE_DIR:-}" ]]; then _env_set "$dir" "WEBDAV_REMOTE_DIR" "/pg-infra-backup"; fi
        read -rp "  远端保留最近几份备份（0=不清理）[${WEBDAV_KEEP:-3}]: " val
        if [[ -n "$val" ]]; then
            [[ "$val" =~ ^[0-9]+$ ]] || error "保留份数必须是非负整数"
            _env_set "$dir" "WEBDAV_KEEP" "$val"
        elif [[ -z "${WEBDAV_KEEP:-}" ]]; then _env_set "$dir" "WEBDAV_KEEP" "3"; fi
        log "WebDAV 配置已保存（写入 ${dir}/.env）"
    fi

    read -rp "  是否测试连通性？[y/N] " yn
    if [[ "${yn,,}" == "y" ]]; then
        _check_webdav_deps
        _load_webdav_conf "$dir"
        local code
        code=$(_webdav_curl -o /dev/null -w '%{http_code}' -X PROPFIND -H "Depth: 0" "${WEBDAV_URL}/") || code="000"
        case "$code" in
            207|200)
                log "✓ WebDAV 连接与认证正常（HTTP ${code}）"
                _webdav_mkcol_p "$WEBDAV_REMOTE_DIR"
                log "✓ 备份目录可用: ${WEBDAV_REMOTE_DIR}"
                ;;
            401) warn "✗ 认证失败（HTTP 401）：请检查用户名/密码（Nextcloud 等需使用应用专用密码）" ;;
            000) warn "✗ 无法连接: ${WEBDAV_URL}" ;;
            *)   warn "✗ 连接异常（HTTP ${code}）  URL: ${WEBDAV_URL}/" ;;
        esac
    fi
}

cmd_webdav_list() {
    local dir="${1:-$DEFAULT_DIR}" files
    _check_webdav_deps
    _load_webdav_conf "$dir"
    header "WebDAV 远端备份: ${WEBDAV_URL}${WEBDAV_REMOTE_DIR}/"
    files=$(_webdav_list "$WEBDAV_REMOTE_DIR") || return 1
    if [[ -n "$files" ]]; then
        while IFS= read -r f; do printf "  webdav://%s\n" "$f"; done <<< "$files"
    else
        warn "（目录为空或无备份文件）"
    fi
}

# ════════════════════════════════════════════════════════════
# 备份 / 恢复
# ════════════════════════════════════════════════════════════
# 本地只保留最近 KEEP 份（仅处理符合备份命名的文件；新备份不存在时不删）
_local_prune() {   # DEST KEEP JUST_CREATED_NAME
    local dest="$1" keep="$2" just="$3" f n=0
    [[ "$keep" =~ ^[0-9]+$ ]] || { warn "LOCAL_BACKUP_KEEP='${keep}' 不是数字，跳过本地清理"; return 0; }
    (( keep > 0 )) || return 0
    [[ -f "${dest}/${just}" ]] || return 0
    while IFS= read -r f; do
        n=$((n + 1))
        (( n > keep )) || continue
        [[ "$f" != "$just" ]] || continue
        if rm -f -- "${dest}/${f}"; then log "已清理本地旧备份: ${f}"
        else warn "清理本地旧备份失败: ${f}"; fi
    done < <(ls -1 -- "$dest" 2>/dev/null | grep -E "$_BK_NAME_RE" | sort -r)
    return 0
}

# cmd_backup [DIR] [DEST] [--webdav] [--encrypt]
cmd_backup() {
    local do_webdav=0 do_encrypt=0
    local _pos=()
    for _a in "$@"; do
        case "$_a" in
            --webdav)  do_webdav=1 ;;
            --encrypt) do_encrypt=1 ;;
            *) _pos+=("$_a") ;;
        esac
    done
    local dir="${_pos[0]:-$DEFAULT_DIR}" dest="${_pos[1]:-${_pos[0]:-$DEFAULT_DIR}/backup}"
    _check_dir_safe "$dir"

    [[ -f "$dir/.env" ]] || error ".env 不存在，请先部署: ${dir}/.env"
    load_env "$dir"
    if (( do_webdav )); then   # 先校验远端配置，避免做完耗时的导出才发现没配
        _check_webdav_deps
        _load_webdav_conf "$dir"
    fi
    mkdir -p "$dest"; chmod 700 "$dest" 2>/dev/null || true

    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local work; work=$(mktemp -d); _register_tmp "$work"
    local pack="${work}/pack"; mkdir -p "$pack"

    header "全量备份 → ${dest}"

    cp "$dir/.env" "$pack/.env"
    [[ -f "$dir/docker-compose.yml" ]] && cp "$dir/docker-compose.yml" "$pack/docker-compose.yml"
    [[ -d "$dir/pg-conf"    ]] && cp -a "$dir/pg-conf"    "$pack/pg-conf"
    [[ -d "$dir/redis-conf" ]] && cp -a "$dir/redis-conf" "$pack/redis-conf"

    cat > "$pack/manifest.txt" <<EOF
backup_time=$(date -Iseconds)
hostname=$(hostname)
DEPLOY_DB=${DEPLOY_DB:-0}
DEPLOY_REDIS=${DEPLOY_REDIS:-0}
WG_IP=${WG_IP:-}
POSTGRES_IMAGE=${POSTGRES_IMAGE}
REDIS_IMAGE=${REDIS_IMAGE}
EOF

    # ── PostgreSQL 全量导出（pg_dumpall：含所有角色 + 所有库） ──
    if [[ "${DEPLOY_DB:-0}" == "1" ]]; then
        _svc_exists "$dir" "db" || { rm -rf "$work"; error "manifest 标记部署了 PostgreSQL，但 compose 中无 db 服务"; }
        info "导出 PostgreSQL 全量数据（pg_dumpall，含角色/库/权限），可能需要几分钟..."
        if compose_run "$dir" exec -T db \
                pg_dumpall -U postgres | gzip > "${pack}/postgres-all.sql.gz"; then
            log "✓ PostgreSQL 全量导出完成 ($(du -sh "${pack}/postgres-all.sql.gz" | cut -f1))"
        else
            rm -rf "$work"; error "pg_dumpall 导出失败"
        fi
    fi

    # ── Redis 数据打包 ──────────────────────────────────────
    if [[ "${DEPLOY_REDIS:-0}" == "1" ]]; then
        if _svc_exists "$dir" "redis"; then
            local _redis_cli=(compose_run "$dir" exec -T redis redis-cli -h 127.0.0.1)
            local _orig_aofpct
            _orig_aofpct=$("${_redis_cli[@]}" CONFIG GET auto-aof-rewrite-percentage 2>/dev/null | tail -1 || true)
            "${_redis_cli[@]}" CONFIG SET auto-aof-rewrite-percentage 0 >/dev/null 2>&1 || true
            "${_redis_cli[@]}" BGSAVE >/dev/null 2>&1 || true

            info "等待 Redis BGSAVE 完成..."
            local _bg_wait=0 _bg_done=0
            while (( _bg_wait < 60 )); do
                if [[ "$("${_redis_cli[@]}" INFO persistence 2>/dev/null \
                        | tr -d '\r' | awk -F: '/^rdb_bgsave_in_progress:/{print $2}')" == "0" ]]; then
                    _bg_done=1; break
                fi
                sleep 1; _bg_wait=$((_bg_wait + 1))
            done
            (( _bg_done )) || warn "等待 BGSAVE 完成超时（60s），备份的 RDB 可能不是最新一致状态"

            if [[ -d "$dir/redis" ]]; then
                tar -C "$dir" -czf "${pack}/redis-data.tar.gz" redis \
                    && log "✓ Redis 数据目录打包完成 ($(du -sh "${pack}/redis-data.tar.gz" | cut -f1))" \
                    || warn "Redis 数据打包失败，恢复时该库将为空"
            else
                warn "Redis 数据目录不存在，跳过"
            fi

            if [[ -n "${_orig_aofpct:-}" ]]; then
                "${_redis_cli[@]}" CONFIG SET auto-aof-rewrite-percentage "${_orig_aofpct}" >/dev/null 2>&1 || true
            fi
        else
            warn "manifest 标记部署了 Redis，但 compose 中无 redis 服务，跳过 Redis 备份"
        fi
    fi

    if [[ "${DEPLOY_DB:-0}" != "1" && "${DEPLOY_REDIS:-0}" != "1" ]]; then
        rm -rf "$work"; error "未检测到已部署的 PostgreSQL/Redis，无内容可备份"
    fi

    local out="${dest}/pg-infra-full-backup_${ts}.tar.gz"
    ( umask 077; tar -C "$pack" -czf "$out" . ) || { rm -rf "$work"; error "打包失败"; }
    chmod 600 "$out" 2>/dev/null || warn "无法收紧备份文件权限，该文件含明文密码，请手动 chmod 600"
    rm -rf "$work"
    log "全量备份完成: ${out}  ($(du -sh "$out" | cut -f1))"

    if (( do_encrypt )); then
        command -v openssl >/dev/null 2>&1 || error "加密需要 openssl，请先安装"
        load_env "$dir"
        local enc_key="${BACKUP_ENC_KEY:-}" _generated=0
        if [[ -z "$enc_key" ]]; then
            enc_key=$(randpw); _generated=1
            _env_set "$dir" "BACKUP_ENC_KEY" "$enc_key"
        fi
        local enc_out="${out}.enc"
        if openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
                -pass "pass:${enc_key}" -in "$out" -out "$enc_out"; then
            command -v shred >/dev/null 2>&1 && shred -u "$out" 2>/dev/null || rm -f "$out"
            chmod 600 "$enc_out" 2>/dev/null || true
            out="$enc_out"
            log "✓ 已加密: ${out}"
        else
            error "备份加密失败"
        fi
        echo
        _c "1;31" "════════════════════════════════════════════════════════"
        _c "1;31" "  重要：备份解密密钥（务必单独抄录保存，不要只依赖本机 .env）"
        _c "1;31" "  ${enc_key}"
        (( _generated )) && _c "1;31" "  已顺手写入 ${dir}/.env 的 BACKUP_ENC_KEY，方便本机后续备份复用；"
        _c "1;31" "  但机器重装后 .env 会随之丢失，到时候 restore 这份备份必须"
        _c "1;31" "  手动提供上面这个密钥，请现在就把它记录到密码管理器/纸面等独立位置。"
        _c "1;31" "════════════════════════════════════════════════════════"
        echo
    fi

    info "该文件可直接拷走保存；机器重装后执行 restore 即可整体恢复。"
    _local_prune "$dest" "${LOCAL_BACKUP_KEEP:-3}" "$(basename "$out")"

    if (( do_webdav )); then
        header "上传备份到 WebDAV"
        (( do_encrypt )) || warn "备份未加密：归档含 .env（数据库/Redis 密码）和全部数据，将以明文存放在远端，强烈建议加 --encrypt"
        _load_webdav_conf "$dir"
        _webdav_mkcol_p "$WEBDAV_REMOTE_DIR"
        _webdav_put "$out" "$WEBDAV_REMOTE_DIR"
        _webdav_prune "$WEBDAV_REMOTE_DIR" "${WEBDAV_KEEP:-3}" "$(basename "$out")"
    fi
}

# cmd_restore [DIR] <备份tar.gz[.enc]|webdav://文件名> [解密密钥]
cmd_restore() {
    local dir="${1:-$DEFAULT_DIR}" f="${2:?用法: restore [DIR] <pg-infra-full-backup_*.tar.gz[.enc]|webdav://文件名> [解密密钥]}"
    local enc_key="${3:-}"
    _check_dir_safe "$dir"

    local _tmp_dir="" _cleanup=0
    if [[ "$f" == webdav://* ]]; then
        _check_webdav_deps
        _load_webdav_conf "$dir"
        local _wp="${f#webdav://}"
        [[ "$_wp" == */* ]] || _wp="${WEBDAV_REMOTE_DIR}/${_wp}"   # 纯文件名 → 备份目录下
        [[ "$_wp" == /* ]]  || _wp="/${_wp}"
        _tmp_dir=$(mktemp -d); _register_tmp "$_tmp_dir"; _cleanup=1
        _webdav_get "$_wp" "$_tmp_dir"
        f="${_tmp_dir}/$(basename "$_wp")"
    fi

    [[ -f "$f" ]] || { [[ $_cleanup -eq 1 ]] && rm -rf "$_tmp_dir"; error "文件不存在: ${f}"; }

    if [[ "$f" == *.enc ]]; then
        command -v openssl >/dev/null 2>&1 \
            || { [[ $_cleanup -eq 1 ]] && rm -rf "$_tmp_dir"; error "解密需要 openssl，请先安装"; }
        if [[ -z "$enc_key" ]]; then
            read -rsp "该备份已加密，请输入解密密钥: " enc_key; echo
        fi
        [[ -n "$enc_key" ]] \
            || { [[ $_cleanup -eq 1 ]] && rm -rf "$_tmp_dir"; error "未提供解密密钥，无法继续"; }
        local _dec_dir; _dec_dir=$(mktemp -d); _register_tmp "$_dec_dir"
        local _dec_file="${_dec_dir}/$(basename "${f%.enc}")"
        if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
                -pass "pass:${enc_key}" -in "$f" -out "$_dec_file" 2>/dev/null; then
            rm -rf "$_dec_dir"; [[ $_cleanup -eq 1 ]] && rm -rf "$_tmp_dir"
            error "解密失败，密钥可能不正确"
        fi
        [[ $_cleanup -eq 1 ]] && rm -rf "$_tmp_dir"
        _tmp_dir="$_dec_dir"; _cleanup=1
        f="$_dec_file"
        log "解密成功"
    fi

    tar -tzf "$f" >/dev/null 2>&1 \
        || { [[ $_cleanup -eq 1 ]] && rm -rf "$_tmp_dir"; error "不是有效的 tar.gz 备份归档: ${f}"; }

    local extract; extract=$(mktemp -d); _register_tmp "$extract"
    tar -C "$extract" -xzf "$f" \
        || { rm -rf "$extract"; [[ $_cleanup -eq 1 ]] && rm -rf "$_tmp_dir"; error "解压失败: ${f}"; }
    [[ $_cleanup -eq 1 ]] && rm -rf "$_tmp_dir"
    [[ -f "$extract/.env" ]] || { rm -rf "$extract"; error "备份归档中缺少 .env，不是有效的全量备份文件"; }

    header "全量恢复 → ${dir}"
    [[ -f "$extract/manifest.txt" ]] && { echo; cat "$extract/manifest.txt" | sed 's/^/  /'; echo; }

    [[ -f "$dir/.env" ]] && warn "目标目录已存在 .env，恢复将覆盖现有配置，PostgreSQL/Redis 数据将被备份内容整体替换！"
    read -rp "确认恢复到 ${dir}？[y/N] " c
    [[ "${c,,}" == "y" ]] || { info "已取消"; rm -rf "$extract"; return; }
    [[ $EUID -eq 0 ]] || { rm -rf "$extract"; error "需要 root 权限"; }

    if [[ -f "$dir/docker-compose.yml" ]]; then
        info "停止现有服务..."
        compose_run "$dir" down 2>/dev/null || true
    fi

    mkdir -p "$dir"
    cp "$extract/.env" "$dir/.env"; chmod 600 "$dir/.env"
    [[ -f "$extract/docker-compose.yml" ]] && cp "$extract/docker-compose.yml" "$dir/docker-compose.yml"
    [[ -d "$extract/redis-conf" ]] && { rm -rf "$dir/redis-conf"; cp -a "$extract/redis-conf" "$dir/redis-conf"; }

    load_env "$dir"

    local new_wg_ip
    if new_wg_ip=$(get_wg_ip 2>/dev/null) && [[ -n "$new_wg_ip" ]]; then
        if [[ "$new_wg_ip" != "${WG_IP:-}" ]]; then
            warn "当前 WG IP (${new_wg_ip}) 与备份记录 (${WG_IP:-无}) 不同，已更新 .env"
            _env_set "$dir" "WG_IP" "$new_wg_ip"
        fi
    else
        warn "无法获取当前 WireGuard IP，沿用备份中的 WG_IP=${WG_IP:-无}（请确认 WireGuard 已启动）"
    fi
    load_env "$dir"
    _write_compose "$dir"
    _write_pg_hba "$dir"   # 按当前（可能已变化的）WG/Docker 网段重写 pg_hba，PostgreSQL 角色本身不受 IP 变化影响

    if [[ "${DEPLOY_DB:-0}" == "1" ]]; then
        [[ -f "$extract/postgres-all.sql.gz" ]] \
            || warn "备份标记 DEPLOY_DB=1，但归档中缺少 postgres-all.sql.gz！PostgreSQL 将以全新空库启动，请确认这是你想要的行为。"
        rm -rf "$dir/db"; mkdir -p "$dir/db"
    fi

    if [[ "${DEPLOY_REDIS:-0}" == "1" ]]; then
        rm -rf "$dir/redis"; mkdir -p "$dir/redis"
        if [[ -f "$extract/redis-data.tar.gz" ]]; then
            info "恢复 Redis 数据目录（dump.rdb + appendonlydir）..."
            tar -C "$dir" -xzf "$extract/redis-data.tar.gz" \
                || warn "Redis 数据解压失败，Redis 将以空数据启动"
        else
            warn "备份中无 Redis 数据文件，Redis 将以空数据启动"
        fi
    fi

    local svcs=()
    [[ "${DEPLOY_DB:-0}"    == "1" ]] && svcs+=("db")
    [[ "${DEPLOY_REDIS:-0}" == "1" ]] && svcs+=("redis")
    [[ ${#svcs[@]} -gt 0 ]] || { rm -rf "$extract"; error "备份未标记任何已部署服务（DEPLOY_DB/DEPLOY_REDIS）"; }

    header "启动服务: ${svcs[*]}"
    compose_run "$dir" up -d --wait "${svcs[@]}" 2>&1 \
        || { rm -rf "$extract"; error "docker compose up 失败"; }

    # ── 导入 PostgreSQL 全量数据 ──────────────────────────────
    # 说明：pg_dumpall 的输出对 postgres 超级用户和 template0/1 也会有 CREATE 语句，
    # 而全新集群里这些对象已存在，导入时会出现少量“already exists”提示，属预期现象，
    # 不使用 ON_ERROR_STOP，遇到这类无害错误会跳过继续，直到全部语句执行完。
    if [[ "${DEPLOY_DB:-0}" == "1" && -f "$extract/postgres-all.sql.gz" ]]; then
        info "导入全量 SQL，可能需要几分钟..."
        if gzip -dc "$extract/postgres-all.sql.gz" \
                | compose_run "$dir" exec -T db psql -U postgres; then
            log "✓ PostgreSQL 数据导入完成"
        else
            warn "导入过程中出现部分错误（常见于 postgres/template0/template1 的 already-exists 提示），请核对 list-db 结果确认数据完整"
        fi
    elif [[ "${DEPLOY_DB:-0}" == "1" ]]; then
        warn "未导入任何 PostgreSQL 数据（归档缺少 postgres-all.sql.gz），当前为全新空库！"
    fi

    rm -rf "$extract"
    compose_run "$dir" ps
    log "全量恢复完成"
    _print_creds "$dir"
}

# ════════════════════════════════════════════════════════════
# 运维命令
# ════════════════════════════════════════════════════════════
cmd_status() {
    local dir="${1:-$DEFAULT_DIR}"; load_env "$dir"
    header "服务状态"; compose_run "$dir" ps
    if _svc_exists "$dir" "db"; then
        header "PostgreSQL"
        if compose_run "$dir" exec -T db pg_isready -U postgres 2>/dev/null | grep -q "accepting connections"; then
            log "✓ 响应正常"
            db_exec "$dir" -c "SELECT count(*) AS 当前连接数 FROM pg_stat_activity;" 2>/dev/null || true
        else warn "✗ 无响应"; fi
    fi
    if _svc_exists "$dir" "redis"; then
        header "Redis"
        if compose_run "$dir" exec -T redis redis-cli -h 127.0.0.1 ping 2>/dev/null | grep -q PONG; then
            log "✓ 响应正常"
            compose_run "$dir" exec -T redis redis-cli -h 127.0.0.1 \
                info server 2>/dev/null | grep -E "redis_version|used_memory_human|connected_clients"
        else warn "✗ 无响应"; fi
    fi
}

_svc_op() {   # op=start|stop DIR [SVC]
    local op="$1" dir="${2:-$DEFAULT_DIR}" svc="${3:-}"
    if [[ -n "$svc" ]]; then
        _svc_exists "$dir" "$svc" || error "服务 ${svc} 未部署"
        compose_run "$dir" "$op" "$svc"
    else
        compose_run "$dir" "$op"
    fi
}
cmd_start() { _svc_op start "$@"; }
cmd_stop()  { _svc_op stop  "$@"; }

cmd_logs() {
    local dir="${1:-$DEFAULT_DIR}" svc="${2:?用法: logs [DIR] <db|redis>}"
    _svc_exists "$dir" "$svc" || error "服务 ${svc} 未部署"
    compose_run "$dir" logs -f --tail=100 "$svc"
}

# ════════════════════════════════════════════════════════════
# 交互菜单
# ════════════════════════════════════════════════════════════
_pause() { echo; read -rp "  按 Enter 返回..." _ || true; }
_ask()   {   # PROMPT VAR [DEFAULT]
    local hint=""; [[ -n "${3:-}" ]] && hint=" [${3}]"
    read -rp "  ${1}${hint}: " "$2"
    if [[ -z "${!2}" && -n "${3:-}" ]]; then
        printf -v "$2" '%s' "$3"
    fi
    return 0
}

_mhdr() {
    clear; echo
    _c "1;34" "╔══════════════════════════════════════════════╗"
    _c "1;34" "║   pg-redis-shared.sh  PostgreSQL 18 + Redis  ║"
    _c "1;34" "╚══════════════════════════════════════════════╝"
    echo
}

_deployed_svcs() {   # DIR → 打印已部署服务
    local out=""
    _svc_exists "$1" "db"    && out+=" PostgreSQL"
    _svc_exists "$1" "redis" && out+=" Redis"
    [[ -n "$out" ]] && info "已部署:${out}" || warn "尚未部署任何服务"
    echo
}

_ask_deploy_params() {
    local auto_ip=""
    ip link show "${WG_IFACE}" &>/dev/null \
        && auto_ip=$(ip addr show "${WG_IFACE}" | awk '/inet /{gsub(/\/.*/, "", $2); print $2; exit}') \
        || warn "${WG_IFACE} 未检测到"
    _ask "部署目录" DIR "$DEFAULT_DIR"
    _ask "WireGuard IP" WG_IP "$auto_ip"
    [[ -n "$WG_IP" ]] || { warn "WireGuard IP 不能为空"; return 1; }
    [[ "$WG_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { warn "IP 格式无效"; return 1; }
}

menu_main() {
    while true; do
        _mhdr
        echo "  ─── 部署 ────────────────────────────────────"
        echo "  1) 部署服务（PostgreSQL / Redis / 全部）"
        echo "  2) 更新服务镜像"
        echo "  ─── 运维 ────────────────────────────────────"
        echo "  3) 查看状态    4) 启动    5) 停止    6) 日志"
        echo "  ─── 数据 ────────────────────────────────────"
        echo "  7) 数据库管理 ▶        8) 备份 / 恢复 ▶"
        echo "  ─── 调优 ────────────────────────────────────"
        echo "  9) 性能调优 ▶（shared_buffers / maxmemory 等）"
        echo "  ─────────────────────────────────────────────"
        echo "  0) 退出"
        echo
        read -rp "  请选择 [0-9]: " CH
        case "$CH" in
            1) menu_deploy  ;; 2) menu_update ;;
            3) menu_status  ;; 4) menu_svc start ;;
            5) menu_svc stop ;; 6) menu_logs ;;
            7) menu_db      ;; 8) menu_bk ;;
            9) menu_tune    ;;
            0) info "再见！"; exit 0 ;;
            *) warn "无效选项"; sleep 1 ;;
        esac
    done
}

menu_deploy() {
    _mhdr; _c "1;33" "  ▶ 部署服务"; echo
    _ask_deploy_params || { _pause; return; }
    echo "  a) PostgreSQL + Redis（全部）"
    echo "  b) 仅 PostgreSQL"
    echo "  c) 仅 Redis"
    echo
    read -rp "  请选择 [a/b/c]: " CH
    local target
    case "$CH" in
        a) target=all   ;; b) target=db ;; c) target=redis ;;
        *) warn "无效选项"; _pause; return ;;
    esac
    warn "将部署 ${target} 到 ${DIR}（WG: ${WG_IP}）"
    read -rp "  确认? [y/N] " C; [[ "${C,,}" == "y" ]] || { info "已取消"; _pause; return; }
    echo; _menu_run cmd_deploy "$DIR" "$WG_IP" "$target" || true; _pause
}

menu_update() {
    _mhdr; _c "1;33" "  ▶ 更新服务镜像"; echo
    _ask "部署目录" DIR "$DEFAULT_DIR"; _deployed_svcs "$DIR"
    echo "  a) 全部更新  b) 仅 PostgreSQL  c) 仅 Redis"
    read -rp "  请选择 [a/b/c]: " CH
    local target
    case "$CH" in
        a) target=all   ;; b) target=db ;; c) target=redis ;;
        *) warn "无效选项"; _pause; return ;;
    esac
    warn "将拉取最新镜像并重建 ${target}"
    read -rp "  确认? [y/N] " C; [[ "${C,,}" == "y" ]] || { info "已取消"; _pause; return; }
    local _uflags=() _B _E
    read -rp "  更新前先做一次全量备份？[Y/n]（推荐） " _B
    if [[ "${_B,,}" != "n" ]]; then
        _uflags+=("--backup")
        read -rp "  备份是否加密？[y/N] " _E
        [[ "${_E,,}" == "y" ]] && _uflags+=("--encrypt")
    fi
    echo; _menu_run cmd_update "$DIR" "$target" ${_uflags[@]+"${_uflags[@]}"} || true; _pause
}

menu_status() {
    _mhdr; _ask "部署目录" DIR "$DEFAULT_DIR"; echo
    _menu_run cmd_status "$DIR" || true; _pause
}

menu_svc() {
    local op="$1" label; [[ "$op" == "start" ]] && label="启动" || label="停止"
    _mhdr; _c "1;33" "  ▶ ${label}服务"; echo
    _ask "部署目录" DIR "$DEFAULT_DIR"; _deployed_svcs "$DIR"
    echo "  1) 全部  2) PostgreSQL  3) Redis"
    read -rp "  请选择 [1-3]: " CH
    local svc=""
    case "$CH" in 1) ;; 2) svc="db" ;; 3) svc="redis" ;;
        *) warn "无效选项"; _pause; return ;;
    esac
    read -rp "  确认${label}? [y/N] " C; [[ "${C,,}" == "y" ]] || { info "已取消"; _pause; return; }
    if [[ "$op" == "start" ]]; then
        _menu_run cmd_start "$DIR" ${svc:+"$svc"} || true
    else
        _menu_run cmd_stop  "$DIR" ${svc:+"$svc"} || true
    fi
    _pause
}

menu_logs() {
    _mhdr; _c "1;33" "  ▶ 查看日志"; echo
    _ask "部署目录" DIR "$DEFAULT_DIR"; _deployed_svcs "$DIR"
    echo "  1) PostgreSQL  2) Redis"
    read -rp "  请选择 [1-2]: " CH
    local svc; case "$CH" in 1) svc=db ;; 2) svc=redis ;; *) warn "无效"; _pause; return ;; esac
    info "Ctrl+C 退出"
    local _ot; _ot=$(trap -p INT); trap 'true' INT
    cmd_logs "$DIR" "$svc" || true
    [[ -n "$_ot" ]] && eval "$_ot" || trap - INT
    _pause
}

menu_db() {
    while true; do
        _mhdr; _c "1;33" "  ▶ 数据库管理"; echo
        echo "  1) 新建库和用户  2) 删除库和用户  3) 清空库内容"
        echo "  4) 列出库/用户   5) 修改用户密码  0) 返回"
        echo
        read -rp "  请选择 [0-5]: " CH
        case "$CH" in
            1) menu_db_add    ;; 2) menu_db_del   ;; 3) menu_db_clear ;;
            4) menu_db_list   ;; 5) menu_db_passwd ;; 0) return ;;
            *) warn "无效选项"; sleep 1 ;;
        esac
    done
}

_db_menu_head() {   # TITLE
    _mhdr; _c "1;33" "  ▶ $1"; echo
    _ask "部署目录" DIR "$DEFAULT_DIR"
}

menu_db_add() {
    _db_menu_head "新建数据库和用户"
    _ask "数据库名" DB_NAME ""; [[ -n "$DB_NAME" ]] || { warn "不能为空"; _pause; return; }
    _ask "用户名"   DB_USER ""; [[ -n "$DB_USER" ]] || { warn "不能为空"; _pause; return; }
    _ask "密码（留空自动生成）" DB_PW "$(randpw)"; echo
    _menu_run cmd_add_db "$DIR" "$DB_NAME" "$DB_USER" "$DB_PW" || true; _pause
}

menu_db_del() {
    _db_menu_head "删除数据库和用户"
    _menu_run cmd_list_db "$DIR" 2>/dev/null || true; echo
    _ask "数据库名" DB_NAME ""; _ask "用户名" DB_USER ""
    [[ -n "$DB_NAME" && -n "$DB_USER" ]] || { warn "不能为空"; _pause; return; }
    echo; _menu_run cmd_del_db "$DIR" "$DB_NAME" "$DB_USER" || true; _pause
}

menu_db_clear() {
    _db_menu_head "清空数据库内容（保留库和权限）"
    _menu_run cmd_list_db "$DIR" 2>/dev/null || true; echo
    _ask "数据库名" DB_NAME ""; [[ -n "$DB_NAME" ]] || { warn "不能为空"; _pause; return; }
    echo; _menu_run cmd_clear_db "$DIR" "$DB_NAME" || true; _pause
}

menu_db_list() {
    _db_menu_head "数据库 / 用户列表"; echo
    _menu_run cmd_list_db "$DIR" || true; _pause
}

menu_db_passwd() {
    _db_menu_head "修改用户密码"
    _ask "用户名" DB_USER ""; [[ -n "$DB_USER" ]] || { warn "不能为空"; _pause; return; }
    _ask "新密码（留空自动生成）" NEW_PW "$(randpw)"; echo
    _menu_run cmd_passwd "$DIR" "$DB_USER" "$NEW_PW" || true; _pause
}

menu_bk() {
    while true; do
        _mhdr; _c "1;33" "  ▶ 备份 / 恢复"; echo
        echo "  说明：全量备份 = .env+配置+pg_dumpall全库(含角色权限)+Redis数据，打包为单个 tar.gz"
        echo "        备份时可选加密（生成 .tar.gz.enc），远端/网盘被攻破也只是密文，密钥务必额外保存"
        echo "        文件可直接拷走；机器重装后用「全量恢复」一步整体拉起。"
        echo "  ─────────────────────────────────────────────"
        echo "  1) 全量备份"
        echo "  2) 全量恢复"
        echo "  3) WebDAV 远端配置（仅上传/拉取远程备份时需要）"
        echo "  ─────────────────────────────────────────────"
        echo "  0) 返回"
        echo
        read -rp "  请选择 [0-3]: " CH
        case "$CH" in
            1) menu_bk_backup        ;;
            2) menu_bk_restore       ;;
            3) menu_bk_remote_config ;;
            0) return ;;
            *) warn "无效选项"; sleep 1 ;;
        esac
    done
}

menu_bk_backup() {
    _db_menu_head "全量备份"
    echo "  保存位置？"
    echo "  1) 仅本地"
    echo "  2) 本地 + 上传到 WebDAV 远端"
    read -rp "  请选择 [1-2，默认 1]: " LOC_CH
    local _flags=() _remote=0
    if [[ "$LOC_CH" == "2" ]]; then
        if [[ -f "$DIR/.env" ]]; then load_env "$DIR"; fi
        if [[ -z "${WEBDAV_URL:-}" || -z "${WEBDAV_USER:-}" || -z "${WEBDAV_PASSWORD:-}" ]]; then
            warn "尚未配置 WebDAV 远端，先去配置一下"
            _menu_run cmd_webdav_config "$DIR" || true
            if [[ -f "$DIR/.env" ]]; then load_env "$DIR"; fi
        fi
        if [[ -n "${WEBDAV_URL:-}" && -n "${WEBDAV_USER:-}" && -n "${WEBDAV_PASSWORD:-}" ]]; then
            _flags+=("--webdav"); _remote=1
        else
            warn "未完成配置，本次改为仅本地备份"
        fi
    fi
    _ask "本地输出目录" DEST "${DIR}/backup"
    if [[ -f "$DIR/.env" ]]; then load_env "$DIR"; fi
    local _keep
    _ask "本地保留最近几份备份（0=不清理）" _keep "${LOCAL_BACKUP_KEEP:-3}"
    if [[ "$_keep" =~ ^[0-9]+$ ]]; then
        [[ "$_keep" == "${LOCAL_BACKUP_KEEP:-3}" ]] || _env_set "$DIR" "LOCAL_BACKUP_KEEP" "$_keep"
    else
        warn "份数无效，沿用 ${LOCAL_BACKUP_KEEP:-3}"
    fi
    if (( _remote )); then
        read -rp "  是否加密备份归档？[Y/n]（上传远端强烈建议加密；密钥请务必额外保存） " ENC_YN; echo
        [[ "${ENC_YN,,}" != "n" ]] && _flags+=("--encrypt")
    else
        read -rp "  是否加密备份归档？[y/N]（推荐；密钥请务必额外保存） " ENC_YN; echo
        [[ "${ENC_YN,,}" == "y" ]] && _flags+=("--encrypt")
    fi
    _menu_run cmd_backup "$DIR" "$DEST" ${_flags[@]+"${_flags[@]}"} || true; _pause
}

menu_bk_restore() {
    _db_menu_head "全量恢复"
    info "支持机器重装后的场景：DIR 可以是全新目录，将从备份归档重建全部配置和数据"
    echo "  备份来源？"
    echo "  1) 本地文件"
    echo "  2) WebDAV 远端"
    read -rp "  请选择 [1-2，默认 1]: " SRC_CH
    local BK_FILE=""
    case "$SRC_CH" in
        2)
            if [[ -f "$DIR/.env" ]]; then load_env "$DIR" 2>/dev/null || true; fi
            if [[ -z "${WEBDAV_URL:-}" || -z "${WEBDAV_USER:-}" || -z "${WEBDAV_PASSWORD:-}" ]]; then
                info "本机没有 WebDAV 配置（全新机器），请临时输入连接信息（仅本次使用，不落盘）"
                _ask "WebDAV 地址（如 https://dav.example.com/remote.php/dav/files/me）" WEBDAV_URL ""
                _ask "用户名" WEBDAV_USER ""
                read -rsp "  密码（不回显）: " WEBDAV_PASSWORD; echo
                _ask "远端备份目录" WEBDAV_REMOTE_DIR "${WEBDAV_REMOTE_DIR:-/pg-infra-backup}"
                export WEBDAV_URL WEBDAV_USER WEBDAV_PASSWORD WEBDAV_REMOTE_DIR
            fi
            info "正在列出 WebDAV 远端备份（新→旧）..."
            _menu_run cmd_webdav_list "$DIR" || warn "无法列出远端文件，请检查 WebDAV 配置/网络"
            echo
            _ask "远端文件（webdav://文件名）" BK_FILE ""
            ;;
        *)
            _ask "全量备份文件（pg-infra-full-backup_*.tar.gz 或 .tar.gz.enc）" BK_FILE ""
            ;;
    esac
    [[ -n "$BK_FILE" ]] || { warn "不能为空"; _pause; return; }
    [[ "$SRC_CH" == "2" && "$BK_FILE" != webdav://* ]] && BK_FILE="webdav://${BK_FILE}"
    echo; _menu_run cmd_restore "$DIR" "$BK_FILE" || true; _pause
}

menu_bk_remote_config() {
    _db_menu_head "配置 WebDAV 远端"
    _menu_run cmd_webdav_config "$DIR" || true; _pause
}

menu_tune() {
    while true; do
        _mhdr; _c "1;33" "  ▶ 性能调优"; echo
        echo "  1) PostgreSQL 参数（shared_buffers / work_mem / connections）"
        echo "  2) Redis 参数（maxmemory）"
        echo "  0) 返回"
        echo
        read -rp "  请选择 [0-2]: " CH
        case "$CH" in
            1) menu_tune_db    ;;
            2) menu_tune_redis ;;
            0) return ;;
            *) warn "无效选项"; sleep 1 ;;
        esac
    done
}

menu_tune_db() {
    _db_menu_head "PostgreSQL 性能调优"
    _menu_run cmd_tune_db "$DIR" || true; _pause
}

menu_tune_redis() {
    _db_menu_head "Redis 性能调优"
    _menu_run cmd_tune_redis "$DIR" || true; _pause
}

# ════════════════════════════════════════════════════════════
# 入口
# ════════════════════════════════════════════════════════════
main() {
    _check_deps
    [[ $# -eq 0 ]] && { menu_main; return; }
    local cmd="$1"; shift
    case "$cmd" in
        deploy)    cmd_deploy   "$@" ;;
        update)    cmd_update   "$@" ;;
        add-db)    cmd_add_db   "$@" ;;
        del-db)    cmd_del_db   "$@" ;;
        clear-db)  cmd_clear_db "$@" ;;
        list-db)   cmd_list_db  "$@" ;;
        passwd)    cmd_passwd   "$@" ;;
        backup)       cmd_backup       "$@" ;;
        restore)      cmd_restore      "$@" ;;
        tune-db)      cmd_tune_db      "$@" ;;
        tune-redis)   cmd_tune_redis   "$@" ;;
        webdav-config) cmd_webdav_config "$@" ;;
        webdav-list)   cmd_webdav_list   "$@" ;;
        status)    cmd_status   "$@" ;;
        start)     cmd_start    "$@" ;;
        stop)      cmd_stop     "$@" ;;
        logs)      cmd_logs     "$@" ;;
        help|--help|-h)
            sed -n '/^# 用法/,/^# ══/p' "$0" | sed 's/^# \{0,2\}//' | head -n -1 ;;
        *) error "未知子命令: ${cmd}，执行 help 查看用法" ;;
    esac
}

main "$@"
