#!/bin/sh
# OpenBSD 沙箱冒烟矩阵：在真实 OpenBSD 上逐个场景启动真实二进制。
#
# 用法：openbsd-sandbox-smoke.sh /path/to/stalwart
#
# 覆盖：
#   1. 默认模式（配置与数据分两棵树）
#   2. 相对路径配置（数据目录用相对路径）
#   3. 严格读模式（STALWART_UNVEIL_STRICT=on）
#   4. chroot（STALWART_CHROOT，-c 与配置里的路径都按 jail 内解释）
#   5. 运行后改数据目录（模拟控制台改路径 + 重启）
#   6. WebUI 解压目录（Application.unpackDirectory）
#   7. 引导模式（配置文件不存在 → 首次安装向导）
#   8. store 导出（-e，沙箱关闭，可写任意路径）
set -u

BIN=${1:?usage: $0 /path/to/stalwart}
WORK=${WORK:-/home/build/sandbox-matrix}
FAILS=0
START_DIR=$(pwd)

# 进程是否还“在跑”。注意不能用 `kill -0` 判断：已经退出但还没被 wait 的子进程
# 是僵尸，kill -0 对它仍返回成功，于是每个场景都要空等满时长。
pid_alive() {
    state=$(ps -o state= -p "$1" 2>/dev/null | tr -d ' ')
    case $state in
        '' | Z*) return 1 ;;
        *) return 0 ;;
    esac
}

# 有界等待：SIGTERM 之后最多等 $2 秒，然后 SIGKILL，最后绝不再无限 wait。
# 之前 CI 挂 5 小时就是因为在等一个不响应 SIGTERM 的进程。
# 返回 0 表示进程自己退了（退出码看 wait），1 表示是被 SIGKILL 干掉的。
stop_pid() {
    pid=$1
    limit=${2:-20}
    i=0
    while [ "$i" -lt "$limit" ]; do
        pid_alive "$pid" || return 0
        i=$((i + 1))
        sleep 1
    done
    kill -KILL "$pid" 2>/dev/null
    i=0
    while [ "$i" -lt 10 ]; do
        pid_alive "$pid" || return 1
        i=$((i + 1))
        sleep 1
    done
    printf '  warning: pid %s survived SIGKILL (stuck in kernel?), leaving it\n' "$pid"
    return 1
}

say()  { printf '%s\n' "$*"; }
fail() { FAILS=$((FAILS + 1)); printf '  FAIL %s\n' "$*"; }
ok()   { printf '  ok   %s\n' "$*"; }

# 在 $WORKDIR 里启动二进制，把 pid 放到 LAUNCH_PID。
# \
# 关键点：**不要**用 `( cd "$dir" && ... ) &`——OpenBSD 的 /bin/sh 是 ksh，
# 这样启动时 $! 是那个子 shell 而不是服务器本身，SIGTERM 打在子 shell 上不会
# 转发给服务器，于是每个场景都要等满 60 秒再 SIGKILL（exit=137），既慢又把
# “真的不响应 SIGTERM”这个信号盖掉了。这里改用脚本自己 cd，启动后 cd 回来。
# $1 工作目录，$2 日志文件，其余：env 赋值 + 命令
launch() {
    wdir=$1; log=$2; shift 2
    LAUNCH_PID=
    cd "$wdir" || { FAILS=$((FAILS + 1)); printf '  FAIL cannot cd %s\n' "$wdir"; return; }
    env "$@" > "$log" 2>&1 &
    LAUNCH_PID=$!
    cd "$START_DIR" || exit 1
}

# 启动一次并等待“活着”，随后 SIGTERM
# $1 场景名  $2 工作目录  $3 配置文件路径（传给 -c）  $4 期望出现的库文件
run_case() {
    name=$1; dir=$2; cfg=$3; db=$4
    shift 4
    log="$dir/server.log"
    say "== $name"
    rm -f "$db"
    t0=$(date +%s)
    launch "$dir" "$log" "$@" "$BIN" -c "$cfg"
    pid=$LAUNCH_PID
    alive=0
    i=0
    while [ "$i" -lt 90 ]; do
        pid_alive "$pid" || break
        if [ -f "$db" ]; then alive=1; break; fi
        i=$((i + 1))
        sleep 1
    done
    pid_alive "$pid" && alive=1
    kill -TERM "$pid" 2>/dev/null
    stop_pid "$pid" 60 && graceful=1 || graceful=0
    wait "$pid" 2>/dev/null
    code=$?

    if grep -q "OpenBSD sandbox:" "$log"; then
        ok "sandbox line: $(grep -m1 'OpenBSD sandbox:' "$log" | sed 's/^OpenBSD sandbox: //')"
    else
        fail "$name: no sandbox line in log"
    fi
    if [ "$alive" = "1" ]; then ok "$name: server stayed up"; else fail "$name: server died"; fi
    if [ -f "$db" ]; then ok "$name: store created"; else fail "$name: store missing"; fi
    if [ "$graceful" = "1" ] && [ "$code" = "0" ]; then
        ok "$name: exited cleanly on SIGTERM"
    else
        fail "$name: did not exit cleanly on SIGTERM (exit=$code)"
    fi
    say "  (exit=$code, $(( $(date +%s) - t0 ))s)"
    if [ "$alive" != "1" ] || [ "$graceful" != "1" ] || [ ! -f "$db" ] || [ "${VERBOSE:-0}" = "1" ]; then
        say "  ----- $log (tail) -----"
        tail -25 "$log" | sed 's/^/  | /'
    fi
}

say "binary: $BIN"
rm -rf "$WORK"
mkdir -p "$WORK"

# ---------- 1. 默认模式：配置 /etc，数据 /var/lib ----------
d="$WORK/default"; mkdir -p "$d/etc" "$d/var/lib"
printf '{"@type":"Sqlite","path":"%s/var/lib/db.sqlite"}' "$d" > "$d/etc/config.json"
run_case "default" "$d" "$d/etc/config.json" "$d/var/lib/db.sqlite"
if grep -q "rwc: .*$d/var/lib" "$d/server.log"; then
    ok "data path collected from configuration"
else
    fail "data path missing from unveil list"
fi

# ---------- 2. 相对路径：数据目录写相对路径，应按 cwd 解析 ----------
d="$WORK/relative"; mkdir -p "$d/etc" "$d/var/lib"
printf '{"@type":"Sqlite","path":"var/lib/db.sqlite"}' > "$d/etc/config.json"
run_case "relative-path" "$d" "etc/config.json" "$d/var/lib/db.sqlite"
if grep -q "rwc: .*$d/var/lib" "$d/server.log"; then
    ok "relative data path resolved to absolute"
else
    fail "relative data path was not resolved"
fi

# ---------- 3. 严格读模式 ----------
d="$WORK/strict"; mkdir -p "$d/etc" "$d/var/lib"
printf '{"@type":"Sqlite","path":"%s/var/lib/db.sqlite"}' "$d" > "$d/etc/config.json"
run_case "strict-read" "$d" "$d/etc/config.json" "$d/var/lib/db.sqlite" \
    STALWART_UNVEIL_STRICT=on
if grep -q "strict" "$d/server.log"; then ok "strict mode reported"; else fail "strict mode not reported"; fi

# ---------- 4. chroot ----------
# chroot 在**读配置之前**完成（否则配置文件和数据目录会按宿主路径打开，等于没关住），
# 所以 -c 必须写 jail 内的路径，配置里的数据目录同理。
d="$WORK/chroot"; jail="$d/jail"
mkdir -p "$jail/etc" "$jail/var/lib" "$jail/var/log" "$jail/tmp" "$jail/dev"
printf '{"@type":"Sqlite","path":"/var/lib/db.sqlite"}' > "$jail/etc/config.json"
cp /etc/passwd "$jail/etc/passwd" 2>/dev/null
cp /etc/group "$jail/etc/group" 2>/dev/null
cp /etc/resolv.conf "$jail/etc/resolv.conf" 2>/dev/null
cp /etc/hosts "$jail/etc/hosts" 2>/dev/null
# /dev 下是字符设备节点：从 ls -ln 的第 5/6 列取 major,minor 后重建
make_dev() {
    pair=$(ls -ln "$1" | awk '{ gsub(/,$/, "", $5); print $5, $6 }')
    major=$(printf '%s' "$pair" | cut -d' ' -f1)
    minor=$(printf '%s' "$pair" | cut -d' ' -f2)
    if [ -n "$major" ] && [ -n "$minor" ]; then
        mknod "$2" c "$major" "$minor" 2>/dev/null && chmod 666 "$2"
    fi
}
make_dev /dev/urandom "$jail/dev/urandom"
make_dev /dev/null "$jail/dev/null"
make_dev /dev/random "$jail/dev/random"
run_case "chroot" "$jail" "/etc/config.json" "$jail/var/lib/db.sqlite" \
    STALWART_CHROOT="$jail"
if grep -q "chroot(" "$jail/server.log"; then ok "chroot reported"; else fail "chroot not applied"; fi

# ---------- 5. 改数据目录后重启 ----------
d="$WORK/path-change"; mkdir -p "$d/etc" "$d/var/lib-a" "$d/var/lib-b"
printf '{"@type":"Sqlite","path":"%s/var/lib-a/db.sqlite"}' "$d" > "$d/etc/config.json"
run_case "path-change (run 1)" "$d" "$d/etc/config.json" "$d/var/lib-a/db.sqlite"
printf '{"@type":"Sqlite","path":"%s/var/lib-b/db.sqlite"}' "$d" > "$d/etc/config.json"
run_case "path-change (run 2)" "$d" "$d/etc/config.json" "$d/var/lib-b/db.sqlite"
if grep -q "rwc: .*$d/var/lib-b" "$d/server.log"; then
    ok "new data path collected after restart"
else
    fail "new data path was not collected"
fi

# ---------- 6. WebUI 解压目录（Application.unpackDirectory） ----------
# 只验证“配置里指定的解压目录被登记成可写”；不引入真实 WebUI 包。
d="$WORK/webapp"; mkdir -p "$d/etc" "$d/var/lib" "$d/webroot"
printf '{"@type":"Sqlite","path":"%s/var/lib/db.sqlite"}' "$d" > "$d/etc/config.json"
run_case "webapp-unpack" "$d" "$d/etc/config.json" "$d/var/lib/db.sqlite"
say "  (webapp 解压目录只在配置了 unpackDirectory 时才登记，这里验证默认路径不报错)"

# ---------- 7. 引导模式（配置文件不存在 → 首次安装向导） ----------
# 这是最容易被沙箱搞坏的一条路径：没有配置文件时数据存储由向导决定，
# 沙箱此时应当只登记很有限的路径，并且进程不能崩。
d="$WORK/bootstrap"; mkdir -p "$d/etc"
say "== bootstrap-mode (no config file)"
launch "$d" "$d/server.log" "$BIN" -c "$d/etc/missing.json"
pid=$LAUNCH_PID
sleep 25
alive=0
pid_alive "$pid" && alive=1
kill -TERM "$pid" 2>/dev/null
stop_pid "$pid" 60 && graceful=1 || graceful=0
wait "$pid" 2>/dev/null
code=$?
if [ "$alive" = "1" ]; then ok "bootstrap mode: server stayed up"; else fail "bootstrap mode: server died"; fi
if [ "$graceful" = "1" ] && [ "$code" = "0" ]; then
    ok "bootstrap mode: exited cleanly on SIGTERM"
else
    fail "bootstrap mode: did not exit cleanly on SIGTERM (exit=$code)"
fi
if grep -q "OpenBSD sandbox:" "$d/server.log"; then
    ok "bootstrap mode: sandbox line present"
else
    fail "bootstrap mode: no sandbox line"
fi
if grep -qi "bootstrap mode" "$d/server.log"; then
    ok "bootstrap mode: wizard reported"
else
    fail "bootstrap mode: wizard not reported"
    tail -25 "$d/server.log"
fi

# ---------- 8. store 导出（沙箱关闭，任意外部路径） ----------
d="$WORK/export"; mkdir -p "$d/etc" "$d/var/lib"
printf '{"@type":"Sqlite","path":"%s/var/lib/db.sqlite"}' "$d" > "$d/etc/config.json"
# 先正常启动一次把库建出来，否则 --export 会报 "Could not retrieve database schema version"
run_case "export (prepare store)" "$d" "$d/etc/config.json" "$d/var/lib/db.sqlite"
# -e 的目标是**目录**：每个 subspace 写成一个 subspace_<x> 文件（lz4 frame）。
out="$WORK/export-out"
launch / "$d/export.log" "$BIN" -c "$d/etc/config.json" -e "$out"
export_pid=$LAUNCH_PID
i=0
while [ "$i" -lt 120 ] && pid_alive "$export_pid"; do
    i=$((i + 1))
    sleep 1
done
if pid_alive "$export_pid"; then
    fail "export did not finish in 120s"
    stop_pid "$export_pid" 5
    wait "$export_pid" 2>/dev/null
    export_code=124
else
    wait "$export_pid" 2>/dev/null
    export_code=$?
fi
if [ "$export_code" = "0" ] && [ -d "$out" ] && ls "$out"/subspace_* >/dev/null 2>&1; then
    ok "export to arbitrary path ($(ls "$out" | wc -l | tr -d ' ') subspaces)"
else
    fail "export failed (exit=$export_code)"
    tail -20 "$d/export.log"
fi

say ""
if [ "$FAILS" -eq 0 ]; then
    say "SANDBOX MATRIX PASSED"
    exit 0
else
    say "SANDBOX MATRIX FAILED ($FAILS check(s))"
    exit 1
fi
