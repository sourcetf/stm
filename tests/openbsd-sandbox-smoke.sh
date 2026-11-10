#!/bin/sh
# OpenBSD 沙箱冒烟矩阵：在真实 OpenBSD 上逐个场景启动真实二进制。
#
# 用法：openbsd-sandbox-smoke.sh /path/to/stalwart
#
# 覆盖：
#   1. 默认模式（配置与数据分两棵树）
#   2. 相对路径配置（数据目录用相对路径）
#   3. 严格读模式（STALWART_UNVEIL_STRICT=on）
#   4. chroot（STALWART_CHROOT）
#   5. 运行后改数据目录（模拟控制台改路径 + 重启）
#   6. store 导出（-e，沙箱此时应关闭，可写任意路径）
set -u

BIN=${1:?usage: $0 /path/to/stalwart}
WORK=${WORK:-/home/build/sandbox-matrix}
FAILS=0

# 有界等待：SIGTERM 之后最多等 $2 秒，然后 SIGKILL，最后绝不再无限 wait。
# 之前 CI 挂 5 小时就是因为在等一个不响应 SIGTERM 的进程。
stop_pid() {
    pid=$1
    limit=${2:-20}
    i=0
    while [ "$i" -lt "$limit" ]; do
        kill -0 "$pid" 2>/dev/null || return 0
        i=$((i + 1))
        sleep 1
    done
    kill -KILL "$pid" 2>/dev/null
    i=0
    while [ "$i" -lt 5 ]; do
        kill -0 "$pid" 2>/dev/null || return 0
        i=$((i + 1))
        sleep 1
    done
    printf '  warning: pid %s survived SIGKILL (stuck in kernel?), leaving it
' "$pid"
}

say()  { printf '%s\n' "$*"; }
fail() { FAILS=$((FAILS + 1)); printf '  FAIL %s\n' "$*"; }
ok()   { printf '  ok   %s\n' "$*"; }

# 启动一次并等待“活着”，随后 SIGTERM
# $1 场景名  $2 工作目录  $3 配置文件路径（传给 -c）  $4 期望出现的库文件
run_case() {
    name=$1; dir=$2; cfg=$3; db=$4
    shift 4
    log="$dir/server.log"
    say "== $name"
    rm -f "$db"
    ( cd "$dir" && env "$@" "$BIN" -c "$cfg" ) > "$log" 2>&1 &
    pid=$!
    alive=0
    i=0
    while [ "$i" -lt 90 ]; do
        kill -0 "$pid" 2>/dev/null || break
        if [ -f "$db" ]; then alive=1; break; fi
        i=$((i + 1))
        sleep 1
    done
    kill -0 "$pid" 2>/dev/null && alive=1
    kill -TERM "$pid" 2>/dev/null
    stop_pid "$pid" 60
    wait "$pid" 2>/dev/null
    code=$?

    if grep -q "OpenBSD sandbox:" "$log"; then
        ok "sandbox line: $(grep -m1 'OpenBSD sandbox:' "$log" | sed 's/^OpenBSD sandbox: //')"
    else
        fail "$name: no sandbox line in log"
    fi
    if [ "$alive" = "1" ]; then ok "$name: server stayed up"; else fail "$name: server died"; fi
    if [ -f "$db" ]; then ok "$name: store created"; else fail "$name: store missing"; fi
    say "  (exit=$code)"
    if [ "$alive" != "1" ] || [ ! -f "$db" ] || [ "${VERBOSE:-0}" = "1" ]; then
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
d="$WORK/chroot"; jail="$d/jail"
mkdir -p "$jail/etc" "$jail/var/lib" "$jail/dev"
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
# 配置文件是在 chroot 之前读的，所以 -c 要传【宿主】路径；
# 而配置里的数据目录写的是【jail 内】路径（chroot 之后才用）。
run_case "chroot" "$d" "$jail/etc/config.json" "$jail/var/lib/db.sqlite" \
    STALWART_CHROOT="$jail"
if grep -q "chroot(" "$d/server.log"; then ok "chroot reported"; else fail "chroot not applied"; fi

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
( cd "$d" && "$BIN" -c "$d/etc/missing.json" ) > "$d/server.log" 2>&1 &
pid=$!
sleep 25
alive=0
kill -0 "$pid" 2>/dev/null && alive=1
kill -TERM "$pid" 2>/dev/null
stop_pid "$pid" 60
wait "$pid" 2>/dev/null
if [ "$alive" = "1" ]; then ok "bootstrap mode: server stayed up"; else fail "bootstrap mode: server died"; fi
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
out="$WORK/export-out.bin"
( cd / && "$BIN" -c "$d/etc/config.json" -e "$out" ) > "$d/export.log" 2>&1 &
export_pid=$!
i=0
while [ "$i" -lt 120 ] && kill -0 "$export_pid" 2>/dev/null; do
    i=$((i + 1))
    sleep 1
done
if kill -0 "$export_pid" 2>/dev/null; then
    fail "export did not finish in 120s"
    stop_pid "$export_pid" 5
else
    wait "$export_pid" 2>/dev/null
fi
if [ -f "$out" ]; then ok "export to arbitrary path"; else fail "export failed"; tail -20 "$d/export.log"; fi

say ""
if [ "$FAILS" -eq 0 ]; then
    say "SANDBOX MATRIX PASSED"
    exit 0
else
    say "SANDBOX MATRIX FAILED ($FAILS check(s))"
    exit 1
fi
