#!/bin/ksh
#
# openbsd.sh — OpenBSD 上 Stalwart Mail Server 一键初始化
#
#   阶段0  前置检查，停掉冲突进程（旧实例 / OpenSMTPD）
#   阶段1  目录与权限（/etc/stalwart  /var/stalwart  /var/log/stalwart）
#   阶段2  已初始化 → 修 rcctl 参数直接启动（幂等入口）
#          未初始化 → bootstrap 向导（打印临时账号，自动等待保存）
#   阶段3  rcctl 托管 + 监听自检（IPv6-only 绑定告警）
# just for test, for any bugs please open prs or issues
# 重跑安全：已装好再跑 = 只修权限/参数 + 重启，不动数据。

SVC="_stalwart-smtp"
BIN="/usr/local/bin/stalwart"
RC="stalwart_mail"
CONF_DIR="/etc/stalwart"
CONF="$CONF_DIR/config.json"
DATA="/var/stalwart"
LOGD="/var/log/stalwart"
BOOT_LOG="/tmp/stalwart-bootstrap.log"
WIZARD_TIMEOUT=3600          # 等向导保存配置的上限（秒）
PORTS='(25|80|443|465|587|143|993|995|4190|8080)'

G='\033[1;32m'; Y='\033[1;33m'; R='\033[1;31m'; N='\033[0m'
msg()  { printf "${G}==>${N} %s\n" "$*"; }
warn() { printf "${Y}警告:${N} %s\n" "$*" >&2; }
die()  { printf "${R}错误:${N} %s\n" "$*" >&2; exit 1; }

SU_PID=""

cleanup() {
    kill -TERM "$SU_PID" 2>/dev/null
    pkill -TERM -u "$SVC" -x stalwart 2>/dev/null
    sleep 2
    pkill -KILL -u "$SVC" -x stalwart 2>/dev/null
    exit 1
}

handover() {
    chown -R "$SVC:$SVC" "$DATA" "$CONF_DIR" "$LOGD"
    rcctl enable "$RC"
    rcctl set "$RC" user "$SVC"
    rcctl set "$RC" flags -c "$CONF"
    rcctl start "$RC"
    sleep 3
}

verify() {
    if ! rcctl check "$RC" >/dev/null 2>&1; then
        warn "$RC 未在运行，排查："
        echo "  rcctl -d start $RC"
        echo "  cd $DATA && su -s /bin/sh $SVC -c '$BIN -c $CONF'"
        return 1
    fi
    msg "服务运行中"
    # IPv4/IPv6 监听自检（OpenBSD 下 IPv6 通配 socket 不接 IPv4）
    v4=$(netstat -an | grep '^tcp[[:space:]]' | grep LISTEN \
         | grep -v '127\.0\.0\.1' | grep -Ec "\.$PORTS[[:space:]]")
    v6=$(netstat -an | grep '^tcp6' | grep LISTEN \
         | grep -v '::1' | grep -Ec "\.$PORTS[[:space:]]")
    if [ "$v4" -eq 0 ] && [ "$v6" -gt 0 ]; then
        warn "监听全部在 IPv6，外部 IPv4 连不上！修复方法："
        echo "  Web 界面 → Settings → Network → Listeners"
        echo "  把绑定地址 [::] 改为 0.0.0.0（25 端口如保留本机 smtpd 则填公网 IP）"
        echo "  然后: rcctl restart $RC"
    fi
    netstat -an | grep LISTEN | grep -E "\.$PORTS[[:space:]]" | sed 's/^/  /'
}

summary() {
    IP=$(ifconfig 2>/dev/null | awk '/inet / && $2 !~ /^(127\.|169\.254\.)/ {print $2; exit}')
    [ -n "$IP" ] || IP="<服务器IP>"
    echo
    msg "全部完成"
    echo "  服务管理 : rcctl {start|stop|restart|check} $RC"
    echo "  配置文件 : $CONF  （仅数据存储指向；其余设置存于数据库，用 Web 界面改）"
    echo "  数据目录 : $DATA   应用日志: $DATA/logs/（自滚动）"
    echo "  管理界面 : https://$IP/ 或 http://$IP:8080/（以监听器实际配置为准）"
    echo "  改监听   : Web 界面 → Settings → Network → Listeners，改完 rcctl restart $RC"
}

# ---------- 阶段0：前置检查 ----------
[ "$(id -u)" -eq 0 ] || die "请用 root/doas 运行"
[ -x "$BIN" ] || die "缺少 $BIN（先 pkg_add stalwart-mail）"
id "$SVC" >/dev/null 2>&1 || die "用户 $SVC 不存在（包安装异常）"
[ -f "/etc/rc.d/$RC" ] || die "缺 /etc/rc.d/$RC"

if pgrep -x relayd >/dev/null 2>&1; then
    warn "relayd 正在运行：若它占用 443/587，Stalwart 会绑定失败，请先理顺端口分工"
fi

msg "停止旧实例与 OpenSMTPD（25 端口冲突）"
rcctl stop "$RC" >/dev/null 2>&1
pkill -TERM -u "$SVC" -x stalwart 2>/dev/null
sleep 1
pkill -KILL -u "$SVC" -x stalwart 2>/dev/null

if pgrep -x smtpd >/dev/null 2>&1; then
    rcctl stop smtpd
    rcctl disable smtpd
    warn "已停用 smtpd。若之后还需要它收本机邮件，让 Stalwart 的 25 监听只绑公网 IP 即可共存"
fi

# ---------- 阶段1：目录与权限 ----------
msg "创建/修正目录属主与权限"
install -d -o "$SVC" -g "$SVC" -m 0750 "$CONF_DIR" "$LOGD" "$DATA"
for d in data db etc logs queue reports blob tmp; do
    install -d -o "$SVC" -g "$SVC" -m 0750 "$DATA/$d"
done
chown -R "$SVC:$SVC" "$DATA" "$CONF_DIR" "$LOGD"
find "$DATA" "$CONF_DIR" "$LOGD" -type d -exec chmod 0750 {} +
find "$DATA" "$CONF_DIR" "$LOGD" -type f -exec chmod 0640 {} +

# 空的 config.json 会被判为解析错误而不是 bootstrap，先挪走
if [ -f "$CONF" ] && [ ! -s "$CONF" ]; then
    warn "$CONF 是空文件，移走为 $CONF.empty.bak"
    mv "$CONF" "$CONF.empty.bak"
fi

# ---------- 阶段2a：已初始化 → 直接接管 ----------
if [ -s "$CONF" ]; then
    msg "检测到已有配置 $CONF，跳过向导直接交给 rcctl"
    chown "$SVC:$SVC" "$CONF"
    handover
    verify || exit 1
    summary
    exit 0
fi

# ---------- 阶段2b：bootstrap 向导 ----------
msg "启动 bootstrap（用户=$SVC CWD=$DATA）"
: > "$BOOT_LOG"
( cd "$DATA" && exec su -s /bin/sh "$SVC" -c \
    "STALWART_PATH=$DATA $BIN -c $CONF" ) > "$BOOT_LOG" 2>&1 &
SU_PID=$!
trap cleanup INT TERM

msg "等待 bootstrap HTTP 就绪（8080）"
i=0
while [ "$i" -lt 90 ]; do
    netstat -an | grep LISTEN | grep -q '\.8080[[:space:]]' && break
    kill -0 "$SU_PID" 2>/dev/null || \
        { tail -30 "$BOOT_LOG"; die "bootstrap 进程退出，日志见上（$BOOT_LOG）"; }
    sleep 1; i=$((i+1))
done

B_USER=$(awk '/username:/ {print $2; exit}' "$BOOT_LOG")
B_PASS=$(awk '/password:/ {print $2; exit}' "$BOOT_LOG")
IP=$(ifconfig 2>/dev/null | awk '/inet / && $2 !~ /^(127\.|169\.254\.)/ {print $2; exit}')
[ -n "$IP" ] || IP="<服务器IP>"

echo
echo "==================================================================="
echo "  浏览器打开 : http://$IP:8080/admin"
echo "               （不通就打隧道: ssh -L 8080:127.0.0.1:8080 root@$IP）"
echo "  临时账号   : ${B_USER:-见 $BOOT_LOG 的 username 行}"
echo "  临时密码   : ${B_PASS:-见 $BOOT_LOG 的 password 行}"
echo "-------------------------------------------------------------------"
echo "  向导要点："
echo "   * 存储路径一律填【绝对路径】(/var/stalwart/...)"
echo "   * 完成管理员创建并保存，配置写入 $CONF 后脚本自动继续"
echo "==================================================================="
echo

msg "等待向导保存配置（出现非空 $CONF，最长 $((WIZARD_TIMEOUT/60)) 分钟）"
i=0
while [ "$i" -lt "$WIZARD_TIMEOUT" ]; do
    [ -s "$CONF" ] && break
    if ! kill -0 "$SU_PID" 2>/dev/null; then
        sleep 3
        [ -s "$CONF" ] && break
        tail -30 "$BOOT_LOG"
        cleanup
    fi
    sleep 2; i=$((i+2))
done
[ -s "$CONF" ] || { warn "等待超时，重跑本脚本即可继续"; cleanup; }

msg "配置已生成，停止 bootstrap 实例"
sleep 3
trap - INT TERM
pkill -TERM -u "$SVC" -x stalwart 2>/dev/null
i=0
while pgrep -u "$SVC" -x stalwart >/dev/null 2>&1 && [ "$i" -lt 10 ]; do
    sleep 1; i=$((i+1))
done
pkill -KILL -u "$SVC" -x stalwart 2>/dev/null

# ---------- 阶段3：rcctl 托管 + 自检 ----------
msg "交给 rcctl 托管"
handover
verify || exit 1
summary
