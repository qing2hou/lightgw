#!/bin/sh
# HAProxyWeb 每日数据库备份（被 deploy/haproxyweb-backup.service 调用）。
# 前置依赖：sqlite3 命令行（缺它备份会静默失败，故先显式检查）。
# 可选异地推送：设置环境变量 HAWEB_BACKUP_PUSH_CMD（rsync/rclone 等接收
# 备份文件路径 $1 的命令），例如 deploy 单元中：
#   Environment=HAWEB_BACKUP_PUSH_CMD=rclone copy %t/backup remote:haproxyweb
set -eu

# 快照含密码哈希与两步验证密钥，收紧权限防同机其他用户读取
umask 077

DATA_DIR="${HAWEB_DATA_DIR:-/var/lib/haproxyweb}"
DB="$DATA_DIR/haproxyweb.db"
BACKUP_DIR="$DATA_DIR/backups"
KEEP=30

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "[backup] 错误：未安装 sqlite3 命令行，无法备份（apt install sqlite3）" >&2
    exit 1
fi
if [ ! -f "$DB" ]; then
    echo "[backup] 错误：数据库不存在: $DB" >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR"
dest="$BACKUP_DIR/haproxyweb-$(date +%F).db"
# sqlite3 .backup 在线快照（不阻塞业务读写）
sqlite3 "$DB" ".backup '$dest'"

# 可选：推送异地（命令失败不删本地备份，但以非零退出让 systemd 单元转 failed 可见）
if [ -n "${HAWEB_BACKUP_PUSH_CMD:-}" ]; then
    sh -c "$HAWEB_BACKUP_PUSH_CMD '$dest'" || {
        echo "[backup] 警告：异地推送失败，本地备份保留: $dest" >&2
        exit 1
    }
fi

# 保留 $KEEP 份，更早的清理
find "$BACKUP_DIR" -name "haproxyweb-*.db" -mtime +$KEEP -delete
echo "[backup] 备份完成: $dest"
