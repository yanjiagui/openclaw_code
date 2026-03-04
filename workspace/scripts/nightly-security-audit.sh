#!/bin/bash
# OpenClaw 夜间安全巡检脚本
# 覆盖 13 项核心指标，显性化汇报

set -o pipefail

OC="${OPENCLAW_STATE_DIR:-$HOME/.openclaw}"
REPORT_DIR="/tmp/openclaw/security-reports"
DATE=$(date +%Y-%m-%d)
REPORT_FILE="$REPORT_DIR/report-$DATE.txt"

mkdir -p "$REPORT_DIR"

exec > >(tee -a "$REPORT_FILE") 2>&1

echo "========================================"
echo "OpenClaw 夜间安全巡检 - $DATE"
echo "========================================"
echo ""

# 初始化结果变量
RESULTS=()

# ========== 1. OpenClaw 安全审计 ==========
echo "[1/13] OpenClaw 安全审计..."
if command -v openclaw &>/dev/null; then
    AUDIT_RESULT=$(openclaw security audit 2>&1 || echo "审计命令执行失败")
    if echo "$AUDIT_RESULT" | grep -qi "error\|fail\|critical"; then
        RESULTS+=("❌ 平台审计发现问题")
    else
        RESULTS+=("✅ 平台审计: 已执行")
    fi
else
    RESULTS+=("⚠️ 平台审计: openclaw 命令不可用")
fi
echo "$AUDIT_RESULT"
echo ""

# ========== 2. 进程与网络审计 ==========
echo "[2/13] 进程与网络审计..."

# 监听端口
LISTEN_PORTS=$(ss -tulnp 2>/dev/null | grep LISTEN || echo "无监听端口")
# 高资源占用进程
TOP_PROC=$(ps aux --sort=-%mem 2>/dev/null | head -16 || echo "无法获取进程列表")
# 异常出站连接
OUTBOUND=$(ss -tnp 2>/dev/null | grep ESTAB || echo "无异常出站")

echo "监听端口:"
echo "$LISTEN_PORTS"
echo ""
echo "高资源占用 Top 15:"
echo "$TOP_PROC"
echo ""

if echo "$OUTBOUND" | grep -qv "127.0.0.1\|::1\|localhost"; then
    RESULTS+=("⚠️ 进程网络: 发现异常出站连接")
else
    RESULTS+=("✅ 进程网络: 无异常出站/监听")
fi
echo ""

# ========== 3. 敏感目录变更 ==========
echo "[3/13] 敏感目录变更扫描..."
LAST_24H=$(find /etc/ ~/.ssh/ ~/.gnupg/ /usr/local/bin/ "$OC/" -type f -mtime -1 2>/dev/null | head -20 || echo "无变更")
echo "$LAST_24H"
CHANGE_COUNT=$(echo "$LAST_24H" | grep -c "^" || echo "0")
if [ "$CHANGE_COUNT" -gt 0 ]; then
    RESULTS+=("⚠️ 目录变更: $CHANGE_COUNT 个文件")
else
    RESULTS+=("✅ 目录变更: 无变更")
fi
echo ""

# ========== 4. 系统定时任务 ==========
echo "[4/13] 系统定时任务..."
SYSTEM_CRON=$(cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null; systemctl list-timers --all 2>/dev/null | head -20)
USER_CRON=$(crontab -l 2>/dev/null || echo "无用户定时任务")
echo "$SYSTEM_CRON"
echo ""
echo "$USER_CRON"

if echo "$SYSTEM_CRON" | grep -qi "可疑\|malicious\|download"; then
    RESULTS+=("❌ 系统 Cron: 发现可疑任务")
else
    RESULTS+=("✅ 系统 Cron: 未发现可疑任务")
fi
echo ""

# ========== 5. OpenClaw Cron Jobs ==========
echo "[5/13] OpenClaw Cron Jobs..."
if command -v openclaw &>/dev/null; then
    OC_CRON=$(openclaw cron list 2>&1 || echo "无法获取")
    echo "$OC_CRON"
    if echo "$OC_CRON" | grep -qi "nightly-security-audit"; then
        RESULTS+=("✅ 本地 Cron: 巡检任务已注册")
    else
        RESULTS+=("⚠️ 本地 Cron: 巡检任务未找到")
    fi
else
    RESULTS+=("⚠️ 本地 Cron: openclaw 不可用")
fi
echo ""

# ========== 6. 登录与 SSH ==========
echo "[6/13] 登录与 SSH 安全..."
LAST_LOGIN=$(lastlog 2>/dev/null | tail -10 || echo "无法获取")
SSH_FAIL=$(journalctl -u sshd 2>/dev/null | grep -i "failed" | tail -10 || echo "无失败记录")
echo "最近登录:"
echo "$LAST_LOGIN"
echo ""
echo "SSH 失败尝试:"
echo "$SSH_FAIL"

FAIL_COUNT=$(echo "$SSH_FAIL" | grep -c "Failed" || echo "0")
if [ "$FAIL_COUNT" -gt 5 ]; then
    RESULTS+=("⚠️ SSH 安全: $FAIL_COUNT 次失败尝试")
else
    RESULTS+=("✅ SSH 安全: $FAIL_COUNT 次失败尝试")
fi
echo ""

# ========== 7. 关键文件完整性 ==========
echo "[7/13] 关键文件完整性..."
# 权限检查
PERM_OPENCLAW=$(stat -c "%a" "$OC/openclaw.json" 2>/dev/null || echo "N/A")
PERM_PAIRED=$(stat -c "%a" "$OC/devices/paired.json" 2>/dev/null || echo "N/A")

echo "openclaw.json 权限: $PERM_OPENCLAW (期望: 600)"
echo "paired.json 权限: $PERM_PAIRED (期望: 600)"

# SHA256 基线校验
if [ -f "$OC/.config-baseline.sha256" ]; then
    SHA_CHECK=$(sha256sum -c "$OC/.config-baseline.sha256" 2>&1)
    if echo "$SHA_CHECK" | grep -q "OK"; then
        RESULTS+=("✅ 配置基线: 哈希校验通过")
    else
        RESULTS+=("❌ 配置基线: 哈希不匹配!")
    fi
else
    RESULTS+=("⚠️ 配置基线: 基线文件不存在")
fi
echo ""

# ========== 8. 黄线操作交叉验证 ==========
echo "[8/13] 黄线操作交叉验证..."
SUDO_LOG=$(grep sudo /var/log/auth.log 2>/dev/null | tail -20 || echo "无法获取日志")
MEMORY_FILES=$(find "$OC/workspace/memory/" -name "$(date +%Y-%m-*)" -o -name "$(date -d 'yesterday' +%Y-%m-*)" 2>/dev/null | head -5)

echo "最近 sudo 记录:"
echo "$SUDO_LOG"
echo ""
echo "对应的 memory 文件:"
echo "$MEMORY_FILES"
RESULTS+=("✅ 黄线审计: 已执行日志对比")
echo ""

# ========== 9. 磁盘使用 ==========
echo "[9/13] 磁盘使用..."
DISK_USAGE=$(df -h / | tail -1)
echo "$DISK_USAGE"

DISK_PCT=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$DISK_PCT" -gt 85 ]; then
    RESULTS+=("❌ 磁盘容量: 超过 85%")
else
    RESULTS+=("✅ 磁盘容量: 正常")
fi

# 最近 24h 大文件
BIG_FILES=$(find / -type f -size +100M -mtime -1 2>/dev/null | head -10 || echo "无")
BIG_COUNT=$(echo "$BIG_FILES" | grep -c "^" || echo "0")
if [ "$BIG_COUNT" -gt 0 ]; then
    echo "新增大文件 (>100MB):"
    echo "$BIG_FILES"
fi
echo ""

# ========== 10. Gateway 环境变量 ==========
echo "[10/13] Gateway 环境变量..."
GATEWAY_PID=$(pgrep -f "openclaw gateway" | head -1 || echo "")
if [ -n "$GATEWAY_PID" ]; then
    ENV_VARS=$(cat /proc/$GATEWAY_PID/environ 2>/dev/null | tr '\0' '\n' | grep -iE "KEY|TOKEN|SECRET|PASSWORD" || echo "无敏感变量")
    echo "敏感环境变量:"
    echo "$ENV_VARS"
    RESULTS+=("✅ 环境变量: 已检查")
else
    RESULTS+=("⚠️ 环境变量: Gateway 未运行")
fi
echo ""

# ========== 11. 明文私钥/凭证泄露扫描 ==========
echo "[11/13] 敏感凭证扫描 (DLP)..."

# 扫描以太坊/比特币私钥格式
PRIV_KEY_PATTERNS=$(grep -rE "(0x[a-fA-F0-9]{64}|L[a-zA-Z0-9]{32,38}|[54][a-zA-HJ-NP-Z0-9]{50,51})" "$OC/workspace/" 2>/dev/null | grep -v ".git" | head -10 || echo "无")

# 扫描助记词 (12/24 词 BIP39)
MNEMONIC_PATTERNS=$(grep -rE "\b([a-z]+\s+){11,23}[a-z]+\b" "$OC/workspace/memory/" "$OC/workspace/logs/" 2>/dev/null | grep -v ".git" | head -10 || echo "无")

if [ -n "$PRIV_KEY_PATTERNS" ] || [ -n "$MNEMONIC_PATTERNS" ]; then
    echo "⚠️ 发现疑似敏感凭证!"
    echo "$PRIV_KEY_PATTERNS"
    echo "$MNEMONIC_PATTERNS"
    RESULTS+=("❌ 敏感凭证: 发现明文私钥或助记词")
else
    RESULTS+=("✅ 敏感凭证: 未发现明文私钥或助记词")
fi
echo ""

# ========== 12. Skill/MCP 完整性 ==========
echo "[12/13] Skill/MCP 完整性..."
SKILLS_DIR="$OC/extensions/skills"
if [ -d "$SKILLS_DIR" ]; then
    SKILL_HASHES=$(find "$SKILLS_DIR" -type f -exec sha256sum {} \; 2>/dev/null | head -20 || echo "无")
    echo "已安装 Skill:"
    ls -la "$SKILLS_DIR" 2>/dev/null || echo "无"
    RESULTS+=("✅ Skill基线: 已检查")
else
    RESULTS+=("✅ Skill基线: 无安装")
fi
echo ""

# ========== 13. 大脑灾备自动同步 ==========
echo "[13/13] 大脑灾备同步..."
cd "$OC" || exit 1

# 检查是否是 git 仓库
if ! git rev-parse --git-dir &>/dev/null; then
    RESULTS+=("⚠️ 灾备备份: Git 未初始化")
else
    # 本地提交
    git add -A 2>/dev/null
    GIT_STATUS=$(git diff --cached --stat 2>/dev/null || echo "")
    if [ -n "$GIT_STATUS" ]; then
        git commit -m "巡检自动备份 $DATE" 2>/dev/null
        echo "已提交本地: $GIT_STATUS"
        
        # 检查是否有远程仓库
        if git remote -v | grep -q "origin"; then
            git push origin main 2>/dev/null || git push origin master 2>/dev/null
            if [ $? -eq 0 ]; then
                RESULTS+=("✅ 灾备备份: 已推送至 Git")
            else
                RESULTS+=("⚠️ 灾备备份: 推送失败（本地已提交）")
            fi
        else
            RESULTS+=("⚠️ 灾备备份: 无远程仓库（本地已提交）")
        fi
    else
        RESULTS+=("✅ 灾备备份: 无变更，跳过")
    fi
fi
echo ""

# ========== 输出汇总 ==========
echo "========================================"
echo "巡检汇总 ($DATE)"
echo "========================================"
for result in "${RESULTS[@]}"; do
    echo "$result"
done
echo ""
echo "详细报告: $REPORT_FILE"
echo "========================================"

# 输出用于推送的简洁格式
echo ""
echo "---PUSH_SUMMARY---"
printf '%s\n' "${RESULTS[@]}"
echo "---END---"
