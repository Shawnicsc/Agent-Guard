"""沙箱绊网：exec 命令执行前逐条扫描高危行为模式（rehearsal 阶段 2）。

沙箱隔离性把恶意行为变成无害可观测事件：network=none 让外传必然失败、
敏感路径在容器内不存在、提权被 cap-drop 拒绝。绊网把这些尝试本身
升级为检测信号（TRIPWIRE_HIT 审计事件），供彩排层做行为证据研判。

四类信号（rehearsal_plan 阶段 2）：
- egress               出口尝试：curl/wget 等网络客户端（容器无网络，失败即高置信信号）
- sensitive_path       敏感路径探测：宿主凭据、提权目标文件、宿主侧路径
- privilege_escalation 提权尝试：sudo/mount/setuid 等
- data_staging         敏感数据搬运：工作区内容向 /tmp 汇聚、base64 编码等外传前置动作

匹配前先做与策略引擎 command_pattern 相同的规范化（NFKC + 不可见字符剥离
+ 有界 base64 解码变体），防止全角符号/编码绕过。绊网只观测不拦截：
是否处置由彩排裁决层决定（阶段 3 回填策略引擎）。
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from guard.gateway.normalize import decoded_variants, normalize_command_text

# 与 guard.gateway.normalize._INVISIBLE_RE 同源的不可见字符集
_INVISIBLE_RE = re.compile("[​‌‍⁠﻿­\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True)
class TripwireHit:
    """一次绊网命中。snippet 为命中附近的命令片段（审计证据）。"""

    signal: str  # egress / sensitive_path / privilege_escalation / data_staging
    rule_id: str
    command: str  # 触发扫描的原始命令
    snippet: str  # 命中位置的上下文片段

    def payload(self) -> dict:
        return {"signal": self.signal, "rule_id": self.rule_id,
                "command": self.command, "snippet": self.snippet}


# ---- 出口尝试 ----
# 网络客户端必须出现在命令位（行首，或 ; | & ` $( 之后，允许 sudo/nohup/timeout 前缀），
# 避免 "grep curl 文件" 这类参数位置引用误报。python 内联网络调用按内容匹配。
_EGRESS_CMDPOS_RE = re.compile(
    r"(?:^|[;|&`$(\n])\s*(?:sudo\s+|nohup\s+|timeout\s+\d+\s+)*"
    r"(?:curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|rsync|"
    r"telnet|ftp|tftp|ping|dig|nslookup|whois)(?=[\s;&|)]|$)"
)
_EGRESS_CONTENT_RE = re.compile(
    r"(?:urllib\.request|urlopen|requests\.(?:get|post)|socket\.connect|httpx)"
)

# ---- 敏感路径：宿主凭据 / 提权目标 / 宿主侧路径（容器内本不该被引用） ----
_SENSITIVE_PATH_RE = re.compile(
    r"(?:/etc/(?:shadow|sudoers|gshadow)|/root/|\.ssh|id_rsa|id_ed25519|"
    r"authorized_keys|/proc/1/|/var/log/(?:auth|secure)|docker\.sock|"
    r"\.aws/credentials|\.kube/config|\.gnupg|/home/[A-Za-z0-9_-]+/|"
    r"/Users/[A-Za-z0-9_-]+/|/new_data/)"
)

# ---- 提权尝试（chmod 数字位含 setuid/setgid：2xxx/4xxx/6xxx） ----
_PRIV_ESC_RE = re.compile(
    r"(?:^|[\s;&|(])(?:sudo|sudoedit|mount|umount|unshare|nsenter|setpriv|"
    r"capsh|pkexec)(?=[\s;&|)]|$)"
    r"|\bsu\s+(?:-\s*)?[A-Za-z0-9_.-]+"
    r"|chown\s+(?:root|0)\s"
    r"|chmod\s+(?:[ug]*[+-]s|[0-7]*[246][0-7]{3})\b"
    r"|--cap-add"
)

# ---- 敏感数据搬运：工作区内容向临时区汇聚 / base64 编码（外传前置动作） ----
_WS = r"(?:/data|/workspace|\./)"
_SINK = r"(?:/tmp|/dev/shm)"
_STAGING_RE = re.compile(
    # base64：管道喂入 或 以工作区文件为输入
    rf"(?:\|\s*base64|base64\s+(?:-w\s+\d+\s+)?{_WS})"
    # 归档工作区到临时区：tar/zip/gzip 同时引用工作区与临时区（顺序不限）
    rf"|(?:tar|zip|gzip)[^;|]*{_WS}[^;|]*{_SINK}"
    rf"|(?:tar|zip|gzip)[^;|]*{_SINK}[^;|]*{_WS}"
    # 递归拷贝工作区到临时区
    rf"|cp\s+-[A-Za-z]*r[A-Za-z]*\s+{_WS}[^;|]*{_SINK}"
    # 通配聚合：cat <工作区通配> 重定向到临时区
    rf"|cat\s[^;|>]*\*[^;|>]*>\s*{_SINK}"
    # find 逐文件汇聚
    r"|find\s[^;|]*-exec\s+cat"
)


def _normalize_keep_lines(command: str) -> str:
    """NFKC + 剥离不可见字符，但保留换行（命令位判断需要行边界）。"""
    text = unicodedata.normalize("NFKC", command)
    text = _INVISIBLE_RE.sub("", text)
    return text.strip()


def _match_with_context(pattern: re.Pattern[str], variant: str, original: str) -> str:
    """返回命中片段（含少量上下文），找不到时退回整条命令的前 120 字符。"""
    m = pattern.search(variant)
    if not m:
        return original[:120]
    start, end = max(0, m.start() - 20), min(len(variant), m.end() + 20)
    return variant[start:end].strip()


class TripwireScanner:
    """逐命令扫描绊网信号。纯函数式，无状态，可独立测试。"""

    def scan(self, command: str) -> list[TripwireHit]:
        """返回命中的绊网信号（可能多条，同一规则只报一次）。"""
        if not command or not command.strip():
            return []
        # 出口工具按命令位匹配（保留行边界）；其余规则在压缩空白的规范形上匹配。
        # base64 解码变体两者都查（编码载荷解码后通常整段即命令）。
        variants = [normalize_command_text(command)] + decoded_variants(command)[1:]
        line_variants = [_normalize_keep_lines(command)] + decoded_variants(command)[1:]
        checks = [
            ("egress", "network_client", _EGRESS_CMDPOS_RE, line_variants),
            ("egress", "inline_network_code", _EGRESS_CONTENT_RE, variants),
            ("sensitive_path", "sensitive_path", _SENSITIVE_PATH_RE, variants),
            ("privilege_escalation", "privilege_attempt", _PRIV_ESC_RE, variants),
            ("data_staging", "data_staging", _STAGING_RE, variants),
        ]
        hits: list[TripwireHit] = []
        seen: set[tuple[str, str]] = set()
        for signal, rule_id, pattern, texts in checks:
            for variant in texts:
                m = pattern.search(variant)
                if m is None:
                    continue
                snippet = variant[max(0, m.start() - 20):m.end() + 20].strip()
                key = (rule_id, snippet)
                if key not in seen:
                    seen.add(key)
                    hits.append(TripwireHit(
                        signal=signal, rule_id=rule_id,
                        command=command, snippet=snippet,
                    ))
                break  # 同一规则命中一次即可
        return hits
