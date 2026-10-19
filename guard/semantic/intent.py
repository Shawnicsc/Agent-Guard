"""任务意图冻结与比对：MissionSpec 是唯一授权来源，LLM 只负责解释。

意图在会话创建时冻结（MISSION_FROZEN）；后续所有语义研判只回答
"本次调用与冻结意图的关系"，不重新解释权限（DESIGN.md 第 4 节）。
"""

from __future__ import annotations

import re

from guard.contracts import MissionSpec, TaskRelation, ToolCallEnvelope

# 关键词重叠相似度阈值（无模型时的保守启发式）
_HEURISTIC_RATIO = 0.28
# 每个调用分析的参数文本上限（性能与提示注入面控制）
_MAX_ARG_TEXT_LEN = 1200


def intent_signature(mission: MissionSpec) -> str:
    """冻结意图的规范化摘要：目标 + 类别 + 授权动作。"""
    parts = [mission.goal, mission.goal_category.value,
             ",".join(sorted(mission.allowed_actions))]
    return " | ".join(parts)


def _keywords(text: str) -> set[str]:
    # 中英混合分词：英文按词、中文按 2-gram
    words = set(re.findall(r"[a-zA-Z][a-zA-Z0-9_+-]{2,}", text.lower()))
    cjk = re.findall(r"[一-鿿]", text)
    grams = {"".join(cjk[i:i + 2]) for i in range(len(cjk) - 1)}
    return words | grams


def heuristic_relation(mission: MissionSpec,
                       envelope: ToolCallEnvelope) -> TaskRelation:
    """无语义服务时的保守启发式：目标关键词与调用参数的重叠度。

    只区分 aligned 与 uncertain：启发式没有能力断言"偏离"，
    宁可交给 CONFIRM 档也不误放行。
    """
    arg_text = " ".join(str(v) for v in envelope.arguments.values()
                        if isinstance(v, str))[:_MAX_ARG_TEXT_LEN]
    goal_keys = _keywords(mission.goal)
    arg_keys = _keywords(f"{envelope.tool} {arg_text}")
    if not goal_keys or not arg_keys:
        return TaskRelation.UNCERTAIN
    overlap = len(goal_keys & arg_keys) / len(goal_keys)
    return TaskRelation.ALIGNED if overlap >= _HEURISTIC_RATIO else TaskRelation.UNCERTAIN
