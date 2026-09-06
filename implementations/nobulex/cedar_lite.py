#!/usr/bin/env python3
"""
A small evaluator for the subset of Cedar that fixtures/policy/autoresearch-safe.cedar
uses. Not a Cedar implementation, and it says so where it matters.

It exists so this driver derives its decisions from the policy file rather than
from the fixtures' `expected_decision`. A driver that reads `expected_decision`
is copying the answer key, and the suite would report it conformant while
proving nothing. See issue #13, finding 6.

Supported subset, which is everything the policy uses:

    permit ( principal, action in [Action::"A", Action::"B"], resource );
    permit ( principal, action == Action::"A", resource ) when { <cond> };
    forbid ( principal, action == Action::"A", resource ) when { <cond> };

    <cond> := context.<key> in [ "v1", "v2" ]
            | context.<key> == "v"

Cedar semantics applied here: an unmatched request is denied (default deny),
and a matching `forbid` overrides any matching `permit`.
"""

import re
from typing import Any, Dict, List, Optional

_ACTION = re.compile(r'Action::"([^"]+)"')
_IN_LIST = re.compile(r'context\.(\w+)\s+in\s*\[([^\]]*)\]', re.S)
_EQ = re.compile(r'context\.(\w+)\s*==\s*"([^"]*)"')
_STRING = re.compile(r'"([^"]*)"')


class Rule:
    def __init__(self, effect: str, actions: List[str], condition: Optional[dict]):
        self.effect = effect
        self.actions = actions
        self.condition = condition

    def matches(self, tool_name: str, context: Dict[str, Any]) -> bool:
        if self.actions and tool_name not in self.actions:
            return False
        if self.condition is None:
            return True
        got = context.get(self.condition["key"])
        return got in self.condition["values"]

    def __repr__(self):
        return f"<{self.effect} {self.actions} {self.condition}>"


def _strip_comments(text: str) -> str:
    return re.sub(r'//[^\n]*', '', text)


def parse(policy_text: str) -> List[Rule]:
    text = _strip_comments(policy_text)
    rules: List[Rule] = []
    for match in re.finditer(r'\b(permit|forbid)\b(.*?);', text, re.S):
        effect, body = match.group(1), match.group(2)
        head, _, guard = body.partition("when")
        actions = _ACTION.findall(head)
        condition = None
        if guard.strip():
            in_list = _IN_LIST.search(guard)
            equality = _EQ.search(guard)
            if in_list:
                condition = {"key": in_list.group(1), "op": "in",
                             "values": _STRING.findall(in_list.group(2))}
            elif equality:
                condition = {"key": equality.group(1), "op": "==",
                             "values": [equality.group(2)]}
            else:
                raise ValueError(
                    "unsupported `when` clause; this evaluator covers only the "
                    "subset the test-vector policy uses: " + guard.strip()[:80])
        rules.append(Rule(effect, actions, condition))
    if not rules:
        raise ValueError("no permit or forbid statements found in the policy")
    return rules


def evaluate(rules: List[Rule], tool_name: str, context: Dict[str, Any]) -> str:
    """Return "allow" or "deny". forbid wins; unmatched is denied."""
    for rule in rules:
        if rule.effect == "forbid" and rule.matches(tool_name, context):
            return "deny"
    for rule in rules:
        if rule.effect == "permit" and rule.matches(tool_name, context):
            return "allow"
    return "deny"
