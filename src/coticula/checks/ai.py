"""AI- and MCP-specific risks: text that tries to steer the model that reads it.

Covers agent skills (SKILL.md), prompt files, CLAUDE.md/AGENTS.md, and MCP server
source (tool names and descriptions are read by the model, so they are an attack surface).
Also flags invisible Unicode anywhere in the project (Trojan Source / ASCII smuggling).
"""
from __future__ import annotations

import re
from typing import List

from coticula.checks import clip, get_line, ignored, line_of
from coticula.model import Finding

# --- invisible characters -------------------------------------------------
ZERO_WIDTH = {chr(c) for c in (0x200B, 0x200C, 0x200D, 0x2060, 0x180E)}
BIDI = {chr(c) for c in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069)}
BOM = chr(0xFEFF)


def _hidden_unicode(f) -> List[Finding]:
    out: List[Finding] = []
    text = f.text
    tags = [(i, ch) for i, ch in enumerate(text) if 0xE0000 <= ord(ch) <= 0xE007F]
    if tags:
        decoded = "".join(chr(ord(ch) - 0xE0000) for _, ch in tags if 0x20 <= ord(ch) - 0xE0000 < 0x7F)
        ln = line_of(text, tags[0][0])
        if not ignored(text, ln):
            out.append(Finding("ai", "unicode-tag-smuggling", "critical",
                               "Invisible Unicode tag characters found. Models can read these but people can't see them.",
                               f.rel, ln, clip("decoded: " + decoded, 140),
                               "Delete the hidden characters and review what they said."))
    reported = set()
    for i, ch in enumerate(text):
        if ch in BIDI or (ch in ZERO_WIDTH) or (ch == BOM and i > 0):
            ln = line_of(text, i)
            kind = "bidi-control" if ch in BIDI else "zero-width"
            if (kind, ln) in reported or ignored(text, ln):
                continue
            reported.add((kind, ln))
            sev = "critical" if (kind == "bidi-control" and f.is_code) else "high" if kind == "bidi-control" else "medium"
            out.append(Finding("ai", f"hidden-{kind}", sev,
                               f"Invisible {kind.replace('-', ' ')} character (U+{ord(ch):04X}) can make text read differently than it runs.",
                               f.rel, ln, clip(get_line(text, ln).encode("unicode_escape").decode(), 140),
                               "Remove the character unless it is intentional and documented."))
    return out


# --- instruction-level patterns --------------------------------------------
PATTERNS = [
    ("instruction-override", "high",
     r"(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|system|original)\s+(?:instructions?|prompts?|rules|messages|guidelines)"),
    ("conceal-from-user", "high",
     r"(?i)\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal|show|disclose)\s+(?:this\s+)?(?:to\s+)?(?:the\s+)?(?:user|human|operator|developer)"),
    ("role-hijack", "medium",
     r"(?i)(?:\byou\s+are\s+now\b|\bnew\s+system\s+prompt\b|<\s*/?\s*system\s*>|\[\s*system\s*\]|\bact\s+as\s+(?:the\s+)?system\b|\bdeveloper\s+mode\s+enabled\b)"),
    ("exfiltration-instruction", "high",
     r"(?i)\b(?:send|post|upload|exfiltrate|forward|transmit|email)\b[^\n]{0,60}\b(?:credentials?|api[\s_-]?keys?|tokens?|secrets?|passwords?|\.ssh|\.env|ssh\s+keys?|private\s+keys?|cookies)"),
    ("credential-path-reference", "medium",
     r"(?i)(?:~/\.ssh|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|\.npmrc|\.pypirc|\bkeychain\b|/etc/shadow|\.git-credentials)"),
    ("pipe-to-shell", "medium",
     r"(?i)\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"),
    ("auto-approve-instruction", "high",
     r"(?i)\b(?:without\s+(?:asking|confirmation|approval)|skip\s+(?:the\s+)?confirmation|auto[-\s]?approve|bypass\s+(?:the\s+)?(?:permission|approval|safety))"),
]
COMPILED = [(r, s, re.compile(p)) for r, s, p in PATTERNS]
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
COMMENT_TRIGGER = re.compile(r"(?i)\b(?:ignore|assistant|claude|gpt|model|llm|instruction|system|agent|you\s+must|do\s+not\s+tell)\b")
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")

MCP_MARKERS = re.compile(
    r"^\s*(?:from\s+mcp[.\s]|import\s+mcp\b)"                       # Python SDK
    r"|(?:from\s+|require\(\s*)['\"]@modelcontextprotocol/"           # TypeScript SDK
    r"|^\s*@mcp\.tool\b|\bserver\.(?:tool|registerTool)\(\s*['\"]"   # tool registration
    r"|^\s*\"mcpServers\"\s*:",                                       # client config
    re.M,
)
AGENT_FILES = {"skill.md", "claude.md", "agents.md", "gemini.md", ".cursorrules", "copilot-instructions.md"}


def _is_agent_text(f) -> bool:
    n = f.name.lower()
    r = "/" + f.rel.lower()
    return (
        n in AGENT_FILES
        or f.ext == ".prompt"
        or "/skills/" in r
        or "/prompts/" in r
        or "/.claude/" in r
        or "/.cursor/rules" in r
    )


def scan(files) -> List[Finding]:
    out: List[Finding] = []
    for f in files:
        out += _hidden_unicode(f)

        is_mcp = (f.is_code or f.ext == ".json") and bool(MCP_MARKERS.search(f.text))
        agent_text = _is_agent_text(f)
        if not (agent_text or is_mcp or f.is_doc):
            continue
        where = "MCP server source" if is_mcp else "agent instructions" if agent_text else "documentation"
        for rule, sev, rx in COMPILED:
            if rule in ("credential-path-reference", "pipe-to-shell") and not (agent_text or is_mcp):
                continue  # common in ordinary READMEs; only risky where a model will act on it
            for m in rx.finditer(f.text):
                ln = line_of(f.text, m.start())
                if ignored(f.text, ln):
                    continue
                s = sev if (agent_text or is_mcp) else "low"
                out.append(Finding("ai", rule, s,
                                   f"Text in {where} that could steer an AI model: \"{clip(m.group(0), 60)}\".",
                                   f.rel, ln, clip(get_line(f.text, ln)),
                                   "Remove it, or rephrase so it describes behaviour rather than instructing the model."))
        if f.ext in (".md", ".mdx", ".prompt"):
            for m in HTML_COMMENT.finditer(f.text):
                if COMMENT_TRIGGER.search(m.group(1)):
                    ln = line_of(f.text, m.start())
                    if not ignored(f.text, ln):
                        out.append(Finding("ai", "hidden-comment-instruction", "high" if agent_text else "medium",
                                           "HTML comment is hidden when rendered but still read by models, and it looks like an instruction.",
                                           f.rel, ln, clip(m.group(1)), "Move it into visible text or delete it."))
            if agent_text:
                for m in BASE64_BLOB.finditer(f.text):
                    ln = line_of(f.text, m.start())
                    if not ignored(f.text, ln):
                        out.append(Finding("ai", "encoded-blob", "medium",
                                           "Long encoded blob in agent instructions; content can't be reviewed by reading it.",
                                           f.rel, ln, clip(m.group(0), 40), "Ship the decoded content or a reviewed file instead."))
    return out
