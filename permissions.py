from pathlib import Path
import os, re, shlex
from dataclasses import dataclass, field
workspace_root = Path.cwd().resolve() 
import os, re, shlex1
from dataclasses import dataclass, field
from pathlib import Path
FILE_ACTIONS = {"read_file": "read", "write_file": "write", "edit_file": "write", "glob": "list"}
OPERATORS = {";", "&&", "||", "|", "&"}          # 把一条命令切成几段
REDIRECTS = {">", ">>", "<"}                      # 后面跟的是文件路径
WIN_SWITCH = re.compile(r"/[A-Za-z?]")            # /s /q /c 这类 Windows 开关，不是路径
DRIVE = re.compile(r"[A-Za-z]:[\\/]")

@dataclass
class Request:
    tool: str
    kind: str                                      # "file" | "command" | "other"
    action: str                                    # read | write | list | exec
    raw: str = ""
    segments: list = field(default_factory=list)   # 每一段命令的 argv
    targets: list = field(default_factory=list)    # [{"raw","path","inside"}]
    error: str = ""                                # 解析失败的原因

def resolve_workspace_path(p, root):
    path = (root / p).resolve()                    # p 是绝对路径时，root / p 直接得到 p
    return path, path.is_relative_to(root)

def _target(raw, root):
    p = os.path.expanduser(raw)
    p = re.split(r"[*?\[]", p, maxsplit=1)[0] or "."   # glob 只取通配符之前的部分
    path, inside = resolve_workspace_path(p, root)
    return {"raw": raw, "path": path, "inside": inside}

def _unquote(t):
    return t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'" else t

def _looks_like_path(t):
    if "://" in t or WIN_SWITCH.fullmatch(t):
        return False
    return any(s in t for s in "/\\") or t.startswith(("~", ".")) or bool(DRIVE.match(t))

def prepare_request(tool_name, args, root):
    if tool_name in FILE_ACTIONS:
        req = Request(tool_name, "file", FILE_ACTIONS[tool_name])
        req.targets.append(_target(args.get("path") or args.get("pattern") or "", root))
        return req
    if tool_name == "bash":
        req = Request(tool_name, "command", "exec", raw=args.get("command", ""))
        try:
            lex = shlex.shlex(req.raw, posix=False, punctuation_chars=True)
            lex.whitespace_split = True
            tokens = list(lex)
        except ValueError as e:
            req.error = f"无法解析命令：{e}"
            return req
        current, redirect = [], False
        for t in tokens:
            if t in OPERATORS:
                if current:
                    req.segments.append(current)
                    current = []
            elif t in REDIRECTS:
                redirect = True
            elif redirect:
                req.targets.append(_target(_unquote(t), root))
                redirect = False
            else:
                current.append(_unquote(t))
        if current:
            req.segments.append(current)
        for seg in req.segments:
            for token in seg[1:]:
                if _looks_like_path(token):
                    req.targets.append(_target(token, root))
        return req
    req = Request(tool_name, "other", "exec")
    req.error = f"未知工具：{tool_name}"
    return req