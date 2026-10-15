from pathlib import Path
import os, re, shlex
import fnmatch
import stat
from typing import Literal
from dataclasses import dataclass, field
workspace_root = Path.cwd().resolve()

FILE_ACTIONS = {"read_file": "read", "write_file": "write", "edit_file": "write", "glob": "list"}
OPERATORS = {";", "&&", "||", "|", "&"}          # 把一条命令切成几段
REDIRECTS = {">", ">>", "<"}                      # 后面跟的是文件路径
WIN_SWITCH = re.compile(r"/[A-Za-z?]")            # /s /q /c 这类 Windows 开关，不是路径
DRIVE = re.compile(r"[A-Za-z]:[\\/]")

# 命令名规则集中放在这里；不会在普通文本或文件名中搜索这些词。
HARD_DENY_COMMANDS = {"sudo", "shutdown", "reboot", "dd", "mkfs", "fdisk", "format"}
DELETE_COMMANDS = {"rm", "del", "erase", "rmdir", "rd", "remove-item", "ri"}
INTERPRETERS = {
    "cmd", "powershell", "pwsh", "bash", "sh", "zsh", "fish",
    "python", "python3", "pythonw", "py", "node", "perl", "ruby",
}
READ_PATH_COMMANDS = {"cat", "type", "ls", "dir"}
WINDOWS_FILE_COMMANDS = {"dir", "del", "erase", "rmdir", "rd", "cd"}
WINDOWS_FILE_SWITCH = re.compile(r"/[A-Za-z?](?::[^/\\]*)?")

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
    root = Path(root).resolve()
    path = (root / p).resolve()                    # p 是绝对路径时，root / p 直接得到 p
    return path, path.is_relative_to(root)

def _target(raw, root):
    p = os.path.expanduser(raw)
    path, inside = resolve_workspace_path(p, root)
    return {"raw": raw, "path": path, "inside": inside}

def _glob_target(pattern, root):
    """检查完整模式；通配符部分留给受限制的遍历器处理。"""
    if not isinstance(pattern, str) or not pattern.strip() or "\0" in pattern:
        raise ValueError("glob 必须提供非空的 pattern 字符串")

    root = Path(root).resolve()
    expanded = os.path.expanduser(pattern).replace("\\", "/")
    candidate = Path(expanded)
    if candidate.drive and not candidate.root:
        raise ValueError("glob 不支持 C:*.py 这类盘符相对路径")
    try:
        parts = (root / candidate).relative_to(root).parts
    except ValueError:
        raise ValueError("glob 搜索范围超出工作区") from None

    # 即使 .. 位于通配符后面也检查，避免 */../../secret.txt 被漏过。
    if ".." in parts:
        raise ValueError("glob 模式不允许使用 .. 向上跳目录")

    prefix = []
    for part in parts:
        if any(char in part for char in "*?["):
            break
        prefix.append(part)
    path, inside = resolve_workspace_path(Path(*prefix), root)
    if not inside:
        raise ValueError("glob 固定路径通过链接指向工作区外")

    return {
        "raw": pattern,
        "path": path,
        "inside": True,
        "parts": parts,
        "directories_only": expanded.endswith("/"),
    }

def _glob_candidate_allowed(path, root):
    """遍历前检查：不跟随符号链接、目录联接及其他 Windows 重解析点。"""
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            return False
        attributes = getattr(metadata, "st_file_attributes", 0)
        if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            return False
        return path.resolve().is_relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return False

def safe_glob(pattern, root, max_results=201):
    """在工作区内逐层匹配 *、?、[]、**，返回相对路径，跳过链接。"""
    root = Path(root).resolve()
    target = _glob_target(pattern, root)
    parts = target["parts"]
    directories_only = target["directories_only"]
    pending = [(root, 0)]
    visited = set()
    matches = set()

    while pending:
        current, index = pending.pop()
        if (current, index) in visited:
            continue
        visited.add((current, index))
        if not _glob_candidate_allowed(current, root):
            continue

        if index == len(parts):
            if directories_only and not current.is_dir():
                continue
            # ** 匹配工作区里的条目；显式 "." 或目录模式可以匹配根目录。
            if current == root and parts and not directories_only:
                continue
            relative = current.relative_to(root).as_posix()
            if directories_only:
                relative += "/"
            matches.add(relative)
            if max_results is not None and len(matches) >= max_results:
                break
            continue

        if not current.is_dir():
            continue
        part = parts[index]
        if part == "**":
            pending.append((current, index + 1))    # ** 也可以匹配零层目录

        try:
            children = sorted(current.iterdir(), key=lambda child: child.name)
        except OSError:
            continue
        for child in reversed(children):
            if child.name.startswith(".") and not part.startswith("."):
                continue
            if not _glob_candidate_allowed(child, root):
                continue
            if part == "**":
                if child.is_dir():
                    pending.append((child, index))
                elif index == len(parts) - 1:
                    pending.append((child, index + 1))
            elif fnmatch.fnmatch(child.name, part):
                pending.append((child, index + 1))

    return sorted(matches)

def _unquote(t):
    return t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'" else t

def _looks_like_path(t):
    if "://" in t or WIN_SWITCH.fullmatch(t):
        return False
    return any(s in t for s in "/\\") or t.startswith(("~", ".")) or bool(DRIVE.match(t))

def _command_name(token):
    """例如 C:/Windows/System32/SHUTDOWN.EXE -> shutdown。"""
    name = token.replace('"', "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name.removesuffix(".exe")

def _command_targets(segment, root):
    """按命令用途提取文件参数；echo 的文字和解释器的代码不当作路径。"""
    name = _command_name(segment[0])
    if name == "echo" or name in INTERPRETERS:
        return []
    targets = []
    after_double_dash = False
    for token in segment[1:]:
        if token == "--" and not after_double_dash:
            after_double_dash = True
            continue
        if not after_double_dash:
            if name in WINDOWS_FILE_COMMANDS and WINDOWS_FILE_SWITCH.fullmatch(token):
                continue
            if token.startswith("-"):
                # --output=../out.txt 仍然需要检查等号右侧的路径。
                if "=" in token and _looks_like_path(token.split("=", 1)[1]):
                    targets.append(_target(token.split("=", 1)[1], root))
                continue
        if token == "-":                           # 标准输入，不是文件路径
            continue
        if name in READ_PATH_COMMANDS or name in DELETE_COMMANDS or name in {"cd", "chdir"}:
            targets.append(_target(token, root))
        elif _looks_like_path(token):
            targets.append(_target(token, root))
    return targets

def prepare_request(tool_name, args, root):
    if not isinstance(args, dict):
        return Request(tool_name, "other", "exec", error="args 必须是字典")
    if tool_name in FILE_ACTIONS:
        req = Request(tool_name, "file", FILE_ACTIONS[tool_name])
        key = "pattern" if tool_name == "glob" else "path"
        raw = args.get(key)
        if not isinstance(raw, str) or not raw.strip():
            req.error = f"{tool_name} 必须提供非空的 {key} 字符串"
            return req
        try:
            target = _glob_target(raw, root) if tool_name == "glob" else _target(raw, root)
            req.targets.append(target)
        except (OSError, RuntimeError, ValueError) as e:
            req.error = f"无法解析文件请求：{e}"
        return req
    if tool_name == "bash":
        raw = args.get("command")
        req = Request(tool_name, "command", "exec", raw=raw if isinstance(raw, str) else "")
        if not isinstance(raw, str) or not raw.strip():
            req.error = "bash 必须提供非空的 command 字符串"
            return req
        if any(char in raw for char in "\0\r\n"):
            req.error = "当前命令分析不支持空字符或多行命令"
            return req
        try:
            lex = shlex.shlex(req.raw, posix=False, punctuation_chars=True)
            lex.whitespace_split = True
            lex.commenters = ""                    # Windows 的 # 不应截断后面的命令
            tokens = list(lex)
        except ValueError as e:
            req.error = f"无法解析命令：{e}"
            return req
        current, redirect = [], False
        for t in tokens:
            if t in OPERATORS:
                if redirect or not current:
                    req.error = "串联操作符前缺少命令或重定向目标"
                    return req
                req.segments.append(current)
                current = []
            elif t in REDIRECTS:
                if redirect:
                    req.error = "重定向缺少目标路径"
                    return req
                redirect = True
                redirect_action = "read" if t == "<" else "write"
            elif re.fullmatch(r"[();<>|&]+", t):
                req.error = f"当前命令分析不支持操作符：{t}"
                return req
            elif redirect:
                try:
                    target = _target(_unquote(t), root)
                except (OSError, RuntimeError, ValueError) as e:
                    req.error = f"无法解析重定向路径：{e}"
                    return req
                target["action"] = redirect_action
                req.targets.append(target)
                redirect = False
            else:
                current.append(_unquote(t))
        if redirect or not current:
            req.error = "命令末尾缺少命令或重定向目标"
            return req
        req.segments.append(current)
        try:
            for segment in req.segments:
                req.targets.extend(_command_targets(segment, root))
        except (OSError, RuntimeError, ValueError) as e:
            req.error = f"无法解析命令路径：{e}"
        return req
    req = Request(tool_name, "other", "exec")
    req.error = f"未知工具：{tool_name}"
    return req

@dataclass(frozen=True)#根据预先定义的规则，判断请求是否可以执行
class Assessment:
    action: Literal["allow", "ask", "deny"]
    reason: str
    rule_id: str


def assess_file_request(req: Request) -> Assessment:
    # 1. 准备阶段已经发现错误，直接拒绝（请求解析失败）
    if req.error:
        return Assessment("deny", req.error, "request.invalid")

    # 2. 确认工具和操作类型匹配
    expected_action = FILE_ACTIONS.get(req.tool)
    if (
        req.kind != "file"
        or expected_action is None
        or req.action != expected_action
    ):
        return Assessment(
            "deny", "不支持的文件操作", "file.unsupported"
        )

    # 3. 目标不能为空
    if not req.targets:
        return Assessment(
            "deny", "缺少目标路径", "file.missing_target"
        )

    # 4. 检查全部目标，任何一个越界都拒绝
    for target in req.targets:
        if not target.get("raw"):
            return Assessment(
                "deny", "目标路径为空", "file.invalid_target"
            )

        if target.get("inside") is not True:
            return Assessment(
                "deny",
                f"目标超出工作区：{target.get('raw')}",
                "file.outside_workspace",
            )

    # 5. glob 模式已检查；执行时还必须使用 safe_glob 约束遍历范围
    if req.tool == "glob":
        return Assessment(
            "allow",
            "模式已检查；执行时仅遍历工作区内的普通目录",
            "file.workspace_glob",
        )

    # 6. 按当前项目策略，允许工作区内普通读写和精确编辑
    return Assessment(
        "allow",
        "工作区内的普通文件操作",
        "file.workspace_operation",
    )

def assess_command_request(req: Request) -> Assessment:
    """使用 raw、segments、targets、error 判断；返回 Assessment，不执行命令。"""
    # 1. 请求必须是已成功解析的 bash 调用。
    if req.error:
        return Assessment("deny", req.error, "request.invalid")
    if req.tool != "bash" or req.kind != "command" or req.action != "exec":
        return Assessment("deny", "不支持的命令请求", "command.unsupported")
    if not req.raw.strip() or not req.segments:
        return Assessment("deny", "命令不能为空", "command.empty")
    if any(not segment or not segment[0] for segment in req.segments):
        return Assessment("deny", "缺少命令名", "command.empty_segment")

    # 2. 参数及重定向中的显式越界路径直接拒绝。
    for target in req.targets:
        if target.get("inside") is not True:
            return Assessment(
                "deny", f"目标超出工作区：{target.get('raw')}", "command.outside_workspace"
            )

    results = []
    # 3. 这些语法需要 Shell 扩展；简单分词不足以确定其运行效果。
    if any(char in req.raw for char in "$%^!" + chr(96)) or (os.name == "nt" and "'" in req.raw):
        results.append(Assessment(
            "ask", "变量、替换或转义语法需要审批", "command.shell_expansion"
        ))
    if any('"' in token for segment in req.segments for token in segment):
        results.append(Assessment(
            "ask", "单词内部拼接引号的含义需要审批", "command.complex_quotes"
        ))
    if os.name != "nt" and "\\" in req.raw:
        results.append(Assessment(
            "ask", "Unix Shell 反斜杠转义需要审批", "command.shell_escape"
        ))
    if any(target.get("action") == "write" for target in req.targets):
        results.append(Assessment(
            "ask", "重定向会写入文件，需要审批", "command.redirect_write"
        ))
    if any(any(char in target["raw"] for char in "*?[") for target in req.targets):
        results.append(Assessment(
            "ask", "Shell 通配符的实际匹配范围需要审批", "command.wildcard"
        ))

    # 4. 每一段命令都判断，避免前面的安全命令掩盖后面的危险命令。
    for segment in req.segments:
        command = _command_name(segment[0])
        arguments = segment[1:]
        if command in HARD_DENY_COMMANDS or command.startswith("mkfs."):
            results.append(Assessment(
                "deny", f"禁止执行系统危险命令：{command}", "command.hard_deny"
            ))
        elif command in DELETE_COMMANDS:
            # 你的练习：把下面的 "ask" 改成 "deny"，再验证其他规则仍然生效。
            results.append(Assessment(
                "ask", f"删除命令需要审批：{command}", "command.delete"
            ))
        elif command in INTERPRETERS:
            results.append(Assessment(
                "ask", f"{command} 可以执行任意代码，需要审批", "command.interpreter"
            ))
        elif command in {"cd", "chdir"}:
            results.append(Assessment(
                "ask", "切换目录会改变后续相对路径的含义，需要审批", "command.change_directory"
            ))
        elif command == "git" and arguments[:1] == ["status"]:
            results.append(Assessment("allow", "查看 Git 状态", "command.git_status"))
        elif command in {"echo", "pwd", "whoami"} | READ_PATH_COMMANDS:
            if command in {"ls", "dir"} and any(
                token.lower() in {"/s", "--recursive"}
                or token.startswith("--dereference")
                or (token.startswith("-") and not token.startswith("--")
                    and any(c in token for c in "RLH"))
                for token in arguments
            ):
                results.append(Assessment(
                    "ask", "递归列目录或跟随链接需要审批", "command.recursive_listing"
                ))
            else:
                results.append(Assessment("allow", "普通输出或读取命令", "command.read_only"))
        else:
            results.append(Assessment(
                "ask", f"命令未列入允许规则：{command}", "command.unknown"
            ))
        if "/" in segment[0] or "\\" in segment[0]:
            results.append(Assessment(
                "ask", "通过路径指定的程序需要审批", "command.executable_path"
            ))

    # 5. 整条命令取最严格的决策：deny > ask > allow。
    for result in results:
        if result.action == "deny":
            return result
    for result in results:
        if result.action == "ask":
            return result
    return Assessment("allow", "所有命令段均符合允许规则", "command.allowed")


if __name__ == "__main__":
    user_input = input("请输入工具名，例如 read_file、glob 或 bash：")
    key = "command" if user_input == "bash" else "pattern" if user_input == "glob" else "path"
    value = input(f"请输入 {key}：")
    req = prepare_request(user_input, {key: value}, workspace_root)
    print(req)
    assessment = assess_command_request(req) if req.kind == "command" else assess_file_request(req)
    print(assessment)
