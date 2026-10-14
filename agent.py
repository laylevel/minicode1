import os
import subprocess
from dotenv import load_dotenv
from anthropic import Anthropic
from pathlib import Path
import re

load_dotenv()
client = Anthropic(
    base_url=os.getenv("ANTHROPIC_BASE_URL"),
    auth_token=os.getenv("ANTHROPIC_AUTH_TOKEN"),
)

SYSTEM = f"You are a coding agent at {os.getcwd()}. Use bash to solve tasks. Act, don't explain."
WORKDIR = Path.cwd().resolve()  # 用解析后的绝对路径，后续 is_relative_to 才可靠
MAX_STEPS = 20
PERMISSION_MODE = "ask"
STATS = {"llm_calls":0,"input_tokens":0,"output_tokens":0,"tool_calls":[],"hit_max_steps":False}
# 定义工具
TOOLS = [
    {"name": "bash", "description": "Run a shell command.",
     "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}},
    {"name": "read_file", "description": "Read file contents.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["path"]}},
    {"name": "write_file", "description": "Write content to a file.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}},
    {"name": "edit_file", "description": "Replace exact text in a file once.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "old_text": {"type": "string"}, "new_text": {"type": "string"}}, "required": ["path", "old_text", "new_text"]}},
    {"name": "glob", "description": "Find files matching a glob pattern; ** matches recursively.",
     "input_schema": {"type": "object", "properties": {"pattern": {"type": "string"}}, "required": ["pattern"]}},
]


def safe_path(p: str) -> Path:
    path = (WORKDIR / p).resolve()
    if not path.is_relative_to(WORKDIR):
        raise ValueError(f"Path {path} is not relative to {WORKDIR}")
    return path


def run_bash(command: str, timeout: int = 120) -> str:
    dangerous = ["rm -rf /", "sudo", "shutdown", "reboot", "> /dev/"]
    if any(d in command for d in dangerous):
        return "Error: Dangerous command blocked."
    try:
        # cwd 限定在工作区；errors="replace" 防止非 UTF-8 输出直接崩溃
        r = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            timeout=timeout, cwd=WORKDIR, errors="replace",
        )
        out = (r.stdout + r.stderr).strip()
        return out[:50000] if out else "(no output)"
    except subprocess.TimeoutExpired:
        return "Error: Timeout (120s)"
    except (FileNotFoundError, OSError) as e:
        return f"Error: {type(e).__name__}: {e}"


def read_file(path: str, limit: int | None = None):
    path = safe_path(path)
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
        lines = content.splitlines()
        if limit:
            lines = lines[:limit]
        return "\n".join(lines) if lines else "(empty file)"


def write_file(path: str, content: str):
    path = safe_path(path)
    # 自动创建父目录，支持"在子目录里新建文件"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return f"Wrote {len(content)} bytes to {path}"


def edit_file(path: str, old_text: str, new_text: str):
    path = safe_path(path)
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    if old_text not in content:
        return f"Error: Text {old_text} not found in {path}"
    content = content.replace(old_text, new_text, 1)
    write_file(path, content)
    return f"Edited {path}"


def glob(pattern: str):
    import glob as g
    # 过滤掉解析后落在工作区之外的结果，防止 glob("../*") 越界
    matches = sorted({
        m for m in g.glob(pattern, root_dir=WORKDIR, recursive=True)
        if (WORKDIR / m).resolve().is_relative_to(WORKDIR)
    })
    shown = matches[:200]
    if len(matches) > 200:
        shown.append("... (more matches omitted; narrow the pattern)")
    return "\n".join(shown) if shown else "(no matches)"


TOOL_HANDLERS = {
    "bash": run_bash, "read_file": read_file, "write_file": write_file,
    "edit_file": edit_file, "glob": glob,
}

DENY_LIST = ["rm -rf /", "sudo", "shutdown", "reboot", "> /dev/sda", "dd if="]


def check_deny_list(command: str) -> str | None:
    for deny in DENY_LIST:
        if deny in command:
            return f"Error: Dangerous command {deny} blocked."
    return None


DESTRUCTIVE_COMMAND_WORD = re.compile(
    r"(?i)(?:^|[;&|()\n])\s*(?:rm|del)(?=\s|$|[;&|()])"
)


def contains_destructive_command(command: str) -> bool:
    return bool(DESTRUCTIVE_COMMAND_WORD.search(command))


PERMISSION_RULES = [
    {
        "tools": ["read_file", "write_file", "edit_file", "glob"],
        "check": lambda args: not (WORKDIR / args.get("path", "")).resolve().is_relative_to(WORKDIR),
        "message": "Access outside workspace",
    },
    {
        "tools": ["bash"],
        "check": lambda args: contains_destructive_command(args.get("command", ""))
        or any(kw in args.get("command", "") for kw in ["rm ", "> /etc/", "chmod 777"]),
        "message": "Dangerous command blocked.",
    },
]


def check_rules(tool_name: str, args: dict) -> str | None:
    for rule in PERMISSION_RULES:
        if tool_name in rule["tools"] and rule["check"](args):
            return rule["message"]
    return None


def ask_user(tool_name: str, args: dict, reason: str) -> str:
    if PERMISSION_MODE == "auto_deny":
        return "deny"
    if PERMISSION_MODE == "auto_allow":
        return "allow"
    print(f"\n⚠  {reason}")
    print(f"   Tool: {tool_name}({args})")
    choice = input("   Allow? [y/N] ").strip().lower()
    return "allow" if choice in ("y", "yes") else "deny"


def check_permission(block) -> bool:
    # 闸门 1: 硬拒绝
    if block.name == "bash":
        reason = check_deny_list(block.input.get("command", ""))
        if reason:
            print(f"\n⛔ {reason}")
            return False

    # 闸门 2 + 3: 规则匹配 → 用户审批
    reason = check_rules(block.name, block.input)
    if reason:
        decision = ask_user(block.name, block.input, reason)
        if decision == "deny":
            return False
    return True


def agent_loop(messages: list):
    for i in range(MAX_STEPS):
        response = client.messages.create(
            model=os.getenv("MODEL_ID"),
            system=SYSTEM,
            messages=messages,
            tools=TOOLS,
            max_tokens=8000,
        )
        STATS["llm_calls"] += 1
        usage = getattr(response, "usage", None)
        STATS["input_tokens"] +=getattr(usage,"input_tokens",0) or 0
        STATS["output_tokens"] +=getattr(usage,"output_tokens",0) or 0
        messages.append({"role": "assistant", "content": response.content})

        # 收集所有工具调用
        tool_calls = [b for b in response.content if b.type == "tool_use"]

        # 没有工具调用：本轮结束，回到主循环等用户下一句
        if not tool_calls:
            return

        # 有工具调用：逐个过权限、执行，异常统一兜底为字符串回给模型
        results = []
        for block in tool_calls:
            print(f"\033[33m> {block.name}\033[0m")
            if not check_permission(block):
                STATS["tool_calls"].append({"name":block.name,"input":block.input,"denied":True,"error":False})
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": "Permission denied",
                })
                continue

            handler = TOOL_HANDLERS.get(block.name)
            if handler is None:
                # 模型编了不存在的工具名：不要 KeyError 崩溃
                output = f"Error: Tool {block.name} not found."
            else:
                try:
                    output = handler(**block.input)
                except Exception as e:
                    # 任何工具异常都变成字符串，让模型能换办法重试
                    output = f"Error: {type(e).__name__}: {e}"
            STATS["tool_calls"].append({"name":block.name,"input":block.input,"denied":False,"error":output.startswith("Error")})
            print(output[:200])
            results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": output,
            })
        messages.append({"role": "user", "content": results})
        STATS["hit_max_steps"] = True


if __name__ == "__main__":
    print("s01 agent start")
    print("Enter a question, press Enter to send. Type q to quit.\n")
    history = []
    while True:
        try:
            query = input("\001\033[36m\002s01 >> \001\033[0m\002")
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        if query.lower() == "q":
            break
        # 空输入不要发给 API
        if not query.strip():
            continue
        history.append({"role": "user", "content": query})
        agent_loop(history)
        response_content = history[-1]["content"]
        if isinstance(response_content, list):
            for block in response_content:
                if getattr(block, "type", None) == "text":
                    print(block.text)
        print()
