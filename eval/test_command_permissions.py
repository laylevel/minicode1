"""验证命令评估结果，不执行任何待测命令，也不调用模型。"""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from permissions import Request, assess_command_request, prepare_request


class CommandPermissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="minicode-command-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / "notes.txt").write_text("notes", encoding="utf-8")
        (self.root / "sudoers_notes.txt").write_text("notes", encoding="utf-8")

    def assess(self, command):
        request = prepare_request("bash", {"command": command}, self.root)
        return assess_command_request(request)

    def test_prepare_preserves_raw_and_splits_commands(self):
        raw = 'echo "please confirm this"; rm notes.txt'
        request = prepare_request("bash", {"command": raw}, self.root)
        self.assertEqual(request.raw, raw)
        self.assertEqual(
            request.segments, [["echo", "please confirm this"], ["rm", "notes.txt"]]
        )
        self.assertEqual(request.targets[0]["path"], self.root / "notes.txt")

    def test_plain_output_and_reading_are_allowed(self):
        for command in (
            "echo hello", 'echo "please confirm this"', "echo shutdown",
            'echo "../secret.txt"', "cat sudoers_notes.txt", "type notes.txt",
            "ls", "dir /b", "pwd", "whoami", "git status --short",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.assess(command).action, "allow")

    def test_deleting_workspace_files_requires_approval(self):
        # 学习练习修改删除策略后，这组预期也应根据新需求变为 deny。
        for command in (
            "rm -rf ./build", "del notes.txt", "rmdir /s /q build",
            "rd /s /q build", "erase notes.txt", "Remove-Item -Force notes.txt",
        ):
            with self.subTest(command=command):
                result = self.assess(command)
                self.assertEqual(result.action, "ask")
                self.assertEqual(result.rule_id, "command.delete")

    def test_system_dangerous_commands_are_denied(self):
        for command in (
            "sudo apt install curl", "shutdown /s /t 0", "SHUTDOWN.EXE /s",
            "reboot", "dd if=/dev/zero of=disk.img", "mkfs.ext4 disk.img",
            "format C:", '"C:/Windows/System32/shutdown.exe" /s',
        ):
            with self.subTest(command=command):
                self.assertEqual(self.assess(command).action, "deny")

    def test_explicit_path_escape_is_denied(self):
        for command in (
            "cat ../secret.txt", r"type ..\secret.txt", "cat -- ../secret.txt",
            "echo hacked > ../out.txt", "del ../notes.txt",
            "cat " + str(self.root.parent / "secret.txt"),
            "custom_tool --output=../out.txt",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.assess(command).action, "deny")

    def test_redirects_keep_target_and_intent(self):
        request = prepare_request("bash", {"command": "echo hello > out.txt"}, self.root)
        self.assertEqual(request.targets[0]["raw"], "out.txt")
        self.assertEqual(request.targets[0]["action"], "write")
        self.assertEqual(assess_command_request(request).action, "ask")
        request = prepare_request("bash", {"command": "cat < notes.txt"}, self.root)
        self.assertEqual(request.targets[0]["action"], "read")
        self.assertEqual(assess_command_request(request).action, "allow")

    def test_interpreters_and_unknown_commands_require_approval(self):
        for command in (
            "python test.py", 'python -c "print(1)"', "cmd /c del notes.txt",
            "powershell -Command Remove-Item -Recurse -Force build",
            "bash -c echo", "node script.js", "custom_tool notes.txt",
            "git reset --hard", "chmod 777 notes.txt",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.assess(command).action, "ask")

    def test_command_chain_uses_the_strictest_decision(self):
        cases = {
            "echo hello; cat notes.txt": "allow",
            "echo hello && rm notes.txt": "ask",
            "rm notes.txt; shutdown /s": "deny",
            "shutdown /s; rm notes.txt": "deny",
            "echo hello | sudo cmd": "deny",
            "echo hello || cat ../secret.txt": "deny",
            "echo hello # text & shutdown /s": "deny",
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertEqual(self.assess(command).action, expected)

    def test_expansion_and_escape_are_never_automatically_allowed(self):
        for command in ("echo %NAME%", "echo $NAME", "echo ^hello",
                        "echo !NAME!", "echo " + chr(96) + "whoami" + chr(96)):
            with self.subTest(command=command):
                self.assertNotEqual(self.assess(command).action, "allow")

    @unittest.skipUnless(os.name == "nt", "Windows 单引号不表示 Shell 引用")
    def test_windows_single_quotes_do_not_hide_commands(self):
        self.assertNotEqual(self.assess("echo 'hello & shutdown /s'").action, "allow")

    def test_wildcards_and_recursive_listing_require_approval(self):
        for command in ("cat *.txt", "dir /s", "ls -R", "ls -L", "ls --recursive",
                        "ls --dereference", "ls --recursive --dereference ."):
            with self.subTest(command=command):
                self.assertEqual(self.assess(command).action, "ask")

    def test_quote_concatenation_is_not_automatically_allowed(self):
        self.assertNotEqual(self.assess('cat .".\\secret.txt"').action, "allow")
        self.assertEqual(self.assess('shut"down" /s').action, "deny")

    def test_type_does_not_treat_absolute_path_as_a_switch(self):
        self.assertEqual(self.assess("type /a").action, "deny")

    def test_program_paths_require_approval(self):
        self.assertEqual(self.assess("./echo.exe hello").action, "ask")

    def test_invalid_inputs_are_denied(self):
        for args in ({}, {"command": ""}, {"command": "  "},
                     {"command": None}, {"command": 123}, [], None):
            with self.subTest(args=args):
                request = prepare_request("bash", args, self.root)
                self.assertEqual(assess_command_request(request).action, "deny")

    def test_malformed_or_unsupported_syntax_is_denied(self):
        for command in ('echo "hello', "echo hello >", "&& echo hello",
                        "echo hello &&", "echo hello > | cat",
                        "echo hello >>> out.txt", "(echo hello)",
                        "echo hello\nshutdown /s", "echo \0"):
            with self.subTest(command=command):
                self.assertEqual(self.assess(command).action, "deny")

    def test_wrong_request_kind_and_empty_segments_are_denied(self):
        for request in (
            Request("read_file", "file", "read"),
            Request("bash", "command", "exec"),
            Request("bash", "command", "exec", raw="echo", segments=[[]]),
        ):
            with self.subTest(request=request):
                self.assertEqual(assess_command_request(request).action, "deny")

    def test_assessment_does_not_prompt_or_execute(self):
        with patch("builtins.input", side_effect=AssertionError("不能询问用户")):
            with patch("subprocess.run", side_effect=AssertionError("不能执行命令")):
                self.assertEqual(self.assess("rm notes.txt").action, "ask")
                self.assertEqual(self.assess("shutdown /s").action, "deny")

    def test_original_command_cases_with_explicit_script_policy(self):
        cases = json.loads(Path(__file__).with_name("cases.json").read_text(encoding="utf-8"))
        for case in cases:
            if case["tool"] != "bash":
                continue
            with self.subTest(case=case["id"]):
                result = self.assess(case["args"]["command"])
                if case["id"] == "N-07":
                    self.assertEqual(result.action, "ask")  # 项目脚本同样可以执行任意代码
                elif case["expected"] == "block":
                    self.assertIn(result.action, {"ask", "deny"})
                else:
                    self.assertEqual(result.action, "allow")


if __name__ == "__main__":
    unittest.main()
