"""只在临时目录里验证 glob，不调用模型或执行危险命令。"""
import contextlib
import importlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import permissions


class GlobPermissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Agent 的模型客户端与这些测试无关；替换它，避免依赖 SDK 或加载密钥。
        anthropic = ModuleType("anthropic")
        anthropic.Anthropic = lambda **kwargs: object()
        dotenv = ModuleType("dotenv")
        dotenv.load_dotenv = lambda: False
        with patch.dict(sys.modules, {"anthropic": anthropic, "dotenv": dotenv}):
            cls.agent = importlib.import_module("agent")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="minicode-glob-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "workspace"
        self.root.mkdir()
        self.outside = self.base / "outside"
        self.outside.mkdir()
        for name in ("main.py", "src/app.py", "src/deep/test_a.py",
                     "src/notes.txt", "report[1].txt", ".hidden.py",
                     ".cache/cached.py"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("test", encoding="utf-8")
        (self.outside / "secret.py").write_text("private", encoding="utf-8")
        previous_root = self.agent.WORKDIR
        self.agent.WORKDIR = self.root
        self.addCleanup(setattr, self.agent, "WORKDIR", previous_root)

    def assess(self, pattern):
        request = permissions.prepare_request("glob", {"pattern": pattern}, self.root)
        return permissions.assess_file_request(request)

    def test_original_n05_is_allowed_and_finds_python_files(self):
        self.assertEqual(self.assess("**/*.py").action, "allow")
        self.assertEqual(
            permissions.safe_glob("**/*.py", self.root),
            ["main.py", "src/app.py", "src/deep/test_a.py"],
        )

    def test_single_level_and_character_patterns(self):
        self.assertEqual(permissions.safe_glob("*.py", self.root), ["main.py"])
        self.assertEqual(permissions.safe_glob("src/a??.py", self.root), ["src/app.py"])
        self.assertEqual(
            permissions.safe_glob("src/deep/test_[ab].py", self.root),
            ["src/deep/test_a.py"],
        )
        self.assertEqual(
            permissions.safe_glob("report[[]1].txt", self.root), ["report[1].txt"]
        )

    def test_double_star_matches_zero_levels_and_deduplicates(self):
        self.assertEqual(
            permissions.safe_glob("src/**/app.py", self.root), ["src/app.py"]
        )
        self.assertEqual(
            permissions.safe_glob("**/**/*.py", self.root),
            ["main.py", "src/app.py", "src/deep/test_a.py"],
        )

    def test_explicit_hidden_paths_and_directory_only_patterns(self):
        self.assertEqual(permissions.safe_glob(".*.py", self.root), [".hidden.py"])
        self.assertEqual(
            permissions.safe_glob(".cache/*.py", self.root), [".cache/cached.py"]
        )
        self.assertEqual(permissions.safe_glob("src/*/", self.root), ["src/deep/"])

    def test_internal_absolute_pattern_and_windows_separators(self):
        self.assertEqual(
            permissions.safe_glob(str(self.root / "src" / "*.py"), self.root),
            ["src/app.py"],
        )
        self.assertEqual(
            permissions.safe_glob(r"src\**\*.py", self.root),
            ["src/app.py", "src/deep/test_a.py"],
        )

    def test_parent_components_are_denied_everywhere(self):
        for pattern in ("../*.py", r"..\*.py", "*/../../secret.py",
                        "**/../*.py", "src/../*.py"):
            with self.subTest(pattern=pattern):
                self.assertEqual(self.assess(pattern).action, "deny")
                with self.assertRaises(ValueError):
                    permissions.safe_glob(pattern, self.root)

    def test_external_absolute_pattern_is_denied(self):
        pattern = str(self.outside / "*.py")
        self.assertEqual(self.assess(pattern).action, "deny")
        with self.assertRaises(ValueError):
            permissions.safe_glob(pattern, self.root)

    def test_missing_or_invalid_pattern_is_denied(self):
        for args in ({}, {"path": "**/*.py"}, {"pattern": ""},
                     {"pattern": "  "}, {"pattern": None},
                     {"pattern": 123}, {"pattern": "\0"}):
            with self.subTest(args=args):
                req = permissions.prepare_request("glob", args, self.root)
                self.assertEqual(permissions.assess_file_request(req).action, "deny")

    @unittest.skipUnless(os.name == "nt", "Windows 盘符相对路径")
    def test_drive_relative_pattern_is_denied(self):
        self.assertEqual(self.assess(self.root.drive + "*.py").action, "deny")

    def test_missing_match_returns_empty(self):
        self.assertEqual(self.assess("missing/**/*.py").action, "allow")
        self.assertEqual(permissions.safe_glob("missing/**/*.py", self.root), [])
        self.assertEqual(self.agent.glob("missing/**/*.py"), "(no matches)")

    def test_normal_file_path_is_not_cut_at_brackets(self):
        req = permissions.prepare_request(
            "read_file", {"path": "a[1]/../../secret.py"}, self.root
        )
        self.assertFalse(req.targets[0]["inside"])
        self.assertEqual(permissions.assess_file_request(req).action, "deny")
        req = permissions.prepare_request(
            "read_file", {"path": "report[1].txt"}, self.root
        )
        self.assertEqual(req.targets[0]["path"], self.root / "report[1].txt")
        self.assertEqual(permissions.assess_file_request(req).action, "allow")

    def test_missing_file_path_is_denied(self):
        req = permissions.prepare_request("read_file", {}, self.root)
        self.assertEqual(permissions.assess_file_request(req).action, "deny")

    def test_agent_gate_and_execution_share_the_glob_policy(self):
        allowed = SimpleNamespace(name="glob", input={"pattern": "**/*.py"})
        denied = SimpleNamespace(name="glob", input={"pattern": "*/../../secret.py"})
        self.assertTrue(self.agent.check_permission(allowed))
        with patch.object(self.agent, "PERMISSION_MODE", "auto_allow"):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(self.agent.check_permission(denied))
        self.assertEqual(
            self.agent.glob("**/*.py").splitlines(),
            ["main.py", "src/app.py", "src/deep/test_a.py"],
        )
        self.assertTrue(self.agent.glob("../*.py").startswith("Error:"))

    def test_results_are_limited_and_agent_reports_truncation(self):
        for index in range(205):
            (self.root / f"file_{index:03}.txt").write_text("", encoding="utf-8")
        self.assertEqual(len(permissions.safe_glob("file_*.txt", self.root)), 201)
        lines = self.agent.glob("file_*.txt").splitlines()
        self.assertEqual(len(lines), 201)
        self.assertIn("more matches omitted", lines[-1])

    def assert_link_is_not_traversed(self, link):
        visited = []
        original_iterdir = Path.iterdir

        def record_iterdir(path):
            visited.append(path.resolve())
            return original_iterdir(path)

        with patch.object(Path, "iterdir", record_iterdir):
            matches = permissions.safe_glob("**/*.py", self.root)
        self.assertNotIn(f"{link.name}/secret.py", matches)
        self.assertTrue(all(path.is_relative_to(self.root) for path in visited))
        self.assertEqual(self.assess(f"{link.name}/*.py").action, "deny")

    def test_external_directory_symlink_is_not_traversed(self):
        link = self.root / "linked"
        try:
            link.symlink_to(self.outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("当前 Windows 账户未启用符号链接创建权限")
        self.assert_link_is_not_traversed(link)

    @unittest.skipUnless(os.name == "nt", "Windows 目录联接")
    def test_external_junction_is_not_traversed(self):
        link = self.root / "junction"
        # 两个路径均由本测试创建，且限制在同一个临时目录内。
        self.assertTrue(link.parent.resolve().is_relative_to(self.base))
        self.assertTrue(self.outside.resolve().is_relative_to(self.base))
        completed = subprocess.run(
            ["cmd", "/d", "/c", "mklink", "/J", str(link), str(self.outside)],
            capture_output=True,
        )
        if completed.returncode:
            self.skipTest("当前环境无法创建 Windows 目录联接")
        try:
            self.assert_link_is_not_traversed(link)
        finally:
            link.rmdir()                           # 只移除联接，不删除目标目录
        self.assertTrue((self.outside / "secret.py").exists())


if __name__ == "__main__":
    unittest.main()
