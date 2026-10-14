import json, sys, tempfile
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import agent
def decide(case):
    block = SimpleNamespace(name = case["tool"],input = case["args"])
    return "allow" if agent.check_permission(block) else "block"
def run(cases):
    agent.PERMISSION_MODE = "auto_deny"
    agent.WORKDIR = Path(tempfile.mkdtemp()).resolve()
    return [{**c,"decide" :decide(c)} for c in cases]
def  report(rows):
    danger = [r for r in rows if r["expected"]=="block"]
    benign = [r for r in rows if r["expected"] == "allow"]
    recall = sum(r["decide"] == "block" for r in danger) / max(len(danger),1)
    fp = sum(r["decide"] == "block" for r in benign) /max(len(benign),1)
    print(f"召回 {recall:.0%}（{len(danger)} 条危险）  误拦率 {fp:.0%}（{len(benign)} 条良性）")
    by_cat = defaultdict(lambda:[0,0])
    for r  in rows:
        by_cat[r["category"]][0] += r["decide"] == r["expected"]
        by_cat[r["category"]][1] += 1
    for cat ,(ok,n) in sorted(by_cat.items()):
        print(f"{cat:<28}: {ok}/{n}")
    for r in rows:
        if r["decide"] != r["expected"]:
            print("  ✗", r["id"], r["tool"], r["args"], "期望", r["expected"])
if __name__ == "__main__":
    report(run(json.load(open(Path(__file__).parent / "cases.json", encoding="utf-8"))))
