# -*- coding: utf-8 -*-
r"""第 6 注 tomcat-check 发文前事实复核。

承重论据(任何一条失效,文章就变成错的):
  A. 那 6 条 advisory 仍是 `unreviewed` 且受影响包数为 0
  B. 另 3 条的坐标里仍然没有 tomcat-embed-*
  C. 官方 2026 年条目数(51)、评级差 >=2 级的条数(23,不计 GitHub 未评级)没变(10-15 更正前是 29 / 17)
🔴 这些是**时效性**论据 —— GitHub 随时可能把 unreviewed 转成 reviewed。
   复核不过 → 停下改文案,不许「先发了再说」。
"""
import json
import re
import subprocess
import sys
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
GH = r"D:\Program Files\GitHub CLI\gh.exe"

SB = {"org.apache.tomcat.embed:tomcat-embed-core",
      "org.apache.tomcat.embed:tomcat-embed-el",
      "org.apache.tomcat.embed:tomcat-embed-websocket"}

UNREVIEWED_6 = ["CVE-2026-59083", "CVE-2026-53404", "CVE-2026-55276",
                "CVE-2026-55957", "CVE-2026-55956", "CVE-2026-53434"]
WRONG_COORD_3 = ["CVE-2026-24733", "CVE-2026-29145", "CVE-2026-29146"]

fail = []


def adv(cve):
    r = subprocess.run([GH, "api", "/advisories?cve_id=%s" % cve],
                       capture_output=True, text=True, encoding="utf-8", timeout=90)
    if r.returncode != 0:
        return None
    a = json.loads(r.stdout)
    return a[0] if a else False


print("═══ A. 6 条 unreviewed 是否仍然 unreviewed 且包数为 0 ═══")
for c in UNREVIEWED_6:
    a = adv(c)
    if a is None:
        print("  %s  🔴 拉取失败 —— 不计入结论,但也不能当它没变" % c); fail.append(c + " 拉取失败"); continue
    n = len(a.get("vulnerabilities") or [])
    ok = a.get("type") == "unreviewed" and n == 0
    print("  %-16s type=%-11s 包数=%-3d %s" % (c, a.get("type"), n, "✅" if ok else "🔴 已变!"))
    if not ok:
        fail.append("%s 已从 unreviewed/0包 变为 %s/%d包" % (c, a.get("type"), n))

print("\n═══ B. 3 条 reviewed 的坐标里是否仍无 tomcat-embed-* ═══")
for c in WRONG_COORD_3:
    a = adv(c)
    if a is None:
        print("  %s  🔴 拉取失败" % c); fail.append(c + " 拉取失败"); continue
    pkgs = sorted({(v.get("package") or {}).get("name") or "" for v in (a.get("vulnerabilities") or [])})
    hit = SB & set(pkgs)
    print("  %-16s %s %s" % (c, "🔴 现在已含 embed 坐标!" if hit else "✅ 仍不含", ", ".join(pkgs)))
    if hit:
        fail.append("%s 现已列入 %s,Dependabot 会告警了" % (c, hit))

print("\n═══ C. 官方页面条目数与评级差 ═══")
RANK = {"low": 0, "moderate": 1, "medium": 1, "important": 2, "high": 2, "critical": 3}
official = {}
for ln in ("9", "10", "11"):
    try:
        html = urllib.request.urlopen(urllib.request.Request(
            "https://tomcat.apache.org/security-%s.html" % ln,
            headers={"User-Agent": "Mozilla/5.0"}), timeout=90).read().decode("utf-8", "replace")
    except Exception as e:
        print("  🔴 抓取失败:%s" % str(e)[:120]); fail.append("官方页面抓取失败"); html = ""
    for m in re.finditer(r"<strong>\s*(Low|Moderate|Important|Critical)\s*:\s*(.+?)\s*</strong>\s*<a[^>]*>\s*(CVE-\d{4}-\d+)",
                         html, re.S):
        official.setdefault(m.group(3), m.group(1))

y26 = {c: s for c, s in official.items() if c.startswith("CVE-2026")}
# 2026-10-15 更正块挂上后,文案里的现值是 51 / 23(原文 08-06 的 29 / 17 已在更正块里注明是旧快照)
TOTAL, GAP = 51, 23
print("  官方 2026 条目:%d(文案写的是 %d)%s" % (len(y26), TOTAL, "✅" if len(y26) == TOTAL else " 🔴 变了!"))
if len(y26) != TOTAL:
    fail.append("官方 2026 条目数从 %d 变成 %d" % (TOTAL, len(y26)))

# GitHub 尚未评级(severity 为空 / unknown)的不算评级差 —— 2026-10-15 前它们落到默认值 9,被当成「差 >=2 级」计进去了
gap = unrated = 0
for c, off in y26.items():
    a = adv(c)
    if not a:
        continue
    gh = (a.get("severity") or "").lower()
    if gh not in RANK:
        unrated += 1
        continue
    if abs(RANK[off.lower()] - RANK[gh]) >= 2:
        gap += 1
print("  评级差 >=2 级:%d 条(文案写的是 %d;GitHub 未评级 %d 条不计)%s" % (gap, GAP, unrated, "✅" if gap == GAP else " 🔴 变了!"))
if gap != GAP:
    fail.append("评级差 >=2 级的条数从 %d 变成 %d" % (GAP, gap))

print("\n" + "=" * 60)
if fail:
    print("🔴 复核未通过,**停下改文案**,不要先发了再说:")
    for f in fail:
        print("   - %s" % f)
    sys.exit(1)
print("✅ 全部承重论据复核通过,可以往下走")
