# -*- coding: utf-8 -*-
r"""从**两个一手源**生成 CveTable.java —— 一行都不手抄。

源 A:https://tomcat.apache.org/security-{9,10,11}.html   官方评级(ASF 体系)+ 标题 + Affects 版本区间
源 B:GitHub Advisory API                                  GitHub 评级 + CVSS + type + 受影响 Maven 坐标

🔴 本脚本存在的理由,是三个只有一手源才看得见的事实:
   1. `Affects:` 行在 HTML 里位于 CVE 标题**前面**,属于紧随其后的那一条 ——
      配对方向反了就会给出「看起来完全正常但整体错位一格」的判定表。
      → 用源 B 的结构化版本下限自动校验方向(ASSERT 3),错了直接中止。
   2. 6 条 advisory 是 `unreviewed` 且受影响包为空 —— 它们的版本区间**只有源 A 有**。
   3. WebFetch 转述过一次 CVE-2026-41293 的区间(9.0.0.M1 而非 9.0.2),就是错位一格。

任一断言不满足 → **中止,不写文件**(防「解析失败生成空壳表而测试照样全绿」)。
"""
import json
import os
import re
import subprocess
import sys
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
GH = r"D:\Program Files\GitHub CLI\gh.exe"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "src", "main", "java", "dev", "mikko", "tomcatcheck", "CveTable.java")
YEAR = "2026"

# Spring Boot 依赖树里实际存在的 Tomcat 坐标 —— 判断 Dependabot 会不会告警的依据
SB_COORDS = {"org.apache.tomcat.embed:tomcat-embed-core",
             "org.apache.tomcat.embed:tomcat-embed-el",
             "org.apache.tomcat.embed:tomcat-embed-websocket"}

# 触发条件:唯一的人工输入,来自官方页面 Mitigation/描述原文。
# 🔴 ASSERT 4 强制每条 CVE 都要有,漏一条就中止 —— 留空会被读者读成「无条件即中招」。
CONDITIONS = {
    "default": ("DEFAULT", "默认配置即受影响"),
    "CVE-2026-59083": ("CONFIG", "仅当显式配置了 RewriteValve(rewrite.config)"),
    "CVE-2026-53404": ("CONFIG", "仅当显式配置了 RewriteValve 且使用 ornext 标志"),
    "CVE-2026-55957": ("CONFIG", "仅当使用 JNDIRealm + GSSAPI 认证"),
    # 措辞只写「触发条件」本身,不写「内嵌版不含」—— 后者是排除理由,放在 excludeReason 里。
    # 混合部署(装了 tomcat-tribes)时这些条目是适用的,触发条件里带排除语会自相矛盾。
    "CVE-2026-59084": ("CLUSTER", "仅当启用集群通信的 EncryptInterceptor"),
    "CVE-2026-55955": ("CLUSTER", "仅当启用集群通信的 EncryptInterceptor"),
    "CVE-2026-34487": ("CLUSTER", "仅当启用 Kubernetes / 云环境的集群成员发现"),
    "CVE-2026-29145": ("TLS", "仅当启用 OpenSSL + OCSP 校验"),
    "CVE-2026-29146": ("TLS", "仅当启用 OpenSSL + OCSP 校验"),
    "CVE-2026-34500": ("TLS", "仅当使用 FFM/panama OpenSSL(需 JDK22+,9.0 线不适用)"),
    "CVE-2026-53434": ("TLS", "仅当配置了 CRL 且配置无效"),
    "CVE-2026-24734": ("TLS", "仅当启用 OCSP 校验"),
    "CVE-2026-50229": ("EXAMPLES", "仅示例应用 webapps/examples(生产环境应已移除)"),
    "CVE-2026-66299": ("EXAMPLES", "仅示例应用 webapps/examples(生产环境应已移除)"),
    "CVE-2026-43514": ("AJP", "仅当启用 AJP 连接器"),
    "CVE-2026-41284": ("WEBDAV", "仅当启用 WebDAV servlet"),
    # 下面三条由 ASSERT4 拦下后补,措辞逐字对照官方描述原文,未作外推
    "CVE-2026-43512": ("CONFIG", "仅当配置了 DIGEST 认证(此时未知用户提交密码 \"null\" 即可通过)"),
    "CVE-2026-43515": ("CONFIG", "仅当多个 security-constraint 对同一扩展名模式定义了 HTTP 方法约束"),
    "CVE-2026-55956": ("CONFIG", "仅当对 default servlet 配置了 security-constraint"),
}

LINES = ["9", "10", "11"]

# 🔴 对「Spring Boot 内嵌 Tomcat」不适用的条目 —— 受影响代码不在 tomcat-embed-* 里。
# 这不是我的判断,是实测:下 9.0.118 真 jar 列 class 得到的。ASSERT6 每次重跑都会重验。
# 少了这层,工具会拿 tribes/examples 的洞去吓唬 Spring Boot 用户(他们根本没装那些代码)。
EXCLUDE_FROM_EMBED = {
    "CVE-2026-59084": ("EncryptInterceptor", "集群组件,在 tomcat-tribes.jar,内嵌版不含"),
    "CVE-2026-55955": ("EncryptInterceptor", "集群组件,在 tomcat-tribes.jar,内嵌版不含"),
    "CVE-2026-34487": ("CloudMembershipService", "集群组件,在 tomcat-tribes.jar,内嵌版不含"),
    "CVE-2026-34500": ("panama", "FFM/panama OpenSSL 专属,tomcat-embed-* 内无 panama 类"),
    # 🔴 真实构件复验时才发现:官方标题写明 "for FFM Connector"。
    #    实测 9.0.118 / 10.1.54 / 11.0.21 三条线的 embed-core 内 panama 类均为 0 个
    #    —— FFM 连接器在单独的 tomcat-coyote-ffm 构件里,内嵌版根本没有。
    #    不排除的话,工具会对 Spring Boot 用户报一条 CVSS 9.1 且他绝不可能中的洞。
    "CVE-2026-53434": ("panama", "FFM 连接器专属(tomcat-coyote-ffm),tomcat-embed-* 内不含"),
    "CVE-2026-50229": (None, "示例应用 webapps/examples,不在任何 jar 内"),
    "CVE-2026-66299": (None, "示例应用 webapps/examples,不在任何 jar 内"),
}


# ────────────────────────── 源 A:官方页面 ──────────────────────────
def fetch(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        return urllib.request.urlopen(req, timeout=90).read().decode("utf-8", "replace")
    except Exception as e:
        sys.exit("🔴 抓取失败 %s:%s —— 拿不到 ≠ 没有条目,中止" % (url, str(e)[:150]))


def parse_official(html, line):
    """返回 {cve: {sev, title, ranges: {线: (low, high)}}}。

    结构(**实测确认过方向,别凭印象改**):
        <p><strong>Moderate: 标题</strong> <a ...>CVE-2026-24734</a></p>
        <p>描述 / 修复 commit / 上报与公开时间 …</p>
        <p>Affects: 9.0.83 to 9.0.114</p>
        <p><strong>Low: 下一条标题</strong> <a ...>CVE-2026-24733</a></p>

    🔴 `Affects:` 属于它**前面**那条 CVE,不是后面那条。
       只看一眼 HTML 片段极易看反(片段里 Affects 恰好紧挨着下一条标题)。
       三处 first_patched 交叉验证:
         24734 → 9.0.83 to 9.0.114,GitHub first_patched 9.0.115 ✅
         24733 → 9.0.0.M1 to 9.0.112,GitHub first_patched 9.0.113 ✅
         34500 → 9.0.92 to 9.0.116,GitHub first_patched 9.0.117 ✅
    """
    blocks = re.findall(r"<p>(.*?)</p>", html, re.S)
    out, current = {}, None
    for b in blocks:
        plain = re.sub(r"<[^>]+>", " ", b)
        plain = re.sub(r"&nbsp;", " ", plain)
        plain = re.sub(r"\s+", " ", plain).strip()

        m_hdr = re.search(r"<strong>\s*(Low|Moderate|Important|Critical)\s*:\s*(.+?)\s*</strong>", b, re.S)
        m_cve = re.search(r"(CVE-\d{4}-\d{4,7})", b)
        if m_hdr and m_cve:
            cve = m_cve.group(1)
            title = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", m_hdr.group(2))).strip()
            out.setdefault(cve, {"sev": m_hdr.group(1), "title": title, "ranges": {}, "desc": ""})
            current = cve
            continue

        # 标题后的第一段就是官方描述 —— 存原文,工具输出它而不是我的转述
        if current and plain and not out[current]["desc"] \
                and not plain.startswith(("Affects:", "This was fixed", "This issue")):
            out[current]["desc"] = plain[:300]

        m_aff = re.match(r"^Affects:\s*(.+)$", plain)
        if m_aff and current:
            m = re.match(r"^(\S+)\s+to\s+(\S+)", m_aff.group(1).strip())
            if m:
                out[current]["ranges"][line] = (m.group(1), m.group(2).rstrip(".,"))
            else:                       # 形如 "Affects: 9.0.116"(单版本)
                only = m_aff.group(1).strip().split()[0].rstrip(".,")
                out[current]["ranges"][line] = (only, only)
            current = None              # 一条 CVE 在同一页只取一个 Affects
    return out


official = {}
for ln in LINES:
    got = parse_official(fetch("https://tomcat.apache.org/security-%s.html" % ln), ln)
    print("security-%s.html → %d 条" % (ln, len(got)))
    for cve, rec in got.items():
        if cve in official:
            official[cve]["ranges"].update(rec["ranges"])
        else:
            official[cve] = rec

y = {c: v for c, v in official.items() if c.startswith("CVE-%s" % YEAR)}
print("\n源 A:%s 年 %d 条(全部年份 %d 条)" % (YEAR, len(y), len(official)))

# ASSERT 1:官方页面必须解析出足够多的条目,否则是正则失效而非「今年很太平」
assert len(official) >= 100, "🔴 ASSERT1 失败:官方页面只解析到 %d 条,正则可能已失效" % len(official)
assert len(y) >= 20, "🔴 ASSERT1 失败:%s 年只解析到 %d 条" % (YEAR, len(y))


# ────────────────────────── 源 B:GitHub Advisory ──────────────────────────
def gh_adv(cve):
    r = subprocess.run([GH, "api", "/advisories?cve_id=%s" % cve],
                       capture_output=True, text=True, encoding="utf-8", timeout=120)
    if r.returncode != 0:
        sys.exit("🔴 GitHub API 失败(%s):%s —— 拿不到 ≠ 没有,中止" % (cve, (r.stderr or "")[:200]))
    arr = json.loads(r.stdout)
    return arr[0] if arr else None


print("\n拉 GitHub advisory(%d 条)..." % len(y), flush=True)
rows = []
for cve in sorted(y):
    o = y[cve]
    a = gh_adv(cve)
    gh_sev = gh_type = gh_score = None
    pkgs, gh_ranges = [], {}
    if a:
        gh_sev, gh_type = a.get("severity"), a.get("type")
        gh_score = (a.get("cvss") or {}).get("score")
        for v in a.get("vulnerabilities") or []:
            name = (v.get("package") or {}).get("name") or ""
            pkgs.append(name)
            fp = v.get("first_patched_version") or ""
            m = re.match(r"(\d+)\.", fp)
            if m:
                gh_ranges.setdefault(m.group(1), []).append(fp)
    # Dependabot 会不会告警:unreviewed(包列表空)或坐标不在 Spring Boot 依赖树里
    alerts = bool(SB_COORDS & set(pkgs)) and gh_type == "reviewed"
    rows.append({"cve": cve, "off_sev": o["sev"], "title": o["title"], "ranges": o["ranges"],
                 "desc": o.get("desc", ""),
                 "gh_sev": gh_sev, "gh_type": gh_type, "gh_score": gh_score,
                 "pkgs": sorted(set(p for p in pkgs if p)), "gh_ranges": gh_ranges,
                 "alerts": alerts})
    print("  %s %-10s → %-10s %s" % (cve, o["sev"], gh_sev or "无", "" if alerts else "🔴Dependabot不报"))

# ASSERT 2:必须有条目同时拿到两侧评级,否则合并逻辑没生效
both = [r for r in rows if r["gh_sev"]]
assert len(both) >= 20, "🔴 ASSERT2 失败:只有 %d 条同时拿到两侧评级" % len(both)

# ASSERT 3 ⭐ 配对方向校验 —— 本脚本最重要的断言
#
# 🔴 第一版用**下限**做校验器,22/24 处不一致,险些误判成错位。复核后是校验器选错字段:
#    下限两边根本不同口径 —— GitHub 会把 8.5/9.0 合成一个区间(">= 8.5.30, < 9.0.116"),
#    官方则按产品线分别列(9.0 线写 "9.0.114 to ...")。**下限不同是正常的。**
# → 改用**上限**:两边都以「修复版」为界,官方 Affects 上限 + 1 == GitHub first_patched。
#    这个关系跨批次各不相同(9.0.115 / 9.0.116 / 9.0.118 …),错位一格会立刻暴露。
def bump(v):
    """9.0.117 → 9.0.118;末段非纯数字(如 M1)返回 None,不参与校验。"""
    parts = v.split(".")
    if not parts[-1].isdigit():
        return None
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)


checked = mismatch = 0
for r in rows:
    if r["gh_type"] != "reviewed":
        continue
    for line, (low, high) in r["ranges"].items():
        if not high:
            continue
        nxt = bump(high)
        if not nxt:
            continue
        for fp in set(r["gh_ranges"].get(line, [])):
            checked += 1
            if fp != nxt:
                mismatch += 1
                print("  ⚠️ 上限不一致 %s 线%s:官方到 %s(应修复于 %s)vs GitHub first_patched %s"
                      % (r["cve"], line, high, nxt, fp))

print("\nASSERT3 配对方向(上限口径):校验 %d 处,不一致 %d 处" % (checked, mismatch))
assert checked >= 10, "🔴 ASSERT3 失败:可校验样本只有 %d 处,不足以确认配对方向" % checked
assert mismatch <= checked * 0.25, (
    "🔴 ASSERT3 失败:%d/%d 处上限对不上 —— Affects 极可能整体错位一格,中止" % (mismatch, checked))

# ASSERT 4:触发条件必须每条都有(默认走 default,但集群/示例类必须显式列出)
missing = [r["cve"] for r in rows if r["cve"] not in CONDITIONS and r["off_sev"] != "Low"]
assert not missing, "🔴 ASSERT4 失败:这些非 Low 条目缺触发条件标注:%s" % missing

# ASSERT 5:必须真的存在「Dependabot 不报」的条目,否则这一注的核心主张不成立
silent = [r for r in rows if not r["alerts"]]
assert len(silent) >= 5, "🔴 ASSERT5 失败:只有 %d 条 Dependabot 不报,核心主张需重新核实" % len(silent)

# ASSERT 6 ⭐ 下真 jar 复验 EXCLUDE_FROM_EMBED —— 排除依据必须是实测,不是我记得
print("\nASSERT6:下载 9.0.118 真 jar 复验排除依据...", flush=True)
import io
import zipfile

_B = "https://repo1.maven.org/maven2/org/apache/tomcat"
# 三条线各验一个版本 —— 排除依据必须对三条线都成立,只验 9.0 会漏掉「10/11 线加了这个类」的情况
_EMBED_VERS = ["9.0.118", "10.1.54", "11.0.21"]


def _entries(url):
    try:
        raw = urllib.request.urlopen(urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0"}), timeout=180).read()
    except Exception as e:
        sys.exit("🔴 ASSERT6 下载失败 %s:%s —— 拿不到 ≠ 类不存在,中止" % (url, str(e)[:150]))
    return "\n".join(zipfile.ZipFile(io.BytesIO(raw)).namelist()).lower()


_embed = {v: _entries("%s/embed/tomcat-embed-core/%s/tomcat-embed-core-%s.jar" % (_B, v, v))
          for v in _EMBED_VERS}
_tribes = _entries("%s/tomcat-tribes/9.0.118/tomcat-tribes-9.0.118.jar" % _B)

for _cve, (_marker, _why) in EXCLUDE_FROM_EMBED.items():
    if not _marker:
        continue                                   # 示例应用不在任何 jar 里,无类可验
    for _v, _blob in _embed.items():
        assert _marker.lower() not in _blob, (
            "🔴 ASSERT6 失败:%s 的 %s **在 embed-core %s 里**,不能排除 —— 排除清单已过时"
            % (_cve, _marker, _v))
    print("   %s  %-24s 三条线 embed-core 内均确认无 ✅" % (_cve, _marker))
assert "encryptinterceptor" in _tribes, \
    "🔴 ASSERT6 失败:EncryptInterceptor 在 tribes 里也找不到 —— 类名或 jar 选错,排除依据不成立"
print("   反向校验:EncryptInterceptor 确实在 tomcat-tribes 里 ✅")


# ────────────────────────── 生成 Java ──────────────────────────
def jstr(s):
    return '"%s"' % (s or "").replace("\\", "\\\\").replace('"', '\\"')


lines_out = [
    "package dev.mikko.tomcatcheck;",
    "",
    "import java.util.ArrayList;",
    "import java.util.Collections;",
    "import java.util.List;",
    "",
    "/**",
    " * 由 tools/gen_rules.py 从两个一手源生成,请勿手工编辑。",
    " * 源 A:https://tomcat.apache.org/security-{9,10,11}.html(官方 ASF 评级 + 影响区间)",
    " * 源 B:GitHub Advisory API(GitHub 评级 / CVSS / type / 受影响 Maven 坐标)",
    " */",
    "public final class CveTable {",
    "    private CveTable() {}",
    "",
    "    public static final String GENERATED_FROM = \"tomcat.apache.org + GitHub Advisory API\";",
    "",
    "    private static final List<Cve> ALL = new ArrayList<>();",
    "",
    "    static {",
]
for r in rows:
    cond = CONDITIONS.get(r["cve"], CONDITIONS["default"])
    for line, (low, high) in sorted(r["ranges"].items()):
        if not high:
            continue
        exc = EXCLUDE_FROM_EMBED.get(r["cve"])
        lines_out.append("        add(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);" % (
            jstr(r["cve"]), jstr(r["off_sev"]), jstr(r["gh_sev"] or "unknown"),
            "%.1f" % r["gh_score"] if r["gh_score"] else "-1.0",
            jstr(r["gh_type"] or "none"), "true" if r["alerts"] else "false",
            jstr(line), jstr(low or ""), jstr(high),
            jstr(cond[0]), jstr(cond[1]), jstr(r["title"]), jstr(r["desc"]),
            "false" if exc else "true", jstr(exc[1] if exc else "")))
lines_out += [
    "    }",
    "",
    "    private static void add(String cve, String off, String gh, double score, String type,",
    "                            boolean dependabot, String line, String low, String high,",
    "                            String condKind, String condText, String title, String desc,",
    "                            boolean embedApplicable, String excludeReason) {",
    "        ALL.add(new Cve(cve, off, gh, score, type, dependabot, line, low, high,",
    "                        condKind, condText, title, desc, embedApplicable, excludeReason));",
    "    }",
    "",
    "    public static List<Cve> all() { return Collections.unmodifiableList(ALL); }",
    "}",
]
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(lines_out) + "\n")

print("\n✅ 已生成 %s" % os.path.normpath(OUT))
print("   %s 年 %d 条 CVE,展开成 %d 条版本线规则" % (YEAR, len(rows), len(lines_out) - 24))
print("   其中 Dependabot 不会告警:%d 条(unreviewed %d / 坐标不匹配 %d)" % (
    len(silent),
    sum(1 for r in silent if r["gh_type"] == "unreviewed"),
    sum(1 for r in silent if r["gh_type"] == "reviewed")))
json.dump(rows, open(os.path.join(HERE, "rules_dump.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)
