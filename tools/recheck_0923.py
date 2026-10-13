# -*- coding: utf-8 -*-
r"""2026-08 / 09 两批(v0.2.0)的发文前事实复核。

这篇文章是**先写好攒着、以后才发**的(2026-10-13 Mikko 定),所以下面每一条都会在
写稿日和发稿日之间漂移 —— 发之前必须跑一遍,不过就停下改文案:

  A. 两批 22 条里仍是 `unreviewed` 的条数(写稿日 19 条),逐条列出状态
  B. 回归 CVE-2026-86350 的受影响区间仍是 41293 修复版自己那几个版本
  C. 各条 Spring Boot 线在 Central 上的最新版、它自带的 tomcat.version、落不落在区间里
  D. 修复版 9.0.122 / 10.1.60 / 11.0.26 在 Central 上拿得到(带 404 哨兵)

🔴 拉取失败一律记为「复核不过」,不许当它没变 —— 拿不到 ≠ 没变。
"""
import json
import re
import subprocess
import sys
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
GH = r"D:\Program Files\GitHub CLI\gh.exe"
CENTRAL = "https://repo1.maven.org/maven2"

BATCH = ["CVE-2026-65182", "CVE-2026-65183", "CVE-2026-65637", "CVE-2026-65905",
         "CVE-2026-65927", "CVE-2026-66422", "CVE-2026-68525", "CVE-2026-68569",
         "CVE-2026-68763", "CVE-2026-73180", "CVE-2026-73581", "CVE-2026-75973",
         "CVE-2026-76183", "CVE-2026-77756", "CVE-2026-77762", "CVE-2026-77791",
         "CVE-2026-78383", "CVE-2026-78437", "CVE-2026-79677", "CVE-2026-86248",
         "CVE-2026-86350", "CVE-2026-87022"]
UNREVIEWED_AT_WRITING = 19

# 写稿日(2026-10-13)读到的:Boot 线 → (该线最新版, 自带 tomcat.version)
BOOT_AT_WRITING = {"2.7": ("2.7.18", "9.0.83"), "3.4": ("3.4.13", "10.1.50"),
                   "3.5": ("3.5.16", "10.1.55"), "4.0": ("4.0.8", "11.0.24"),
                   "4.1": ("4.1.1", "11.0.24")}
REGRESSION = {"9": ("9.0.118", "9.0.121"), "10": ("10.1.55", "10.1.59"),
              "11": ("11.0.22", "11.0.25")}
FIXED = ["9.0.122", "10.1.60", "11.0.26"]

fail = []


def get(url, timeout=90):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")


def status(url):
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"})
        return urllib.request.urlopen(req, timeout=60).status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def adv(cve):
    r = subprocess.run([GH, "api", "/advisories?cve_id=%s" % cve],
                       capture_output=True, text=True, encoding="utf-8", timeout=90)
    if r.returncode != 0:
        return None
    a = json.loads(r.stdout)
    return a[0] if a else False


def vkey(v):
    return [int(x) for x in re.findall(r"\d+", v)]


print("═══ A. 两批 22 条的 advisory 状态 ═══")
# 阳性对照:一条早已 reviewed 的,证明接口今天能分清两种状态
ctl = adv("CVE-2026-24880")
if not ctl or ctl.get("type") != "reviewed":
    fail.append("阳性对照 CVE-2026-24880 没读到 reviewed —— 接口读数不可信")
unrev = 0
for c in BATCH:
    a = adv(c)
    if a is None:
        print("  %s  🔴 拉取失败" % c)
        fail.append(c + " 拉取失败")
        continue
    if a is False:
        print("  %-16s 全局库无此条" % c)
        unrev += 1
        continue
    n = len(a.get("vulnerabilities") or [])
    if a.get("type") == "unreviewed" and n == 0:
        unrev += 1
    print("  %-16s type=%-11s 包数=%d" % (c, a.get("type"), n))
print("  仍进不了告警(unreviewed 且包数 0):%d 条(写稿日 %d)%s"
      % (unrev, UNREVIEWED_AT_WRITING, "✅" if unrev == UNREVIEWED_AT_WRITING else " 🔴 变了!"))
if unrev != UNREVIEWED_AT_WRITING:
    fail.append("unreviewed 条数从 %d 变成 %d" % (UNREVIEWED_AT_WRITING, unrev))

print("\n═══ B. 回归 CVE-2026-86350 的受影响区间 ═══")
for ln, (lo, hi) in REGRESSION.items():
    try:
        html = get("https://tomcat.apache.org/security-%s.html" % ln)
    except Exception as e:
        print("  🔴 抓取失败:%s" % str(e)[:120])
        fail.append("官方页 security-%s 抓取失败" % ln)
        continue
    # 本条编号在 </strong> 之后;Affects 在它后面、下一条标题之前
    m = re.search(r"</strong>\s*<a[^>]*>\s*CVE-2026-86350.*?Affects:\s*([^<]+)", html, re.S)
    got = re.sub(r"\s+", " ", m.group(1)).strip() if m else None
    want = "%s to %s" % (lo, hi)
    ok = got == want
    print("  %s 线:官方 %s(写稿日 %s)%s" % (ln, got, want, "✅" if ok else " 🔴 变了!"))
    if not ok:
        fail.append("86350 在 %s 线的区间从 %s 变成 %s" % (ln, want, got))

print("\n═══ C. 各条 Spring Boot 线最新版自带的 Tomcat ═══")
try:
    meta = get(CENTRAL + "/org/springframework/boot/spring-boot-dependencies/maven-metadata.xml")
    allv = re.findall(r"<version>(\d+\.\d+\.\d+)</version>", meta)
except Exception as e:
    allv = []
    fail.append("Boot 版本清单抓取失败:%s" % str(e)[:100])
for line, (v0, t0) in BOOT_AT_WRITING.items():
    mine = sorted((v for v in allv if v.startswith(line + ".")), key=vkey)
    if not mine:
        print("  Boot %s 线:🔴 没读到版本" % line)
        fail.append("Boot %s 线没读到版本" % line)
        continue
    latest = mine[-1]
    try:
        pom = get("%s/org/springframework/boot/spring-boot-dependencies/%s/spring-boot-dependencies-%s.pom"
                  % (CENTRAL, latest, latest))
        tv = (re.search(r"<tomcat\.version>([^<]+)", pom) or [None, None])[1]
    except Exception:
        tv = None
    same = latest == v0 and tv == t0
    print("  Boot %s 线:最新 %s → tomcat %s(写稿日 %s → %s)%s"
          % (line, latest, tv, v0, t0, "✅" if same else " 🔴 变了!"))
    if not same:
        fail.append("Boot %s 线从 %s/%s 变成 %s/%s" % (line, v0, t0, latest, tv))

print("\n═══ D. 修复版在 Central 上拿不拿得到 ═══")
sent = status(CENTRAL + "/org/apache/tomcat/embed/tomcat-embed-core/9.9.999/tomcat-embed-core-9.9.999.pom")
if sent != 404:
    fail.append("404 哨兵没返回 404(%s)—— 这一节读数不可信" % sent)
for v in FIXED:
    st = status("%s/org/apache/tomcat/embed/tomcat-embed-core/%s/tomcat-embed-core-%s.pom" % (CENTRAL, v, v))
    print("  tomcat-embed-core %s → %s %s" % (v, st, "✅" if st == 200 else "🔴"))
    if st != 200:
        fail.append("修复版 %s 读到 %s" % (v, st))

print("\n" + "=" * 60)
if fail:
    print("🔴 复核未通过,**停下改文案**,不要先发了再说:")
    for f in fail:
        print("   - %s" % f)
    sys.exit(1)
print("✅ 全部承重论据复核通过,可以往下走")
