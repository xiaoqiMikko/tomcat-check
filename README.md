# tomcat-check

查出你实际装的 Tomcat 版本,并对每条 2026 年的 CVE **同时给出两套评级和触发条件**。

零依赖单 jar,离线跑,不联网、不上传任何东西。

---

## 它解决什么

**一、Spring Boot 项目的内嵌 Tomcat 版本,你的 pom 里没有。**

它由 `spring-boot-starter-parent` 的 `tomcat.version` 属性管着,你在 pom 里只看得到
`spring-boot-starter-web`。所以本工具**扫构建产物**(jar / fat jar / 安装目录),不读 pom。

**二、有些条目进不了 Dependabot 的告警。**

2026 年 Tomcat 公布了 29 条 CVE,其中一部分因为两种机制不会出现在 Spring Boot 项目的告警里:

| 机制 | 说明 |
|---|---|
| advisory 是 `unreviewed` | GitHub 只用 `reviewed` 的 advisory 做 Dependabot 告警。`unreviewed` 是 NVD 自动导入、尚未人工确认受影响包的**正常流程状态** |
| 坐标对不上 | advisory 挂在 `org.apache.tomcat:tomcat-coyote` 等坐标下,而 Spring Boot 的依赖树里只有 `tomcat-embed-core` / `-el` / `-websocket` |

实际效果:**一个内嵌 Tomcat 9.0.118 的 Spring Boot 应用,Dependabot 面板全绿,
本工具会报出 4 条命中**,其中一条是默认配置即暴露。

**三、两套评级体系口径不同,而你只看得到其中一套。**

| | ASF / Tomcat 官方 | GitHub / NVD |
|---|---|---|
| 分级 | Low / Moderate / Important / Critical | CVSS 数值 |
| 依据 | **默认配置下的实际可利用性** | 向量机械计算,不看你开没开那个功能 |
| 在哪看 | `tomcat.apache.org/security-9.html` | Dependabot 直接推送给你 |

29 条里有 **17 条两套评级差 2 级以上**,最极端的 CVE-2026-41293:官方 **Low**,GitHub **critical CVSS 9.8**。

> **这不是谁报错了。** 两套体系测量的本来就是不同的东西。
> 但要判断「该不该现在就升」,你需要同时看到它们 —— 以及你有没有开那个功能。

---

## 用法

```bash
java -jar tomcat-check.jar <jar 或目录> ...

  --all     连「不适用」的条目也列出来
  --utf8    Windows 控制台中文乱码时加这个
```

```bash
# Spring Boot fat jar
java -jar tomcat-check.jar target/my-app.jar

# 独立安装的 Tomcat
java -jar tomcat-check.jar /opt/tomcat

# 整个依赖目录
java -jar tomcat-check.jar target/lib
```

需要 Java 17+。

## 输出里有什么

每条命中给出:两套评级、**触发条件**、官方描述原文、以及这条**会不会出现在你的 Dependabot 告警里**。
最后给一个能覆盖全部命中条目的升级目标。

## 🔴 请这样读它的输出

- **「命中」= 你的版本落在官方 Affects 区间内**,不等于「已被利用」,也不等于「必然可利用」。
  29 条里只有少数是默认配置即暴露,其余需要你显式开启某个功能(RewriteValve、DIGEST 认证、
  AJP、WebDAV、集群通信……)。**请逐条对照触发条件。**
- **「Dependabot 不会告警」不是说 GitHub 失职。** `unreviewed` 是正常流程状态。
- **判定表只覆盖 2026 年公布的 CVE。** 没有命中不等于你的版本没问题。
- 工具**不会**替你决定要不要升级 —— 它给的是做这个决定所需的三样东西:
  你装的是哪个版本、官方怎么评、以及触发条件是什么。

## 判定表怎么来的

`tools/gen_rules.py` 从**两个一手源**生成 `CveTable.java`,**一行都不手抄**:

- `https://tomcat.apache.org/security-{9,10,11}.html` —— 官方评级、标题、描述原文、影响区间
- GitHub Advisory API —— GitHub 评级、CVSS、`type`、受影响 Maven 坐标

生成过程带 **7 条断言**,任一不满足就中止、不写文件。其中三条值得单说:

- **ASSERT7(解析完整性)**:用第二个独立的正则口径再数一遍条目,两边集合必须完全相同。
  由来是一类很隐蔽的错配 —— 官方页面上有的标题里**嵌着另一个 CVE 的链接**:
  `<strong>Moderate: The fix for <a>CVE-2025-66614</a> was incomplete</strong> <a>CVE-2026-32990</a>`。
  在整块里找「第一个 CVE」会取到标题里嵌的那个旧编号,后果不是少一条,是**张冠李戴**:
  一条 CVE 挂上了另一条的标题和描述,而生成、测试、真实构件复验**全部照常通过**。
- **ASSERT3(配对方向)**:官方页面里 `Affects:` 行紧挨着**下一条** CVE 的标题,
  极容易配对到错误的那一条 —— 错了会得到一张「看起来完全正常但整体错位一格」的表。
  用 GitHub 的 `first_patched_version` 交叉校验,开发时**真的靠它抓到过一次错位**。
- **ASSERT6(排除依据)**:下载 9.0 / 10.1 / 11.0 三条线的真 jar,
  逐一确认被排除的条目(集群组件、FFM 连接器、示例应用)的代码**确实不在** `tomcat-embed-*` 里。
  排除依据必须是实测,不能是「我记得」。

重新生成:

```bash
python tools/gen_rules.py
```

## 构建

```bash
mvn clean package     # → target/tomcat-check.jar
```

34 个测试。运行时零依赖,JUnit 仅测试期。

## 许可

MIT
