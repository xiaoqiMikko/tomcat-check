package dev.mikko.tomcatcheck;

import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * tomcat-check —— 查出你实际装的 Tomcat 版本,并对每条 CVE 同时给出两套评级和触发条件。
 *
 * <p>🔴 <b>本工具的措辞红线</b>(改输出前先读):
 * <ul>
 *   <li>不说「GitHub / Dependabot 误报」—— ASF 与 CVSS 两套体系口径不同,不是谁错;
 *   <li>不说「官方瞒报 / 淡化」—— ASF 分级方法是公开的;
 *   <li>不说「你一定中招」—— 类在 jar 里 ≠ 可被利用,绝大多数条目需要特定配置;
 *   <li>unreviewed 是 GitHub 的正常流程状态,只陈述「进不了 Dependabot 告警」这个事实。
 * </ul>
 */
public final class Main {

    /**
     * 有文件读不动 —— 「我没能读它」不许在自动化里等于「通过」。
     *
     * <p>2026-09-09 加。在此之前读不动只在输出里留一行提示,退出码照旧是 0,
     * 而 CI 与脚本看的是退出码。**留痕给人看,退出码给机器看,两者缺一不可。**
     * <p>发现了真问题时不降级成它:命中比读不动更要紧。
     */
    private static final int EXIT_UNREADABLE = 4;

    public static void main(String[] args) throws Exception {
        boolean utf8 = false;
        boolean showAll = false;
        List<String> targets = new ArrayList<>();
        for (String a : args) {
            switch (a) {
                // 🔴 别再试图自动探测控制台编码:Java 拿不到控制台真实代码页(第 5 注踩过整整两轮)
                case "--utf8" -> utf8 = true;
                case "--all" -> showAll = true;
                case "-h", "--help" -> {
                    usage(System.out);
                    return;
                }
                default -> targets.add(a);
            }
        }
        PrintStream out = utf8
                ? new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out),
                        true, StandardCharsets.UTF_8.name())
                : System.out;

        if (targets.isEmpty()) {
            usage(out);
            return;
        }

        Scanner sc = new Scanner();
        for (String t : targets) {
            sc.scan(Path.of(t));
        }
        report(out, sc, showAll);
        // 🔴 有文件读不动时,退出码不许停在 0 —— 见 EXIT_UNREADABLE 的注释。
        if (sc.unreadableCount() > 0) {
            System.exit(EXIT_UNREADABLE);
        }
    }

    private static void usage(PrintStream out) throws UnsupportedEncodingException {
        out.println("tomcat-check - Tomcat / Spring Boot embedded Tomcat CVE checker");
        // 🔴 这一行必须是纯 ASCII:控制台 chcp 与 Java 认定的编码不一致时中文会全糊,
        //    而用户恰恰是从这里才知道有 --utf8 这个开关。糊掉的帮助 = 没有帮助。
        out.println("  (Chinese text garbled? re-run with --utf8)");
        out.println();
        out.println("tomcat-check —— Tomcat / Spring Boot 内嵌 Tomcat 的 CVE 排查");
        out.println();
        out.println("  用法:java -jar tomcat-check.jar [选项] <jar 或目录> ...");
        out.println();
        out.println("  --all     连「不适用」的条目也列出来(默认只提示条数)");
        out.println("  --utf8    Windows 控制台中文乱码时加这个");
        out.println();
        out.println("  判定表来源:" + CveTable.GENERATED_FROM);
    }

    private static void report(PrintStream out, Scanner sc, boolean showAll) {
        List<Scanner.Artifact> arts = sc.artifacts();
        for (String w : sc.warnings()) {
            out.println("⚠️  " + w);
        }
        if (arts.isEmpty()) {
            out.println("没有扫到任何 Tomcat 构件。");
            out.println("🔴 这不等于「你没装 Tomcat」—— 也可能是路径给错了,或产物还没构建。");
            return;
        }

        // 集群组件在不在,按**版本线**分别看 —— 一个目录里混着两条线的产物时,
        // 不能拿 9.0 的 tribes 去证明 11.0 那套装了集群组件。
        Set<String> clusterLines = arts.stream().filter(Scanner.Artifact::cluster)
                .map(a -> a.version().line()).collect(Collectors.toSet());
        // WebSocket 同理按版本线看:内嵌形态下它是单独的 tomcat-embed-websocket。
        Set<String> websocketLines = arts.stream().filter(Scanner.Artifact::websocket)
                .map(a -> a.version().line()).collect(Collectors.toSet());

        for (Scanner.Artifact a : arts) {
            // 版本号由 embed-core / catalina 这类核心构件决定,其余构件同版本线不重复判定
            if (!a.artifact().equals("tomcat-embed-core") && !a.artifact().equals("catalina")
                    && !a.artifact().equals("tomcat-catalina")) {
                continue;
            }
            out.println();
            out.println("═".repeat(78));
            out.println("构件:" + a.artifact() + "  版本:" + a.version()
                    + "  (版本号取自 " + a.source() + ")");
            out.println("路径:" + a.path());
            if (a.embedded()) {
                out.println("形态:Spring Boot 内嵌 Tomcat"
                        + "  —— 这个版本号由 spring-boot-starter-parent 管,你的 pom 里查不到");
            }
            out.println("═".repeat(78));

            List<Cve> hit = new ArrayList<>();
            List<Cve> skipped = new ArrayList<>();
            for (Cve c : CveTable.all()) {
                if (!c.line().equals(a.version().line())) {
                    continue;
                }
                if (!a.version().inRange(c.low(), c.high())) {
                    continue;
                }
                boolean clusterHere = clusterLines.contains(a.version().line());
                boolean websocketHere = websocketLines.contains(a.version().line());
                if (Applicability.applicable(c, a.embedded(), clusterHere, websocketHere)) {
                    hit.add(c);
                } else {
                    skipped.add(c);
                }
            }

            if (hit.isEmpty() && skipped.isEmpty()) {
                out.println("✅ 判定表内(2026 年)没有命中这个版本的条目。");
                out.println("   注意:判定表只覆盖 2026 年公布的 CVE,更早的不在范围内。");
                continue;
            }

            print(out, "🔴 你的 Dependabot 大概率不会告警的条目", hit.stream()
                    .filter(c -> !c.dependabotAlerts()).toList(), true);
            print(out, "扫描器通常会报的条目", hit.stream()
                    .filter(Cve::dependabotAlerts).toList(), false);

            if (!skipped.isEmpty()) {
                out.println();
                out.println("── 版本区间命中但对你不适用:" + skipped.size() + " 条 "
                        + (showAll ? "──" : "(加 --all 查看)──"));
                if (showAll) {
                    boolean clusterHere = clusterLines.contains(a.version().line());
                    boolean websocketHere = websocketLines.contains(a.version().line());
                    for (Cve c : skipped) {
                        out.println("   " + c.id() + "  " + c.title());
                        out.println("      不适用:"
                                + Applicability.reason(c, a.embedded(), clusterHere,
                                        websocketHere));
                    }
                }
            }
            summarize(out, hit);
        }
    }

    private static void print(PrintStream out, String header, List<Cve> list, boolean silent) {
        if (list.isEmpty()) {
            return;
        }
        out.println();
        out.println("── " + header + ":" + list.size() + " 条 ──");
        List<Cve> sorted = new ArrayList<>(list);
        sorted.sort(Comparator.comparingDouble((Cve c) -> -c.ghScore()));
        for (Cve c : sorted) {
            out.println();
            out.println("  " + c.id() + "  " + c.title());
            out.printf("     评级:ASF 官方 %-9s │ GitHub %s%s%n",
                    c.officialSev(), "unknown".equals(c.ghSev()) ? "尚未评级" : c.ghSev(),
                    c.ghScore() >= 0 ? String.format(" (CVSS %.1f)", c.ghScore()) : "");
            if (differ(c)) {
                out.println("     ↑ 两套体系口径不同(官方按默认配置下的可利用性,CVSS 按向量机械计算),"
                        + "不是谁报错了");
            }
            if (silent) {
                out.println("     进不了告警:" + c.silentReason());
            }
            out.println("     触发条件:" + c.condText());
            if (c.defaultExposed()) {
                out.println("     ⚠️ 这条是默认配置即暴露 —— 优先处理");
            }
            if (!c.desc().isEmpty()) {
                out.println("     官方原文:" + c.desc());
            }
        }
    }

    private static boolean differ(Cve c) {
        int off = rank(c.officialSev());
        int gh = rank(c.ghSev());
        return off >= 0 && gh >= 0 && Math.abs(off - gh) >= 2;
    }

    private static int rank(String s) {
        return switch (s.toLowerCase()) {
            case "low" -> 0;
            case "moderate", "medium" -> 1;
            case "important", "high" -> 2;
            case "critical" -> 3;
            default -> -1;
        };
    }

    /** 给出升级目标 = 所有命中条目上限里最高的那个再进一版。 */
    private static void summarize(PrintStream out, List<Cve> hit) {
        if (hit.isEmpty()) {
            return;
        }
        TomcatVersion max = null;
        for (Cve c : hit) {
            TomcatVersion v = TomcatVersion.parse(c.high());
            if (v != null && (max == null || v.compareTo(max) > 0)) {
                max = v;
            }
        }
        Set<String> defaults = new LinkedHashSet<>();
        for (Cve c : hit) {
            if (c.defaultExposed()) {
                defaults.add(c.id());
            }
        }
        out.println();
        out.println("── 小结 ──");
        out.println("  命中 " + hit.size() + " 条,其中 "
                + hit.stream().filter(c -> !c.dependabotAlerts()).count()
                + " 条你的 Dependabot 大概率不会告警");
        out.println("  默认配置即暴露:" + (defaults.isEmpty() ? "无" : String.join(", ", defaults)));
        if (max != null) {
            out.println("  升到高于 " + max + " 的版本可覆盖以上全部条目");
        }
        out.println();
        out.println("  🔴 「命中」= 版本落在官方 Affects 区间内,不等于「已被利用」或「必然可利用」。");
        out.println("     多数条目需要特定配置才成立,请逐条对照上面的触发条件。");
    }

    private Main() {
    }
}
