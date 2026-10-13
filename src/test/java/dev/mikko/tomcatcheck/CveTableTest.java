package dev.mikko.tomcatcheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 判定表的守门测试。
 *
 * <p>🔴 存在理由:判定表是 tools/gen_rules.py 生成的,如果哪天解析失败生成了一张空表,
 * 「扫描没报问题」看起来和「你很安全」一模一样。这里的断言让空表直接把构建打红。
 */
class CveTableTest {

    private static List<Cve> byId(String id) {
        return CveTable.all().stream().filter(c -> c.id().equals(id)).toList();
    }

    @Test
    @DisplayName("表不能是空的,且要覆盖三条版本线")
    void notEmpty() {
        assertTrue(CveTable.all().size() >= 150,
                "判定表只有 " + CveTable.all().size() + " 条 —— 生成脚本可能解析失败了");
        Set<String> lines = CveTable.all().stream().map(Cve::line).collect(Collectors.toSet());
        assertTrue(lines.containsAll(Set.of("9", "10", "11")), "缺版本线:" + lines);
    }

    @Test
    @DisplayName("每条规则的字段都要有值 —— 触发条件留空会被读成「无条件即中招」")
    void fieldsFilled() {
        for (Cve c : CveTable.all()) {
            assertFalse(c.id().isEmpty(), "CVE 编号为空");
            assertFalse(c.officialSev().isEmpty(), c.id() + " 缺官方评级");
            assertFalse(c.high().isEmpty(), c.id() + " 缺受影响上限");
            assertFalse(c.condText().isEmpty(), c.id() + " 缺触发条件说明");
            assertFalse(c.title().isEmpty(), c.id() + " 缺标题");
        }
    }

    @Test
    @DisplayName("🔴 核心主张一:确实存在 Dependabot 不会告警的条目")
    void silentOnesExist() {
        long silent = CveTable.all().stream()
                .filter(c -> !c.dependabotAlerts()).map(Cve::id).distinct().count();
        assertTrue(silent >= 5,
                "只有 " + silent + " 条不进告警 —— 核心主张需重新核实,别继续对外宣传");
    }

    @Test
    @DisplayName("🔴 核心主张二:确实存在两套评级差 2 级以上的条目")
    void ratingGapExists() {
        long gap = CveTable.all().stream()
                .filter(c -> Math.abs(rank(c.officialSev()) - rank(c.ghSev())) >= 2)
                .map(Cve::id).distinct().count();
        assertTrue(gap >= 10, "只有 " + gap + " 条评级差 >= 2 级");
    }

    @Test
    @DisplayName("已核实过的具体条目不能漂移(一手源验证过的锚点)")
    void anchors() {
        // 官方 Low,GitHub critical 9.8 —— 差距最大的那条
        List<Cve> a = byId("CVE-2026-41293");
        assertFalse(a.isEmpty(), "CVE-2026-41293 不在表里");
        assertEquals("Low", a.get(0).officialSev());
        assertEquals("critical", a.get(0).ghSev());

        // 官方 Moderate,GitHub critical 9.8,DIGEST 认证才触发
        List<Cve> b = byId("CVE-2026-43512");
        assertFalse(b.isEmpty());
        assertEquals("Moderate", b.get(0).officialSev());
        assertTrue(b.get(0).condText().contains("DIGEST"));

        // unreviewed,进不了 Dependabot
        List<Cve> c = byId("CVE-2026-59083");
        assertFalse(c.isEmpty());
        assertFalse(c.get(0).dependabotAlerts());
        assertEquals("unreviewed", c.get(0).ghType());
    }

    @Test
    @DisplayName("2026-09 批:修 41293 引入的回归 86350 只落在修复版自己那几个版本上")
    void regressionOf41293() {
        List<Cve> l = byId("CVE-2026-86350");
        assertEquals(3, l.size(), "86350 应三条线各一条");
        assertEquals("Important", l.get(0).officialSev());
        assertEquals("HTTP2", l.get(0).condKind());
        for (Cve c : l) {
            TomcatVersion low = TomcatVersion.parse(c.low());
            // 回归的下限 = 41293 在同一条线上的上限再进一版(即 41293 的修复版)
            Cve fixed = byId("CVE-2026-41293").stream()
                    .filter(x -> x.line().equals(c.line())).findFirst().orElseThrow();
            assertTrue(low.compareTo(TomcatVersion.parse(fixed.high())) > 0,
                    c.line() + " 线:86350 下限 " + c.low() + " 应高于 41293 上限 " + fixed.high());
            assertFalse(TomcatVersion.parse(fixed.high()).inRange(c.low(), c.high()),
                    "41293 的受影响版本不该同时落在 86350 区间里");
        }
        assertEquals("9.0.118", l.stream().filter(c -> c.line().equals("9")).findFirst()
                .orElseThrow().low());
        assertEquals("10.1.59", l.stream().filter(c -> c.line().equals("10")).findFirst()
                .orElseThrow().high());
    }

    @Test
    @DisplayName("2026-08 / 09 两批:非默认前提的条目不许落到「默认配置即受影响」")
    void newBatchesHaveConditions() {
        for (String id : List.of("CVE-2026-65182", "CVE-2026-65183", "CVE-2026-65637",
                "CVE-2026-65905", "CVE-2026-65927", "CVE-2026-66422", "CVE-2026-68525",
                "CVE-2026-68569", "CVE-2026-68763", "CVE-2026-73180", "CVE-2026-73581",
                "CVE-2026-75973", "CVE-2026-76183", "CVE-2026-77756", "CVE-2026-77762",
                "CVE-2026-77791", "CVE-2026-78383", "CVE-2026-78437", "CVE-2026-79677",
                "CVE-2026-86248", "CVE-2026-86350", "CVE-2026-87022")) {
            List<Cve> l = byId(id);
            assertEquals(3, l.size(), id + " 应三条线各一条");
            assertFalse(l.get(0).defaultExposed(), id + " 不该标成默认即受影响");
        }
        // FFM 专属的那条必须对内嵌版排除(与 34500 同理)
        assertFalse(byId("CVE-2026-86248").get(0).embedApplicable());
    }

    @Test
    @DisplayName("🔴 集群/示例类条目必须标为「内嵌版不适用」——否则会吓唬 Spring Boot 用户")
    void embedExclusions() {
        for (String id : List.of("CVE-2026-59084", "CVE-2026-55955", "CVE-2026-34487",
                "CVE-2026-29146", "CVE-2026-34486", "CVE-2026-50229", "CVE-2026-66299")) {
            List<Cve> l = byId(id);
            assertFalse(l.isEmpty(), id + " 不在表里");
            assertFalse(l.get(0).embedApplicable(), id + " 应标为内嵌版不适用");
            assertFalse(l.get(0).excludeReason().isEmpty(), id + " 缺不适用原因");
        }
    }

    @Test
    @DisplayName("🔴 条目不能张冠李戴:标题/描述里不该出现本条自己的编号")
    void noSelfReference() {
        // 由来:官方页面上有一类标题长这样 ——
        //   "The fix for CVE-2026-29146 allowed the bypass of the EncryptInterceptor"  CVE-2026-34486
        // 生成脚本一度在整块里找「第一个 CVE」,于是把这条的标题挂到了 CVE-2026-29146 上。
        // 结果是 29146 的标题里出现它自己的编号 —— 这正是错配的指纹。
        for (Cve c : CveTable.all()) {
            assertFalse(c.title().contains(c.id()),
                    c.id() + " 的标题里出现了它自己的编号,极可能挂错了条目:" + c.title());
            assertFalse(c.desc().contains(c.id()),
                    c.id() + " 的描述里出现了它自己的编号,极可能挂错了条目");
        }
    }

    @Test
    @DisplayName("🔴 集群类条目必须同时进排除清单 —— 两处标注不一致就是有一处忘了改")
    void clusterEntriesAreExcluded() {
        for (Cve c : CveTable.all()) {
            if ("CLUSTER".equals(c.condKind())) {
                assertFalse(c.embedApplicable(),
                        c.id() + " 标了 CLUSTER 却没进排除清单(EXCLUDE_FROM_EMBED)");
            }
        }
    }

    @Test
    @DisplayName("区间端点都要能被解析 —— 解析不了的端点会让整条规则静默失效")
    void endpointsParsable() {
        for (Cve c : CveTable.all()) {
            assertTrue(TomcatVersion.parse(c.high()) != null,
                    c.id() + " 的上限解析不了:" + c.high());
            if (!c.low().isEmpty()) {
                assertTrue(TomcatVersion.parse(c.low()) != null,
                        c.id() + " 的下限解析不了:" + c.low());
            }
        }
    }

    private static int rank(String s) {
        return switch (s.toLowerCase()) {
            case "low" -> 0;
            case "moderate", "medium" -> 1;
            case "important", "high" -> 2;
            case "critical" -> 3;
            default -> 0;
        };
    }
}
