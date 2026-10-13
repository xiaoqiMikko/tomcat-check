package dev.mikko.tomcatcheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 🔴 这组测试是补写的 —— 原逻辑没有单测,bug 是真实构件复验才抓到的
 * (目录里扫到了 tomcat-tribes,集群类条目仍被判为「内嵌版不含」)。
 * 两个方向都要盯:漏排除会吓唬用户,误排除会漏报真风险。
 */
class ApplicabilityTest {

    private static Cve cve(String condKind, boolean embedApplicable) {
        return new Cve("CVE-2026-00000", "Low", "critical", 9.1, "unreviewed", false,
                "9", "9.0.0", "9.0.117", condKind, "条件", "标题", "描述",
                embedApplicable, embedApplicable ? "" : "内嵌版不含");
    }

    @Test
    @DisplayName("普通条目:内嵌形态下,判定表说不适用就排除")
    void embedExcluded() {
        Cve c = cve("TLS", false);
        assertFalse(Applicability.applicable(c, true, false));
        assertEquals("内嵌版不含", Applicability.reason(c, true, false));
    }

    @Test
    @DisplayName("普通条目:独立安装形态不受内嵌排除影响")
    void standaloneNotExcluded() {
        Cve c = cve("TLS", false);
        assertTrue(Applicability.applicable(c, false, false));
        assertEquals("", Applicability.reason(c, false, false));
    }

    @Test
    @DisplayName("普通条目:判定表说适用就适用")
    void normalApplicable() {
        assertTrue(Applicability.applicable(cve("DEFAULT", true), true, false));
    }

    @Test
    @DisplayName("🔴 集群条目:扫到集群组件就适用 —— 哪怕核心构件是内嵌形态(修过的 bug)")
    void clusterPresentMakesApplicable() {
        Cve c = cve("CLUSTER", false);
        assertTrue(Applicability.applicable(c, true, true),
                "装了 tomcat-tribes,集群代码是真的在,不能因为核心构件是内嵌就排除");
        assertEquals("", Applicability.reason(c, true, true));
    }

    @Test
    @DisplayName("集群条目:没扫到集群组件才排除,且理由要说清是「没扫到」")
    void clusterAbsent() {
        Cve c = cve("CLUSTER", false);
        assertFalse(Applicability.applicable(c, true, false));
        assertTrue(Applicability.reason(c, true, false).contains("未扫到"),
                "理由应说明是没扫到集群组件,而不是「内嵌版不含」");
        // 独立安装但没装集群组件,同样不适用
        assertFalse(Applicability.applicable(c, false, false));
    }

    @Test
    @DisplayName("集群条目的适用性与 embedApplicable 无关,只看集群组件在不在")
    void clusterIgnoresEmbedFlag() {
        assertTrue(Applicability.applicable(cve("CLUSTER", true), true, true));
        assertTrue(Applicability.applicable(cve("CLUSTER", false), true, true));
        assertFalse(Applicability.applicable(cve("CLUSTER", true), true, false));
    }

    @Test
    @DisplayName("WebSocket 条目:内嵌形态下没扫到 tomcat-embed-websocket 就不适用,理由要说清")
    void websocketAbsentOnEmbedded() {
        Cve c = cve("WEBSOCKET", true);
        assertFalse(Applicability.applicable(c, true, false, false));
        assertTrue(Applicability.reason(c, true, false, false).contains("tomcat-embed-websocket"));
    }

    @Test
    @DisplayName("WebSocket 条目:扫到了就适用;独立安装自带 WebSocket,不看这个参数")
    void websocketPresentOrStandalone() {
        Cve c = cve("WEBSOCKET", true);
        assertTrue(Applicability.applicable(c, true, false, true));
        assertTrue(Applicability.applicable(c, false, false, false));
        assertEquals("", Applicability.reason(c, false, false, false));
    }

    @Test
    @DisplayName("非 WebSocket 条目不受 websocketHere 影响")
    void websocketFlagOnlyTouchesWebsocketKind() {
        assertTrue(Applicability.applicable(cve("HTTP2", true), true, false, false));
        assertTrue(Applicability.applicable(cve("DEFAULT", true), true, false, false));
    }

    @Test
    @DisplayName("判定表里真实的集群条目走同一条路径")
    void realClusterEntries() {
        Cve c = CveTable.all().stream()
                .filter(x -> x.id().equals("CVE-2026-59084")).findFirst().orElseThrow();
        assertEquals("CLUSTER", c.condKind());
        assertFalse(Applicability.applicable(c, true, false));
        assertTrue(Applicability.applicable(c, true, true));
        // 触发条件里不该再带排除语,否则「已扫到 tribes」时自相矛盾
        assertFalse(c.condText().contains("不含"),
                "触发条件不该包含排除语:" + c.condText());
    }
}
