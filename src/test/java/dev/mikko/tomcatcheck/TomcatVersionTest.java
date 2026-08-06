package dev.mikko.tomcatcheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class TomcatVersionTest {

    private static int cmp(String a, String b) {
        return Integer.signum(TomcatVersion.parse(a).compareTo(TomcatVersion.parse(b)));
    }

    @Test
    @DisplayName("普通版本号按数值比较,不按字典序")
    void ordinary() {
        assertEquals(-1, cmp("9.0.117", "9.0.118"));
        assertEquals(1, cmp("9.0.118", "9.0.117"));
        assertEquals(0, cmp("9.0.117", "9.0.117"));
        // 字典序会把 9.0.9 排在 9.0.117 后面 —— 这正是要防的
        assertEquals(-1, cmp("9.0.9", "9.0.117"));
        assertEquals(-1, cmp("9.0.99", "9.0.100"));
    }

    @Test
    @DisplayName("🔴 里程碑版必须排在同号正式版前面(官方 Affects 大量以 9.0.0.M1 起头)")
    void milestone() {
        assertEquals(-1, cmp("9.0.0.M1", "9.0.0"));
        assertEquals(-1, cmp("11.0.0-M14", "11.0.0"));
        assertEquals(-1, cmp("9.0.0.M1", "9.0.0.M23"));
        assertEquals(-1, cmp("11.0.0-M1", "11.0.0-M14"));
        assertEquals(-1, cmp("9.0.0.M23", "9.0.1"));
        assertEquals(1, cmp("10.1.0", "10.1.0-M7"));
    }

    @Test
    @DisplayName("段数不同时缺位补 0")
    void padding() {
        assertEquals(0, cmp("9.0", "9.0.0"));
        assertEquals(-1, cmp("9.0", "9.0.1"));
    }

    @Test
    @DisplayName("版本线取主版本号")
    void line() {
        assertEquals("9", TomcatVersion.parse("9.0.117").line());
        assertEquals("10", TomcatVersion.parse("10.1.55").line());
        assertEquals("11", TomcatVersion.parse("11.0.0-M14").line());
    }

    @Test
    @DisplayName("闭区间判定,两端都含")
    void range() {
        TomcatVersion v = TomcatVersion.parse("9.0.117");
        assertTrue(v.inRange("9.0.0.M1", "9.0.117"));
        assertTrue(v.inRange("9.0.117", "9.0.117"));
        assertFalse(v.inRange("9.0.0.M1", "9.0.116"));
        assertFalse(v.inRange("9.0.118", "9.0.120"));
        // 端点留空 = 该侧不设限
        assertTrue(v.inRange("", "9.0.117"));
        assertTrue(v.inRange("9.0.2", ""));
    }

    @Test
    @DisplayName("🔴 CVE-2026-24734 的真实区间:9.0.83~9.0.114 受影响,9.0.115 起已修")
    void realCase() {
        assertFalse(TomcatVersion.parse("9.0.82").inRange("9.0.83", "9.0.114"));
        assertTrue(TomcatVersion.parse("9.0.83").inRange("9.0.83", "9.0.114"));
        assertTrue(TomcatVersion.parse("9.0.114").inRange("9.0.83", "9.0.114"));
        assertFalse(TomcatVersion.parse("9.0.115").inRange("9.0.83", "9.0.114"));
    }

    @Test
    @DisplayName("解析不了就返回 null —— 不许悄悄当成 0")
    void unparsable() {
        assertNull(TomcatVersion.parse(null));
        assertNull(TomcatVersion.parse(""));
        assertNull(TomcatVersion.parse("不是版本号"));
        assertNull(TomcatVersion.parse("9.0.x"));
    }
}
