package dev.mikko.tomcatcheck;

/**
 * 一条 CVE 在**一条版本线**上的判定规则。由 tools/gen_rules.py 生成。
 *
 * <p>字段刻意保留两套评级而不是折中成一个数 —— 折中就等于替用户做了他该自己做的判断:
 * ASF 官方按「默认配置下的实际可利用性」评级,GitHub/NVD 按 CVSS 向量机械计算,
 * 两者口径不同,不存在谁对谁错。
 */
public record Cve(
        String id,
        /** ASF 官方评级:Low / Moderate / Important / Critical */
        String officialSev,
        /** GitHub advisory 评级:low / medium / high / critical */
        String ghSev,
        /** CVSS v3 分数;-1 表示 GitHub 未给出 */
        double ghScore,
        /** GitHub advisory 类型:reviewed / unreviewed */
        String ghType,
        /** 这条会不会出现在 Spring Boot 项目的 Dependabot 告警里 */
        boolean dependabotAlerts,
        /** 版本线:9 / 10 / 11 */
        String line,
        /** 受影响下限(含),官方 Affects 起点 */
        String low,
        /** 受影响上限(含),官方 Affects 终点 */
        String high,
        /** 触发条件分类:DEFAULT / CONFIG / TLS / CLUSTER / EXAMPLES / AJP / WEBDAV / HTTP2 / WEBSOCKET */
        String condKind,
        /** 触发条件说明(对照官方描述原文,未作外推) */
        String condText,
        /** 官方标题 */
        String title,
        /** 官方描述原文(英文原句,非转述) */
        String desc,
        /** 对 Spring Boot 内嵌 Tomcat 是否适用(false = 受影响代码不在 tomcat-embed-* 里) */
        boolean embedApplicable,
        /** 不适用的原因;embedApplicable 为 true 时为空串 */
        String excludeReason) {

    /** 默认配置即受影响 —— 不需要额外开启任何功能。 */
    public boolean defaultExposed() {
        return "DEFAULT".equals(condKind);
    }

    /**
     * 这条为什么进不了 Dependabot 告警。仅在 {@link #dependabotAlerts()} 为 false 时有意义。
     *
     * <p>🔴 措辞注意:unreviewed 是 GitHub 的**正常流程状态**(NVD 自动导入、尚未人工确认
     * 受影响包),不是隐瞒也不是失职。这里只陈述「进不了告警」这个事实。
     */
    public String silentReason() {
        if (dependabotAlerts()) {
            return "";
        }
        if ("unreviewed".equals(ghType)) {
            return "GitHub advisory 仍是 unreviewed(未标注受影响包),Dependabot 只用 reviewed 的做告警";
        }
        return "advisory 挂在 Spring Boot 依赖树里没有的坐标上(如 tomcat-coyote / tomcat-tribes)";
    }
}
