package dev.mikko.tomcatcheck;

/**
 * 判断一条 CVE 对**这次扫描到的这套东西**适不适用。
 *
 * <p>🔴 单独成类是因为它出过一次真 bug,而且是真实构件复验才抓到的:
 * 原来写成「内嵌形态 && 判定表标了内嵌不适用 → 排除」,一票否决,
 * 结果目录里明明扫到了 {@code tomcat-tribes.jar},集群类条目仍被判为「内嵌版不含」。
 * 现在集群类条目的适用性**只看集群组件在不在**,与核心构件是不是内嵌形态无关。
 *
 * <p>判定的两侧都会出错,方向不同:
 * <ul>
 *   <li>漏排除 → 拿用户根本没装的代码去吓唬他(踩「不许说你一定中招」这条红线);
 *   <li>误排除 → 真有风险却不报,比不报警更糟。
 * </ul>
 */
public final class Applicability {

    /**
     * @param cve          判定表里的一条规则
     * @param embedded     核心构件是不是内嵌形态(tomcat-embed-*)
     * @param clusterHere  同版本线上有没有扫到集群组件(tomcat-tribes / tomcat-catalina-ha)
     */
    public static boolean applicable(Cve cve, boolean embedded, boolean clusterHere) {
        if ("CLUSTER".equals(cve.condKind())) {
            return clusterHere;
        }
        if (embedded && !cve.embedApplicable()) {
            return false;
        }
        return true;
    }

    /** 不适用的原因;{@link #applicable} 为 true 时返回空串。 */
    public static String reason(Cve cve, boolean embedded, boolean clusterHere) {
        if (applicable(cve, embedded, clusterHere)) {
            return "";
        }
        if ("CLUSTER".equals(cve.condKind())) {
            return "未扫到同版本线的集群组件(tomcat-tribes / tomcat-catalina-ha)";
        }
        return cve.excludeReason();
    }

    private Applicability() {
    }
}
