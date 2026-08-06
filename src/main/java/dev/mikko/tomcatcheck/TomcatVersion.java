package dev.mikko.tomcatcheck;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tomcat 版本号解析与比较。
 *
 * <p>🔴 里程碑版必须排在同号正式版**前面**,否则区间判定会整体偏一格:
 * {@code 9.0.0.M1 < 9.0.0}、{@code 11.0.0-M14 < 11.0.0}。
 * 官方 Affects 大量以 {@code 9.0.0.M1} / {@code 11.0.0-M1} 作为起点,
 * 把它们当成普通版本比较,会让「>= 下限」这一侧全部判错。
 *
 * <p>两种写法都要认:9.0.x 线用点号({@code 9.0.0.M1}),11.0.x 线用连字符({@code 11.0.0-M14})。
 */
public final class TomcatVersion implements Comparable<TomcatVersion> {

    /**
     * 限定符只认 Tomcat 真实用过的那几个。
     *
     * <p>🔴 别放宽成 {@code [A-Za-z]+}:那样 {@code 9.0.x} 这种通配写法也会被当成
     * 「9.0 的某个预发布版」解析成功,于是区间判定拿它去比较,结果既不报错也不正确。
     * 解析不了就该返回 null,让调用方显式处理。
     */
    private static final Pattern P =
            Pattern.compile("^(\\d+(?:\\.\\d+)*)(?:[.\\-](M|RC|ALPHA|BETA)(\\d*))?$",
                    Pattern.CASE_INSENSITIVE);

    private final List<Integer> nums;
    /** 里程碑序号;-1 表示正式版(排在里程碑版之后) */
    private final int milestone;
    private final String raw;

    private TomcatVersion(List<Integer> nums, int milestone, String raw) {
        this.nums = nums;
        this.milestone = milestone;
        this.raw = raw;
    }

    /** 解析失败返回 null —— 调用方必须处理,不要用「解析不出就当 0」蒙混过去。 */
    public static TomcatVersion parse(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        if (t.isEmpty()) {
            return null;
        }
        Matcher m = P.matcher(t);
        if (!m.matches()) {
            return null;
        }
        List<Integer> ns = new ArrayList<>();
        for (String part : m.group(1).split("\\.")) {
            try {
                ns.add(Integer.parseInt(part));
            } catch (NumberFormatException e) {
                return null;
            }
        }
        int ms = -1;
        if (m.group(2) != null) {
            // M1 / RC2 / alpha 等一律视为预发布,序号缺省算 0
            String digits = m.group(3);
            ms = (digits == null || digits.isEmpty()) ? 0 : Integer.parseInt(digits);
        }
        return new TomcatVersion(ns, ms, t);
    }

    /** 主版本线:9.0.117 → "9";11.0.0-M14 → "11"。 */
    public String line() {
        return String.valueOf(nums.get(0));
    }

    @Override
    public int compareTo(TomcatVersion o) {
        int n = Math.max(nums.size(), o.nums.size());
        for (int i = 0; i < n; i++) {
            int a = i < nums.size() ? nums.get(i) : 0;
            int b = i < o.nums.size() ? o.nums.get(i) : 0;
            if (a != b) {
                return Integer.compare(a, b);
            }
        }
        // 数字段相同:里程碑版在前,正式版在后
        if (milestone < 0 && o.milestone < 0) {
            return 0;
        }
        if (milestone < 0) {
            return 1;
        }
        if (o.milestone < 0) {
            return -1;
        }
        return Integer.compare(milestone, o.milestone);
    }

    /** 闭区间 [low, high];端点为空表示该侧不设限。 */
    public boolean inRange(String low, String high) {
        if (low != null && !low.isEmpty()) {
            TomcatVersion lo = parse(low);
            if (lo == null || compareTo(lo) < 0) {
                return false;
            }
        }
        if (high != null && !high.isEmpty()) {
            TomcatVersion hi = parse(high);
            if (hi == null || compareTo(hi) > 0) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof TomcatVersion v && compareTo(v) == 0;
    }

    @Override
    public int hashCode() {
        return raw.hashCode();
    }

    @Override
    public String toString() {
        return raw;
    }
}
