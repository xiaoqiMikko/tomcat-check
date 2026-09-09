package dev.mikko.tomcatcheck;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 扫描构建产物,找出实际装了哪个版本的 Tomcat。
 *
 * <p>🔴 <b>为什么必须扫产物而不是读 pom</b>:Spring Boot 项目的 pom 里通常只有
 * {@code spring-boot-starter-web},Tomcat 版本由 {@code spring-boot-starter-parent}
 * 的 {@code tomcat.version} 属性管着 —— <b>用户 pom 里根本没有这个版本号</b>。
 * 这也是本工具存在的首要理由。
 *
 * <p>能认三种形态:普通 jar、Spring Boot fat jar(内嵌 {@code BOOT-INF/lib/})、
 * 独立安装目录({@code lib/catalina.jar})。
 */
public final class Scanner {

    /** Tomcat 各构件的文件名前缀 → 构件标识。顺序有意义:先匹配更长的前缀。 */
    private static final Map<String, String> ARTIFACTS = new LinkedHashMap<>();

    static {
        ARTIFACTS.put("tomcat-embed-core", "tomcat-embed-core");
        ARTIFACTS.put("tomcat-embed-websocket", "tomcat-embed-websocket");
        ARTIFACTS.put("tomcat-embed-el", "tomcat-embed-el");
        ARTIFACTS.put("tomcat-catalina-ha", "tomcat-catalina-ha");
        ARTIFACTS.put("tomcat-catalina", "tomcat-catalina");
        ARTIFACTS.put("tomcat-tribes", "tomcat-tribes");
        ARTIFACTS.put("tomcat-coyote", "tomcat-coyote");
        ARTIFACTS.put("catalina", "catalina");          // 独立安装:lib/catalina.jar
    }

    private static final Pattern NAME_VER =
            Pattern.compile("^(.+?)-(\\d[\\w.\\-]*)\\.jar$", Pattern.CASE_INSENSITIVE);

    /** 一个被识别出来的 Tomcat 构件。 */
    public record Artifact(String path, String artifact, TomcatVersion version, String source) {
        /** 是不是内嵌形态(Spring Boot 用的那套坐标)。 */
        public boolean embedded() {
            return artifact.startsWith("tomcat-embed-");
        }

        /** 集群组件在不在 —— 决定 CLUSTER 类 CVE 对本次扫描是否适用。 */
        public boolean cluster() {
            return artifact.equals("tomcat-tribes") || artifact.equals("tomcat-catalina-ha");
        }
    }

    private final List<Artifact> found = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();

    /**
     * 有多少个文件是「读不动」的(不是 zip / 截断 / IO 失败)。
     *
     * <p>🔴 它存在的理由是退出码:留痕是给人看的,而 CI 与脚本看的是退出码 ——
     * 少了它,「我没能读它」在自动化里等于「通过」(2026-09-09 加)。
     * <p>🔴 用计数器而不是去匹配告警文案:文案改一个字,匹配式判据就安静失效了。
     */
    private int unreadable;

    /** 读不动的文件数 —— 大于 0 时退出码不许是 0。 */
    public int unreadableCount() {
        return unreadable;
    }


    public List<Artifact> artifacts() {
        return found;
    }

    public List<String> warnings() {
        return warnings;
    }

    public void scan(Path target) throws IOException {
        if (!Files.exists(target)) {
            warnings.add("路径不存在:" + target);
            return;
        }
        if (Files.isDirectory(target)) {
            Files.walkFileTree(target, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path f, BasicFileAttributes a) {
                    String n = f.getFileName().toString().toLowerCase();
                    if (n.endsWith(".jar") || n.endsWith(".war")) {
                        try {
                            scanArchive(f);
                        } catch (IOException e) {
                            unreadable++;
            warnings.add("读取失败 " + f + ":" + e.getMessage());
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path f, IOException e) {
                    warnings.add("无法访问 " + f + ":" + e.getMessage());
                    return FileVisitResult.CONTINUE;
                }
            });
        } else {
            scanArchive(target);
        }
    }

    /**
     * ☠️ <b>ZipInputStream 对非 zip 内容不抛异常,只是一个条目都不给</b>(2026-09-08 实测)。
     *
     * <p>后果:损坏 / 加密 / 根本不是 zip 的 .jar 会静默走完扫描,得出「没扫到 Tomcat」——
     * 用户会把它读成「我不受影响」。<b>「读不动」和「你是安全的」必须是两句话。</b>
     *
     * <p>🔴 这个坑第 10 注(log4j-check)实测记过并在那一注加了防线,但后续各注的扫描代码
     * 是从别处复制来的,<b>防线没跟着传下来</b>。空 zip({@code PK\05\06})合法,不算坏文件。
     */
    static boolean looksLikeZip(byte[] b) {
        if (b == null || b.length < 4 || b[0] != 'P' || b[1] != 'K') return false;
        int c = b[2], d = b[3];
        return (c == 3 && d == 4) || (c == 5 && d == 6) || (c == 7 && d == 8);
    }


    /**
     * 是不是一个<b>合法的空 zip</b> —— 整个文件就是一条 22 字节的 EOCD 记录。
     *
     * <p>🔴 判据不是「魔数像 zip」:一个 PK 03 04 开头但截断的文件魔数也是对的。
     * 空 zip 是真的空,不该报错;截断的必须报。
     */
    static boolean isEmptyZip(byte[] b) {
        return b != null && b.length == 22
                && b[0] == 'P' && b[1] == 'K' && b[2] == 5 && b[3] == 6;
    }

    private void scanArchive(Path file) throws IOException {
        byte[] bytes = Files.readAllBytes(file);
        // ① 归档自身是不是 Tomcat 构件(这一步只看文件名/内容特征,不解 zip,所以放在闸门之前)
        record0(file.toString(), file.getFileName().toString(), bytes);

        if (!looksLikeZip(bytes)) {
            unreadable++;
            warnings.add("这个文件读不动,不是有效的 zip/jar:" + file
                    + "(可能是截断、加密,或其实是个 HTML 错误页)"
                    + " —— 🔴 **这不等于「里面没有 Tomcat」**");
            return;
        }

        // ② 内嵌构件(Spring Boot fat jar / war)
        int entries = 0;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                entries++;
                String name = e.getName();
                if (e.isDirectory() || !name.toLowerCase().endsWith(".jar")) {
                    continue;
                }
                // 🔴 ZIP 规范要求用 '/',但现实里存在写成 '\' 的归档
                // (PowerShell Compress-Archive 就是一例)。只认 '/' 的话,
                // 这类 jar 会一条都扫不出来,而「没扫到」看起来和「你很安全」一模一样。
                String base = name.substring(
                        Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\')) + 1);
                if (identify(base) == null) {
                    continue;
                }
                byte[] inner = zis.readAllBytes();
                record0(file + "!/" + name, base, inner);
            }
        }

        // 🔴 第二层防线:魔数对、也没抛异常,但一个条目都没解出来。
        //    ☠️ 2026-09-08 实测:魔数校验只挡住一半 —— PK 03 04 开头但**内容截断**的文件
        //    魔数是对的、ZipInputStream 也不抛异常,只是零条目。少了这一层它照样静默通过。
        if (entries == 0 && !isEmptyZip(bytes)) {
            unreadable++;
            warnings.add("这个文件魔数像 zip,但一个条目都解不出来(多半是截断或下载不全):" + file
                    + " —— 🔴 **这不等于「里面没有 Tomcat」**");
            return;
        }
    }

    private void record0(String path, String fileName, byte[] bytes) {
        String artifact = identify(fileName);
        if (artifact == null) {
            return;
        }
        // 元数据优先于文件名 —— jar 被改名时文件名会骗人,MANIFEST 不会
        TomcatVersion v = fromManifest(bytes);
        String source = "MANIFEST";
        if (v == null) {
            v = fromFileName(fileName);
            source = "文件名";
        }
        if (v == null) {
            warnings.add("识别出 " + artifact + " 但取不到版本号:" + path
                    + "(🔴 这不等于「没有漏洞」,请手工确认版本)");
            return;
        }
        // 去重:同一物理路径 + 同一构件只报一条(第 5 注教训:同一 jar 报两次会让人以为有两个问题)
        for (Artifact a : found) {
            if (a.path().equals(path) && a.artifact().equals(artifact)) {
                return;
            }
        }
        found.add(new Artifact(path, artifact, v, source));
    }

    private static String identify(String fileName) {
        String n = fileName.toLowerCase();
        Matcher m = NAME_VER.matcher(n);
        String stem = m.matches() ? m.group(1) : n.replaceAll("\\.jar$", "");
        for (Map.Entry<String, String> en : ARTIFACTS.entrySet()) {
            if (stem.equals(en.getKey())) {
                return en.getValue();
            }
        }
        return null;
    }

    private static TomcatVersion fromFileName(String fileName) {
        Matcher m = NAME_VER.matcher(fileName.toLowerCase());
        return m.matches() ? TomcatVersion.parse(m.group(2)) : null;
    }

    /**
     * 只读 MANIFEST 主属性段。
     *
     * <p>⚠️ 第 4 注(bc-check)踩过:签名 jar 的 MANIFEST 可以上兆(每个类一个条目),
     * 整段读进来会撑破缓冲。{@link Manifest} 读主属性即可,不要遍历 entries。
     */
    private static TomcatVersion fromManifest(byte[] bytes) {
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (!"META-INF/MANIFEST.MF".equalsIgnoreCase(e.getName())) {
                    continue;
                }
                Manifest mf = new Manifest(new NonClosing(zis));
                String v = mf.getMainAttributes().getValue("Implementation-Version");
                if (v == null) {
                    v = mf.getMainAttributes().getValue("Bundle-Version");
                }
                return TomcatVersion.parse(v);
            }
        } catch (IOException | IllegalArgumentException ex) {
            return null;
        }
        return null;
    }

    /** Manifest 构造器会关掉流,而我们还要继续遍历同一个 ZipInputStream。 */
    private static final class NonClosing extends java.io.FilterInputStream {
        NonClosing(InputStream in) {
            super(in);
        }

        @Override
        public void close() {
            // 故意不关
        }
    }
}
