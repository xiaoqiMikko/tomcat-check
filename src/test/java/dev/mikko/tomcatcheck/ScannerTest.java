package dev.mikko.tomcatcheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ScannerTest {

    /** 造一个带 MANIFEST 的假 jar。 */
    private static byte[] jar(String implVersion, String... extraEntries) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(bos)) {
            z.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
            StringBuilder mf = new StringBuilder("Manifest-Version: 1.0\r\n");
            if (implVersion != null) {
                mf.append("Implementation-Version: ").append(implVersion).append("\r\n");
            }
            mf.append("\r\n");
            z.write(mf.toString().getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
            for (String e : extraEntries) {
                z.putNextEntry(new ZipEntry(e));
                z.write(new byte[] {1, 2, 3});
                z.closeEntry();
            }
        }
        return bos.toByteArray();
    }

    /** 造一个内嵌了别的 jar 的 fat jar。 */
    private static byte[] fatJar(String innerName, byte[] inner) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(bos)) {
            z.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
            z.write("Manifest-Version: 1.0\r\n\r\n".getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
            z.putNextEntry(new ZipEntry(innerName));
            z.write(inner);
            z.closeEntry();
        }
        return bos.toByteArray();
    }

    @Test
    @DisplayName("普通 jar:版本优先取 MANIFEST")
    void plainJar(@TempDir Path dir) throws IOException {
        Path p = dir.resolve("tomcat-embed-core-9.0.117.jar");
        Files.write(p, jar("9.0.117"));
        Scanner sc = new Scanner();
        sc.scan(p);
        assertEquals(1, sc.artifacts().size());
        assertEquals("tomcat-embed-core", sc.artifacts().get(0).artifact());
        assertEquals("9.0.117", sc.artifacts().get(0).version().toString());
        assertEquals("MANIFEST", sc.artifacts().get(0).source());
        assertTrue(sc.artifacts().get(0).embedded());
    }

    @Test
    @DisplayName("🔴 jar 被改名也要认得出 —— 元数据优先于文件名(第 4 注拿到的意外收获)")
    void renamedJar(@TempDir Path dir) throws IOException {
        Path p = dir.resolve("tomcat-embed-core-0.0.0.jar");
        Files.write(p, jar("9.0.117"));
        Scanner sc = new Scanner();
        sc.scan(p);
        assertEquals("9.0.117", sc.artifacts().get(0).version().toString());
    }

    @Test
    @DisplayName("没有 MANIFEST 版本时退回文件名,并标明来源")
    void fallbackToFileName(@TempDir Path dir) throws IOException {
        Path p = dir.resolve("tomcat-embed-core-9.0.100.jar");
        Files.write(p, jar(null));
        Scanner sc = new Scanner();
        sc.scan(p);
        assertEquals("9.0.100", sc.artifacts().get(0).version().toString());
        assertEquals("文件名", sc.artifacts().get(0).source());
    }

    @Test
    @DisplayName("🔴 Spring Boot fat jar:版本藏在 BOOT-INF/lib 里,pom 里查不到")
    void springBootFatJar(@TempDir Path dir) throws IOException {
        byte[] inner = jar("9.0.117");
        Path p = dir.resolve("my-app.jar");
        Files.write(p, fatJar("BOOT-INF/lib/tomcat-embed-core-9.0.117.jar", inner));
        Scanner sc = new Scanner();
        sc.scan(p);
        assertEquals(1, sc.artifacts().size());
        assertEquals("tomcat-embed-core", sc.artifacts().get(0).artifact());
        assertEquals("9.0.117", sc.artifacts().get(0).version().toString());
        assertTrue(sc.artifacts().get(0).path().contains("!/BOOT-INF/lib/"));
    }

    @Test
    @DisplayName("🔴 条目路径用反斜杠的畸形归档也要扫得出(真实复验抓到的)")
    void backslashEntryNames(@TempDir Path dir) throws IOException {
        byte[] inner = jar("9.0.118");
        Path p = dir.resolve("my-app.jar");
        // PowerShell Compress-Archive 生成的就是这种:不合 ZIP 规范,但现实中存在
        Files.write(p, fatJar("BOOT-INF\\lib\\tomcat-embed-core-9.0.118.jar", inner));
        Scanner sc = new Scanner();
        sc.scan(p);
        assertEquals(1, sc.artifacts().size(),
                "只认 '/' 的话这里会是 0 —— 而「没扫到」看起来和「你很安全」一样");
        assertEquals("9.0.118", sc.artifacts().get(0).version().toString());
    }

    @Test
    @DisplayName("🔴 同一个物理构件只报一条(第 5 注:报两次会让人以为有两个问题)")
    void noDuplicate(@TempDir Path dir) throws IOException {
        Path p = dir.resolve("tomcat-embed-core-9.0.117.jar");
        Files.write(p, jar("9.0.117"));
        Scanner sc = new Scanner();
        sc.scan(p);
        sc.scan(p);
        assertEquals(1, sc.artifacts().size());
    }

    @Test
    @DisplayName("识别集群组件 —— 它在不在决定 CLUSTER 类 CVE 适不适用")
    void clusterArtifact(@TempDir Path dir) throws IOException {
        Files.write(dir.resolve("tomcat-tribes-9.0.117.jar"), jar("9.0.117"));
        Scanner sc = new Scanner();
        sc.scan(dir);
        assertEquals(1, sc.artifacts().size());
        assertTrue(sc.artifacts().get(0).cluster());
        assertFalse(sc.artifacts().get(0).embedded());
    }

    @Test
    @DisplayName("独立安装形态:lib/catalina.jar")
    void standalone(@TempDir Path dir) throws IOException {
        Path lib = Files.createDirectories(dir.resolve("lib"));
        Files.write(lib.resolve("catalina.jar"), jar("9.0.117"));
        Scanner sc = new Scanner();
        sc.scan(dir);
        assertEquals("catalina", sc.artifacts().get(0).artifact());
        assertFalse(sc.artifacts().get(0).embedded());
    }

    @Test
    @DisplayName("非 Tomcat 的 jar 一概不认")
    void ignoreOthers(@TempDir Path dir) throws IOException {
        Files.write(dir.resolve("jackson-databind-2.15.0.jar"), jar("2.15.0"));
        Files.write(dir.resolve("spring-core-6.1.0.jar"), jar("6.1.0"));
        Scanner sc = new Scanner();
        sc.scan(dir);
        assertTrue(sc.artifacts().isEmpty());
    }

    @Test
    @DisplayName("🔴 路径不存在要给出警告,不能静默返回空 —— 空结果会被读成「你很安全」")
    void missingPathWarns() throws IOException {
        Scanner sc = new Scanner();
        sc.scan(Path.of("Z:\\根本不存在的路径\\x.jar"));
        assertTrue(sc.artifacts().isEmpty());
        assertFalse(sc.warnings().isEmpty(), "路径不存在却没有任何警告");
    }

    @Test
    @DisplayName("识别出构件但取不到版本号时必须告警,不能当没看见")
    void unknownVersionWarns(@TempDir Path dir) throws IOException {
        Path p = dir.resolve("tomcat-embed-core.jar");
        Files.write(p, jar(null));
        Scanner sc = new Scanner();
        sc.scan(p);
        assertTrue(sc.artifacts().isEmpty());
        List<String> w = sc.warnings();
        assertTrue(w.stream().anyMatch(s -> s.contains("取不到版本号")), "缺少版本号告警:" + w);
    }
}
