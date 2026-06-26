package com.open.jgm.jsse.simple;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

public final class GmsslTestMaterialPaths {

    public static final String DEFAULT_PWD = "12345678";

    private GmsslTestMaterialPaths() {
    }

    public static String clientCa() {
        return resolve("client/sm2.ca.pem");
    }

    public static String clientPfx() {
        return resolve("client/sm2.client.both.pfx");
    }

    public static String serverCa() {
        return resolve("server/sm2.ca.pem");
    }

    public static String serverPfx() {
        return resolve("server/sm2.server.both.pfx");
    }

    static String resolve(String classpathRelative) {
        if (classpathRelative == null || classpathRelative.isEmpty()) {
            throw new IllegalArgumentException("classpath path is empty");
        }
        String normalized = classpathRelative.replace('\\', '/');
        Path relative = Paths.get(normalized);
        if (relative.isAbsolute() && Files.isRegularFile(relative)) {
            return relative.toAbsolutePath().normalize().toString();
        }
        if (Files.isRegularFile(relative)) {
            return relative.toAbsolutePath().normalize().toString();
        }

        ClassLoader loader = GmsslTestMaterialPaths.class.getClassLoader();
        URL url = loader.getResource(normalized);
        if (url == null) {
            Path underSrc = Paths.get("src", "test", "resources").resolve(normalized);
            if (Files.isRegularFile(underSrc)) {
                return underSrc.toAbsolutePath().normalize().toString();
            }
            Path underTarget = Paths.get("target", "test-classes").resolve(normalized);
            if (Files.isRegularFile(underTarget)) {
                return underTarget.toAbsolutePath().normalize().toString();
            }
            throw new IllegalStateException(
                    "Test material not found: " + normalized + " (mvn test-compile or set absolute path via -D)");
        }
        try {
            if ("file".equalsIgnoreCase(url.getProtocol())) {
                return Paths.get(url.toURI()).toAbsolutePath().normalize().toString();
            }
            return copyToTemp(url, normalized);
        } catch (URISyntaxException e) {
            throw new IllegalStateException("Invalid resource URL: " + url, e);
        }
    }

    private static String copyToTemp(URL url, String normalized) {
        String suffix = normalized.replace('/', '_');
        try {
            Path temp = Files.createTempFile("gmssl-test-", "-" + suffix);
            temp.toFile().deleteOnExit();
            try (java.io.InputStream in = url.openStream()) {
                Files.copy(in, temp, StandardCopyOption.REPLACE_EXISTING);
            }
            return temp.toAbsolutePath().normalize().toString();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read test resource " + normalized, e);
        }
    }
}