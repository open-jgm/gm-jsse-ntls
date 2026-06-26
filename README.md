English | [简体中文](./README-CN.md)

# gm-jsse-ntls

Open GM JSSE (NTLS / GMSSL) for Java: `SSLContext`, blocking `SSLSocket` / `SSLServerSocket`, and `SSLEngine` (e.g. Netty).

## Requirements

- **JDK 8+** to run.
- **BouncyCastle** on the classpath (`bcpkix-jdk15to18` is **provided**; your app must supply BC, typically 1.76+).
- Compile with JDK 8, or JDK 17+ with Maven `--release 8`.

## Installation

```xml
<dependency>
    <groupId>com.open.jgm</groupId>
    <artifactId>gm-jsse-ntls</artifactId>
    <version>1.0.0</version>
</dependency>
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcpkix-jdk15to18</artifactId>
    <version>1.76</version>
</dependency>
```

Register providers once at startup:

```java
import com.open.jgm.jsse.GmSslProviders;

GmSslProviders.ensureInstalled();
```

## Algorithm names

| API | Algorithm string |
|-----|------------------|
| `TrustManagerFactory` + `GMProvider` | **`X509`** |
| `CertificateFactory` + BouncyCastle | **`X.509`** |

Cipher suite (enable explicitly when needed): `CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3.getName()` → `ECC-SM2-WITH-SM4-CBC-SM3`. Protocol: **NTLSv1.1**.

**Session resumption:** not supported.

---

## 1. GMSSL / NTLS over HTTPS (`https://xxx/`)

Replace `https://xxx/` with your GMSSL-enabled endpoint. The server must speak **NTLS**, not standard TLS 1.2.

### 1.1 One-way authentication (client verifies server)

Client trusts the server CA; no client certificate.

#### With `JsseSimpleUtil`

```java
import com.open.jgm.jsse.CipherSuite;
import com.open.jgm.jsse.GmSslProviders;
import com.open.jgm.jsse.JsseSimpleUtil;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.net.URL;

public class GmHttpsOneWayUtil {
    public static void main(String[] args) throws Exception {
        GmSslProviders.ensureInstalled();
        SSLContext ctx = JsseSimpleUtil.createAuthClientSSLContext("/path/to/ca.pem", false);

        URL url = new URL("https://xxx/");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(ctx.getSocketFactory());
        conn.setHostnameVerifier((h, s) -> true); // replace with real host verification in production
        conn.connect();
        System.out.println("cipher=" + conn.getCipherSuite());
        conn.getInputStream().close();
    }
}
```

#### Without `JsseSimpleUtil` (manual trust store)

```java
import com.open.jgm.jsse.CipherSuite;
import com.open.jgm.jsse.GMProvider;
import com.open.jgm.jsse.GmSslProviders;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class GmHttpsOneWayManual {
    public static void main(String[] args) throws Exception {
        GmSslProviders.ensureInstalled();
        GMProvider gm = GmSslProviders.gmProvider();
        BouncyCastleProvider bc = new BouncyCastleProvider();

        KeyStore trust = KeyStore.getInstance("PKCS12", bc);
        trust.load(null, null);
        CertificateFactory cf = CertificateFactory.getInstance("X.509", bc);
        try (FileInputStream caIn = new FileInputStream("/path/to/ca.pem")) {
            trust.setCertificateEntry("ca", (X509Certificate) cf.generateCertificate(caIn));
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509", gm);
        tmf.init(trust);

        SSLContext ctx = SSLContext.getInstance("TLS", gm);
        ctx.init(null, tmf.getTrustManagers(), null);

        HttpsURLConnection conn = (HttpsURLConnection) new URL("https://xxx/").openConnection();
        conn.setSSLSocketFactory(ctx.getSocketFactory());
        conn.connect();
        System.out.println(conn.getCipherSuite());
    }
}
```

### 1.2 Mutual authentication (two-way, SM2 dual-cert)

Client presents sign + encryption keys (typically one PKCS#12 with `Sig` / `Enc` entries or separate files).

#### With `JsseSimpleUtil`

```java
import com.open.jgm.jsse.CipherSuite;
import com.open.jgm.jsse.GmSslProviders;
import com.open.jgm.jsse.JsseSimpleUtil;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.net.URL;

public class GmHttpsMutualUtil {
    public static void main(String[] args) throws Exception {
        GmSslProviders.ensureInstalled();
        // Single dual-cert PFX (aliases Sig/Enc inside) + CA PEM
        SSLContext ctx = JsseSimpleUtil.createSm2SSLContext(
                "/path/to/client.both.pfx", "password", "/path/to/ca.pem");

        HttpsURLConnection conn = (HttpsURLConnection) new URL("https://xxx/").openConnection();
        conn.setSSLSocketFactory(ctx.getSocketFactory());
        conn.connect();
        System.out.println(conn.getCipherSuite());
    }
}
```

Separate sign/enc PFX files:

```java
SSLContext ctx = JsseSimpleUtil.createSm2SSLContext(
        "/path/to/sign.pfx", "signPwd",
        "/path/to/enc.pfx", "encPwd",
        "/path/to/ca.pem");
```

#### Without `JsseSimpleUtil` (manual KeyStore)

SM2 client key entries must use aliases **`sign`** and **`enc`** (see `JsseSimpleUtil` / `GMX509KeyManager`).

```java
import com.open.jgm.jsse.GMProvider;
import com.open.jgm.jsse.GmSslProviders;
import com.open.jgm.jsse.JsseSimpleUtil; // only for loading cert/key from PFX if you prefer
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class GmHttpsMutualManual {
    public static void main(String[] args) throws Exception {
        GmSslProviders.ensureInstalled();
        GMProvider gm = GmSslProviders.gmProvider();
        BouncyCastleProvider bc = new BouncyCastleProvider();

        String pfx = "/path/to/client.both.pfx";
        String pwd = "password";
        String ca = "/path/to/ca.pem";

        KeyStore ks = KeyStore.getInstance("PKCS12", bc);
        ks.load(null, null);
        ks.setKeyEntry("enc",
                JsseSimpleUtil.getP12PrivateKey("Enc", pfx, pwd), new char[0],
                new X509Certificate[]{JsseSimpleUtil.getP12Certificate("Enc", pfx, pwd)});
        ks.setKeyEntry("sign",
                JsseSimpleUtil.getP12PrivateKey("Sig", pfx, pwd), new char[0],
                new X509Certificate[]{JsseSimpleUtil.getP12Certificate("Sig", pfx, pwd)});
        ks.setCertificateEntry("ca", JsseSimpleUtil.findCaCertificate(ca));

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, pwd.toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509", gm);
        tmf.init(ks);

        SSLContext ctx = SSLContext.getInstance("TLS", gm);
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        HttpsURLConnection conn = (HttpsURLConnection) new URL("https://xxx/").openConnection();
        conn.setSSLSocketFactory(ctx.getSocketFactory());
        conn.connect();
    }
}
```

To avoid any `JsseSimpleUtil` call, load the PKCS#12 with `KeyStore.load(FileInputStream, password)` and map aliases from your PFX to `sign` / `enc` entries yourself.

---

## 2. Blocking NTLS server and client (`SSLSocket` / `SSLServerSocket`)

### 2.1 Server + client with `JsseSimpleUtil`

**Server** (loopback example):

```java
import com.open.jgm.jsse.CipherSuite;
import com.open.jgm.jsse.GmSslProviders;
import com.open.jgm.jsse.JsseSimpleUtil;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;

public class GmBlockingServerUtil {
    public static void main(String[] args) throws Exception {
        GmSslProviders.ensureInstalled();
        SSLContext ctx = JsseSimpleUtil.createSm2SSLContext(
                "/path/to/server.both.pfx", "password", "/path/to/ca.pem");
        try (SSLServerSocket listen = (SSLServerSocket) ctx.getServerSocketFactory()
                .createServerSocket(8443, 50, InetAddress.getByName("0.0.0.0"))) {
            listen.setNeedClientAuth(true); // mutual TLS
            listen.setEnabledCipherSuites(
                    new String[]{CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3.getName()});
            try (SSLSocket socket = (SSLSocket) listen.accept()) {
                socket.startHandshake();
                InputStream in = socket.getInputStream();
                OutputStream out = socket.getOutputStream();
                byte[] buf = new byte[4096];
                int n = in.read(buf);
                if (n > 0) {
                    out.write(buf, 0, n);
                    out.flush();
                }
            }
        }
    }
}
```

**Client**:

```java
import com.open.jgm.jsse.CipherSuite;
import com.open.jgm.jsse.GmSslProviders;
import com.open.jgm.jsse.JsseSimpleUtil;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

public class GmBlockingClientUtil {
    public static void main(String[] args) throws Exception {
        GmSslProviders.ensureInstalled();
        SSLContext ctx = JsseSimpleUtil.createSm2SSLContext(
                "/path/to/client.both.pfx", "password", "/path/to/ca.pem");
        try (SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket("host", 8443)) {
            socket.setEnabledCipherSuites(
                    new String[]{CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3.getName()});
            socket.startHandshake();
            socket.getOutputStream().write("ping".getBytes("UTF-8"));
            socket.getOutputStream().flush();
        }
    }
}
```

One-way server (no client cert): build server context with server PFX + CA; client uses `createAuthClientSSLContext(ca, false)` and `listen.setNeedClientAuth(false)`.

### 2.2 Server + client without `JsseSimpleUtil`

Build `SSLContext` as in [§1.2 manual mutual](#without-jssesimpleutil-manual-keystore), then:

```java
SSLServerSocketFactory ssf = ctx.getServerSocketFactory();
SSLSocketFactory csf = ctx.getSocketFactory();
// same listen / accept / createSocket pattern as above
```

Automated reference: `src/test/java/com/open/jgm/jsse/integration/Sm2PfxBlockingIT.java`.

---

## 3. Netty NTLS server and client

Add Netty to **your** application (test scope in this repo only):

```xml
<dependency>
    <groupId>io.netty</groupId>
    <artifactId>netty-handler</artifactId>
    <version>4.1.108.Final</version>
</dependency>
<dependency>
    <groupId>io.netty</groupId>
    <artifactId>netty-transport</artifactId>
    <version>4.1.108.Final</version>
</dependency>
<dependency>
    <groupId>io.netty</groupId>
    <artifactId>netty-codec</artifactId>
    <version>4.1.108.Final</version>
</dependency>
```

### 3.1 With `JsseSimpleUtil`

**Server pipeline** (core part):

```java
import com.open.jgm.jsse.CipherSuite;
import com.open.jgm.jsse.GmSslProviders;
import com.open.jgm.jsse.JsseSimpleUtil;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

SSLContext serverCtx = JsseSimpleUtil.createSm2SSLContext(
        "/path/to/server.both.pfx", "password", "/path/to/ca.pem");

new ChannelInitializer<SocketChannel>() {
    @Override
    protected void initChannel(SocketChannel ch) {
        SSLEngine engine = serverCtx.createSSLEngine();
        engine.setUseClientMode(false);
        engine.setNeedClientAuth(true);
        engine.setEnabledProtocols(new String[]{"NTLSv1.1"});
        engine.setEnabledCipherSuites(
                new String[]{CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3.getName()});
        ch.pipeline().addLast("ssl", new SslHandler(engine));
        // add your application handlers after SSL
    }
};
```

**Client pipeline**:

```java
SSLContext clientCtx = JsseSimpleUtil.createSm2SSLContext(
        "/path/to/client.both.pfx", "password", "/path/to/ca.pem");

SSLEngine engine = clientCtx.createSSLEngine("host", 8443);
engine.setUseClientMode(true);
engine.setEnabledProtocols(new String[]{"NTLSv1.1"});
engine.setEnabledCipherSuites(
        new String[]{CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3.getName()});
ch.pipeline().addLast("ssl", new SslHandler(engine));
```

Full runnable demos: `src/test/java/com/open/jgm/jsse/simple/TestNettyGmsslServerMain.java`, `TestNettyGmsslClientMain.java`. CI test: `integration/NettyGmsslIT.java`.

### 3.2 Without `JsseSimpleUtil`

Use the same `SSLContext` you built manually in §1, then identical `createSSLEngine()` / `SslHandler` setup as §3.1.

---

## Tests

```bash
mvn test
```

Integration: `Sm2PfxBlockingIT`, `NettyGmsslIT`, `RecordStreamSecurityTest`, `KeyScheduleTest`. Test certs: `src/test/resources/README.md`.

## License

[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0)