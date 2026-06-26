[English](./README.md) | 简体中文

# gm-jsse-ntls

面向 Java 的国密 JSSE（NTLS / GMSSL）：`SSLContext`、阻塞式 `SSLSocket` / `SSLServerSocket`、`SSLEngine`（可用于 Netty）。

## 环境要求

- 运行需 **JDK 8+**。
- classpath 需提供 **BouncyCastle**（本库对 `bcpkix-jdk15to18` 为 **provided**，建议 1.76+）。
- 推荐 JDK 8 编译，或 JDK 17+ 使用 `--release 8`。

## Maven 依赖

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

启动时注册 Provider：

```java
import com.open.jgm.jsse.GmSslProviders;

GmSslProviders.ensureInstalled();
```

## 算法名约定

| API | 算法字符串 |
|-----|------------|
| `TrustManagerFactory` + `GMProvider` | **`X509`** |
| `CertificateFactory` + BouncyCastle | **`X.509`** |

套件名：`CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3.getName()`（`ECC-SM2-WITH-SM4-CBC-SM3`）。协议：**NTLSv1.1**。

**会话复用：** 不支持。

---

## 1. 使用 GMSSL 访问 `https://xxx/`

将 `https://xxx/` 替换为实际国密 HTTPS 地址；服务端须支持 **NTLS**，而非普通 TLS 1.2。

### 1.1 单向认证（客户端校验服务端）

#### 使用 `JsseSimpleUtil`

```java
import com.open.jgm.jsse.GmSslProviders;
import com.open.jgm.jsse.JsseSimpleUtil;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.net.URL;

public class GmHttpsOneWayUtil {
    public static void main(String[] args) throws Exception {
        GmSslProviders.ensureInstalled();
        // 第二个参数 false 表示国密 NTLS 客户端
        SSLContext ctx = JsseSimpleUtil.createAuthClientSSLContext("/path/to/ca.pem", false);

        HttpsURLConnection conn = (HttpsURLConnection) new URL("https://xxx/").openConnection();
        conn.setSSLSocketFactory(ctx.getSocketFactory());
        conn.connect();
        System.out.println(conn.getCipherSuite());
    }
}
```

#### 不使用 `JsseSimpleUtil`（手写信任库）

```java
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
        try (FileInputStream in = new FileInputStream("/path/to/ca.pem")) {
            trust.setCertificateEntry("ca", (X509Certificate) cf.generateCertificate(in));
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509", gm);
        tmf.init(trust);

        SSLContext ctx = SSLContext.getInstance("TLS", gm);
        ctx.init(null, tmf.getTrustManagers(), null);

        HttpsURLConnection conn = (HttpsURLConnection) new URL("https://xxx/").openConnection();
        conn.setSSLSocketFactory(ctx.getSocketFactory());
        conn.connect();
    }
}
```

### 1.2 双向认证（SM2 双证）

#### 使用 `JsseSimpleUtil`

```java
import com.open.jgm.jsse.GmSslProviders;
import com.open.jgm.jsse.JsseSimpleUtil;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.net.URL;

public class GmHttpsMutualUtil {
    public static void main(String[] args) throws Exception {
        GmSslProviders.ensureInstalled();
        SSLContext ctx = JsseSimpleUtil.createSm2SSLContext(
                "/path/to/client.both.pfx", "password", "/path/to/ca.pem");

        HttpsURLConnection conn = (HttpsURLConnection) new URL("https://xxx/").openConnection();
        conn.setSSLSocketFactory(ctx.getSocketFactory());
        conn.connect();
    }
}
```

签名/加密分两个 PFX：

```java
SSLContext ctx = JsseSimpleUtil.createSm2SSLContext(
        "/path/to/sign.pfx", "signPwd", "/path/to/enc.pfx", "encPwd", "/path/to/ca.pem");
```

#### 不使用 `JsseSimpleUtil`

KeyStore 中客户端密钥别名须为 **`sign`**、**`enc`**（与 `GMX509KeyManager` 一致）。可从 PFX 自行 `KeyStore.load`，或仅用工具类读证书/私钥再装入 KeyStore：

```java
import com.open.jgm.jsse.GMProvider;
import com.open.jgm.jsse.GmSslProviders;
import com.open.jgm.jsse.JsseSimpleUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

// 构建 SSLContext 后：
HttpsURLConnection conn = (HttpsURLConnection) new URL("https://xxx/").openConnection();
conn.setSSLSocketFactory(ctx.getSocketFactory());
conn.connect();
```

（完整 KeyStore 组装步骤同英文 README §1.2 manual。）

---

## 2. 阻塞式 NTLS 服务端 / 客户端

### 2.1 使用 `JsseSimpleUtil`

**服务端**：

```java
import com.open.jgm.jsse.CipherSuite;
import com.open.jgm.jsse.GmSslProviders;
import com.open.jgm.jsse.JsseSimpleUtil;

import javax.net.ssl.*;
import java.net.InetAddress;

SSLContext ctx = JsseSimpleUtil.createSm2SSLContext(
        "/path/to/server.both.pfx", "password", "/path/to/ca.pem");
SSLServerSocket listen = (SSLServerSocket) ctx.getServerSocketFactory()
        .createServerSocket(8443, 50, InetAddress.getByName("0.0.0.0"));
listen.setNeedClientAuth(true);
listen.setEnabledCipherSuites(
        new String[]{CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3.getName()});
SSLSocket socket = (SSLSocket) listen.accept();
socket.startHandshake();
```

**客户端**：

```java
SSLContext ctx = JsseSimpleUtil.createSm2SSLContext(
        "/path/to/client.both.pfx", "password", "/path/to/ca.pem");
SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket("host", 8443);
socket.setEnabledCipherSuites(
        new String[]{CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3.getName()});
socket.startHandshake();
```

单向：服务端 `setNeedClientAuth(false)`；客户端 `createAuthClientSSLContext(ca, false)`。

### 2.2 不使用 `JsseSimpleUtil`

按 §1 手工 `SSLContext.init` 后，使用 `getServerSocketFactory()` / `getSocketFactory()`，配置同上。

参考：`integration/Sm2PfxBlockingIT.java`。

---

## 3. Netty NTLS 服务端 / 客户端

业务工程需自行引入 `netty-handler`、`netty-transport`、`netty-codec`（版本可与仓库测试依赖一致 4.1.108.Final）。

### 3.1 使用 `JsseSimpleUtil`

**服务端**（在 `ChannelInitializer` 中）：

```java
import com.open.jgm.jsse.CipherSuite;
import com.open.jgm.jsse.JsseSimpleUtil;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

SSLContext serverCtx = JsseSimpleUtil.createSm2SSLContext(
        "/path/to/server.both.pfx", "password", "/path/to/ca.pem");

SSLEngine engine = serverCtx.createSSLEngine();
engine.setUseClientMode(false);
engine.setNeedClientAuth(true);
engine.setEnabledProtocols(new String[]{"NTLSv1.1"});
engine.setEnabledCipherSuites(
        new String[]{CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3.getName()});
ch.pipeline().addLast("ssl", new SslHandler(engine));
```

**客户端**：

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

完整示例：`TestNettyGmsslServerMain` / `TestNettyGmsslClientMain`；自动化：`NettyGmsslIT`。

### 3.2 不使用 `JsseSimpleUtil`

使用 §1 手工构建的 `SSLContext`，`SSLEngine` / `SslHandler` 配置与 §3.1 相同。

---

## 测试

```bash
mvn test
```

集成测试：`Sm2PfxBlockingIT`、`NettyGmsslIT` 等。测试证书：`src/test/resources/README.md`。

## 许可证

[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0)