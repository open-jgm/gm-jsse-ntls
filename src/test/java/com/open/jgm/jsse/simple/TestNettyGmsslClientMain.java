package com.open.jgm.jsse.simple;

import com.open.jgm.jsse.CipherSuite;
import com.open.jgm.jsse.JsseSimpleUtil;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.bytes.ByteArrayDecoder;
import io.netty.handler.codec.bytes.ByteArrayEncoder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.nio.charset.StandardCharsets;

public class TestNettyGmsslClientMain {

    private static final String DEFAULT_HOST = "127.0.0.1";
    private static final int DEFAULT_PORT = 19443;
    private static final String DEFAULT_PWD = GmsslTestMaterialPaths.DEFAULT_PWD;
    private static final String DEFAULT_MESSAGE = "im client";

    public static void main(String[] args) throws Exception {
        String host = property("gmssl.netty.host", DEFAULT_HOST);
        int port = intProperty("gmssl.netty.port", DEFAULT_PORT);
        String pfxFile = GmsslTestMaterialPaths.resolve(
                property("gmssl.netty.client.pfx", "client/sm2.client.both.pfx"));
        String caFile = GmsslTestMaterialPaths.resolve(
                property("gmssl.netty.client.ca", "client/sm2.ca.pem"));
        String password = property("gmssl.netty.client.password", DEFAULT_PWD);
        String message = property("gmssl.netty.client.message", DEFAULT_MESSAGE);

        SSLContext sslContext = JsseSimpleUtil.createSm2SSLContext(pfxFile, password, caFile);
        EventLoopGroup group = new NioEventLoopGroup();
        try {
            Bootstrap bootstrap = new Bootstrap();
            bootstrap.group(group)
                    .channel(NioSocketChannel.class)
                    .option(ChannelOption.TCP_NODELAY, true)
                    .handler(new GmsslClientInitializer(sslContext, host, port, message));

            ChannelFuture connectFuture = bootstrap.connect(host, port).sync();
            System.out.println("Netty GMSSL client connected: " + host + ":" + port);
            connectFuture.channel().closeFuture().sync();
        } finally {
            group.shutdownGracefully();
        }
    }

    private static String property(String name, String defaultValue) {
        String value = System.getProperty(name);
        return value == null || value.isEmpty() ? defaultValue : value;
    }

    private static int intProperty(String name, int defaultValue) {
        String value = System.getProperty(name);
        return value == null || value.isEmpty() ? defaultValue : Integer.parseInt(value);
    }

    private static final class GmsslClientInitializer extends ChannelInitializer<SocketChannel> {
        private final SSLContext sslContext;
        private final String host;
        private final int port;
        private final String message;

        private GmsslClientInitializer(SSLContext sslContext, String host, int port, String message) {
            this.sslContext = sslContext;
            this.host = host;
            this.port = port;
            this.message = message;
        }

        @Override
        protected void initChannel(SocketChannel channel) {
            SSLEngine engine = sslContext.createSSLEngine(host, port);
            engine.setUseClientMode(true);
            engine.setEnabledProtocols(new String[]{"NTLSv1.1"});
            engine.setEnabledCipherSuites(new String[]{CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3.getName()});

            channel.pipeline().addLast("ssl", new SslHandler(engine));
            channel.pipeline().addLast("bytesDecoder", new ByteArrayDecoder());
            channel.pipeline().addLast("bytesEncoder", new ByteArrayEncoder());
            channel.pipeline().addLast("clientHandler", new GmsslClientHandler(engine, message));
        }
    }

    private static final class GmsslClientHandler extends SimpleChannelInboundHandler<byte[]> {
        private final SSLEngine engine;
        private final String message;

        private GmsslClientHandler(SSLEngine engine, String message) {
            this.engine = engine;
            this.message = message;
        }

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, byte[] msg) {
            System.out.println("Netty GMSSL client received: " + new String(msg, StandardCharsets.UTF_8));
            ctx.close();
        }

        @Override
        public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
            if (evt instanceof SslHandshakeCompletionEvent) {
                SslHandshakeCompletionEvent event = (SslHandshakeCompletionEvent) evt;
                if (event.isSuccess()) {
                    System.out.println("Netty GMSSL client handshake success: protocol="
                            + engine.getSession().getProtocol() + ", cipher="
                            + engine.getSession().getCipherSuite() + ", remote="
                            + ctx.channel().remoteAddress());
                    ctx.writeAndFlush(message.getBytes(StandardCharsets.UTF_8));
                } else {
                    System.out.println("Netty GMSSL client handshake failed: " + event.cause());
                    ctx.close();
                }
                return;
            }
            super.userEventTriggered(ctx, evt);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            cause.printStackTrace();
            ctx.close();
        }
    }
}