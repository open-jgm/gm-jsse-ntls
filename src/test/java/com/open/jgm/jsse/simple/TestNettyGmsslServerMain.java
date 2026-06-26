package com.open.jgm.jsse.simple;

import com.open.jgm.jsse.CipherSuite;
import com.open.jgm.jsse.JsseSimpleUtil;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.bytes.ByteArrayDecoder;
import io.netty.handler.codec.bytes.ByteArrayEncoder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.nio.charset.StandardCharsets;

public class TestNettyGmsslServerMain {

    private static final String DEFAULT_HOST = "127.0.0.1";
    private static final int DEFAULT_PORT = 19443;
    private static final String DEFAULT_PWD = GmsslTestMaterialPaths.DEFAULT_PWD;
    private static final String RESPONSE_TEXT = "1234im server";

    public static void main(String[] args) throws Exception {
        String host = property("gmssl.netty.host", DEFAULT_HOST);
        int port = intProperty("gmssl.netty.port", DEFAULT_PORT);
        String pfxFile = GmsslTestMaterialPaths.resolve(
                property("gmssl.netty.server.pfx", "server/sm2.server.both.pfx"));
        String caFile = GmsslTestMaterialPaths.resolve(
                property("gmssl.netty.server.ca", "server/sm2.ca.pem"));
        String password = property("gmssl.netty.server.password", DEFAULT_PWD);

        SSLContext sslContext = JsseSimpleUtil.createSm2SSLContext(pfxFile, password, caFile);
        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        try {
            ServerBootstrap bootstrap = new ServerBootstrap();
            bootstrap.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .option(ChannelOption.SO_BACKLOG, 128)
                    .childOption(ChannelOption.TCP_NODELAY, true)
                    .childHandler(new GmsslServerInitializer(sslContext));

            ChannelFuture bindFuture = bootstrap.bind(host, port).sync();
            System.out.println("Netty GMSSL server started: " + host + ":" + port);
            bindFuture.channel().closeFuture().sync();
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
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

    private static final class GmsslServerInitializer extends ChannelInitializer<SocketChannel> {
        private final SSLContext sslContext;

        private GmsslServerInitializer(SSLContext sslContext) {
            this.sslContext = sslContext;
        }

        @Override
        protected void initChannel(SocketChannel channel) {
            SSLEngine engine = sslContext.createSSLEngine();
            engine.setUseClientMode(false);
            engine.setNeedClientAuth(true);
            engine.setEnabledProtocols(new String[]{"NTLSv1.1"});
            engine.setEnabledCipherSuites(new String[]{CipherSuite.NTLS_SM2_WITH_SM4_CBC_SM3.getName()});

            channel.pipeline().addLast("ssl", new SslHandler(engine));
            channel.pipeline().addLast("bytesDecoder", new ByteArrayDecoder());
            channel.pipeline().addLast("bytesEncoder", new ByteArrayEncoder());
            channel.pipeline().addLast("serverHandler", new GmsslServerHandler(engine));
        }
    }

    private static final class GmsslServerHandler extends SimpleChannelInboundHandler<byte[]> {
        private final SSLEngine engine;

        private GmsslServerHandler(SSLEngine engine) {
            this.engine = engine;
        }

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, byte[] msg) {
            System.out.println("Netty GMSSL server received: " + new String(msg, StandardCharsets.UTF_8));
            ctx.writeAndFlush(RESPONSE_TEXT.getBytes(StandardCharsets.UTF_8))
                    .addListener(ChannelFutureListener.CLOSE);
        }

        @Override
        public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
            if (evt instanceof SslHandshakeCompletionEvent) {
                SslHandshakeCompletionEvent event = (SslHandshakeCompletionEvent) evt;
                if (event.isSuccess()) {
                    System.out.println("Netty GMSSL server handshake success: protocol="
                            + engine.getSession().getProtocol() + ", cipher="
                            + engine.getSession().getCipherSuite() + ", remote="
                            + ctx.channel().remoteAddress());
                } else {
                    System.out.println("Netty GMSSL server handshake failed: " + event.cause());
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