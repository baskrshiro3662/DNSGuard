package com.dnsguard.api;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

public class DnsGuardServer {

    private static final int PORT = 8081;

    public static void main(String[] args) throws IOException {

        HttpServer server = HttpServer.create(
                new InetSocketAddress("127.0.0.1", PORT), 0);

        server.createContext("/api/health", exchange -> {
            byte[] response = """
                    {"status":"UP","application":"DNSGuard","version":"1.0.0"}
                    """.getBytes(java.nio.charset.StandardCharsets.UTF_8);

            exchange.getResponseHeaders()
                    .set("Content-Type", "application/json");

            exchange.sendResponseHeaders(200, response.length);

            try (var output = exchange.getResponseBody()) {
                output.write(response);
            }
        });

        server.createContext("/api/analyze", new DnsGuardApiHandler());

        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();

        System.out.println("==================================");
        System.out.println("       DNSGuard v1.0.0 API");
        System.out.println("==================================");
        System.out.println("Backend running on port " + PORT);
        System.out.println("Health: http://127.0.0.1:" + PORT + "/api/health");
        System.out.println("Analyze: POST http://127.0.0.1:" + PORT + "/api/analyze");
    }
}
