package com.dnsguard.api;

import com.dnsguard.app.DnsGuardConfig;
import com.dnsguard.detector.DnsDetector;
import com.dnsguard.model.DnsAlert;
import com.dnsguard.model.DnsQuery;
import com.dnsguard.parser.DnsCsvParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class DnsGuardApiHandler implements HttpHandler {

    private static final int MAX_UPLOAD_SIZE = 10 * 1024 * 1024;

    @Override
    public void handle(HttpExchange exchange) throws IOException {

        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405,
                    "{\"error\":\"Only POST requests are allowed.\"}");
            return;
        }

        Path tempFile = null;

        try {
            byte[] body = exchange.getRequestBody()
                    .readNBytes(MAX_UPLOAD_SIZE + 1);

            if (body.length == 0 || body.length > MAX_UPLOAD_SIZE) {
                sendJson(exchange, 400,
                        "{\"error\":\"CSV is empty or exceeds 10 MB.\"}");
                return;
            }

            tempFile = Files.createTempFile("dnsguard-", ".csv");
            Files.write(tempFile, body);

            DnsCsvParser parser = new DnsCsvParser();
            List<DnsQuery> queries = parser.parse(tempFile);

            if (queries.isEmpty()) {
                sendJson(exchange, 400,
                        "{\"error\":\"No valid DNS records found.\"}");
                return;
            }

            DnsGuardConfig config = DnsGuardConfig.load(
                    Path.of("config", "dnsguard.properties"));

            // A fresh detector prevents state leaking between uploads.
            DnsDetector detector = new DnsDetector(
                    config.getDomainLengthThreshold(),
                    config.getEntropyThreshold(),
                    config.getRepeatedQueryThreshold(),
                    config.getTimeWindow(),
                    config.getUniqueSubdomainThreshold(),
                    config.getQueryRateThreshold(),
                    config.getTxtRepeatedQueryThreshold()
            );

            List<DnsAlert> alerts = new ArrayList<>();

            for (DnsQuery query : queries) {
                alerts.addAll(detector.detect(query));
            }

            long high = count(alerts, DnsAlert.Severity.HIGH);
            long medium = count(alerts, DnsAlert.Severity.MEDIUM);
            long low = count(alerts, DnsAlert.Severity.LOW);

            StringBuilder json = new StringBuilder();

            json.append("{")
                    .append("\"application\":\"DNSGuard\",")
                    .append("\"version\":\"1.0.0\",")
                    .append("\"recordsAnalyzed\":").append(queries.size()).append(",")
                    .append("\"totalAlerts\":").append(alerts.size()).append(",")
                    .append("\"high\":").append(high).append(",")
                    .append("\"medium\":").append(medium).append(",")
                    .append("\"low\":").append(low).append(",")
                    .append("\"alerts\":[");

            for (int i = 0; i < alerts.size(); i++) {
                DnsAlert alert = alerts.get(i);
                DnsQuery query = alert.getQuery();

                if (i > 0) {
                    json.append(",");
                }

                json.append("{")
                        .append("\"timestamp\":").append(quote(query.getTimestamp().toString())).append(",")
                        .append("\"sourceIp\":").append(quote(query.getSourceIp())).append(",")
                        .append("\"domain\":").append(quote(query.getDomain())).append(",")
                        .append("\"recordType\":").append(quote(query.getRecordType())).append(",")
                        .append("\"responseCode\":").append(quote(query.getResponseCode())).append(",")
                        .append("\"riskScore\":").append(alert.getRiskScore()).append(",")
                        .append("\"severity\":").append(quote(alert.getSeverity().name())).append(",")
                        .append("\"reasons\":").append(stringArray(alert.getReasons())).append(",")
                        .append("\"ruleIds\":").append(stringArray(new ArrayList<>(alert.getRuleIds())))
                        .append("}");
            }

            json.append("]}");

            sendJson(exchange, 200, json.toString());

        } catch (IllegalArgumentException exception) {
            sendJson(exchange, 400,
                    "{\"error\":" + quote(exception.getMessage()) + "}");

        } catch (Exception exception) {
            exception.printStackTrace();
            sendJson(exchange, 500,
                    "{\"error\":\"DNSGuard analysis failed.\"}");

        } finally {
            if (tempFile != null) {
                Files.deleteIfExists(tempFile);
            }
        }
    }

    private long count(List<DnsAlert> alerts, DnsAlert.Severity severity) {
        return alerts.stream()
                .filter(alert -> alert.getSeverity() == severity)
                .count();
    }

    private String stringArray(List<String> values) {
        StringBuilder result = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) result.append(",");
            result.append(quote(values.get(i)));
        }
        return result.append("]").toString();
    }

    private String quote(String value) {
        StringBuilder result = new StringBuilder("\"");

        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default -> {
                    if (c < 0x20) {
                        result.append(String.format("\\u%04x", (int) c));
                    } else {
                        result.append(c);
                    }
                }
            }
        }

        return result.append("\"").toString();
    }

    private void sendJson(HttpExchange exchange, int status, String body)
            throws IOException {

        byte[] response = body.getBytes(StandardCharsets.UTF_8);

        exchange.getResponseHeaders()
                .set("Content-Type", "application/json; charset=UTF-8");

        exchange.sendResponseHeaders(status, response.length);

        try (var output = exchange.getResponseBody()) {
            output.write(response);
        }
    }
}
