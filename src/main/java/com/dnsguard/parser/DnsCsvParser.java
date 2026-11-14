
package com.dnsguard.parser;

import com.dnsguard.model.DnsQuery;

import java.io.BufferedReader;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class DnsCsvParser {

    public List<DnsQuery> parse(Path filePath) throws IOException {
        List<DnsQuery> queries = new ArrayList<>();

        try (BufferedReader reader = Files.newBufferedReader(
                filePath, StandardCharsets.UTF_8)) {

            String headerLine = reader.readLine();

            if (headerLine == null || headerLine.isBlank()) {
                throw new IOException("CSV file is empty.");
            }

            // Remove UTF-8 BOM if present.
            headerLine = headerLine.replace("\uFEFF", "").trim();

            List<String> headers = parseCsvLine(headerLine);
            Map<String, Integer> columns = mapColumns(headers);

            int timestampIndex = findColumn(
                    columns, "timestamp", "time", "ts",
                    "querytimestamp");

            int sourceIpIndex = findColumn(
                    columns, "sourceip", "srcip",
                    "clientip", "clientaddress",
                    "sourceaddress");

            int domainIndex = findColumn(
                    columns, "domain", "qname",
                    "query", "queryname", "domainname");

            int recordTypeIndex = findColumn(
                    columns, "recordtype", "type", "qtype");

            int responseCodeIndex = findColumn(
                    columns, "responsecode", "rcode",
                    "response", "status");

            if (timestampIndex < 0 ||
                    sourceIpIndex < 0 ||
                    domainIndex < 0 ||
                    recordTypeIndex < 0 ||
                    responseCodeIndex < 0) {

                throw new IOException(
                        "CSV is missing required DNS columns. " +
                        "Required: timestamp, sourceIp, domain, " +
                        "recordType, responseCode.");
            }

            String line;
            int lineNumber = 1;
            int skippedRows = 0;

            while ((line = reader.readLine()) != null) {
                lineNumber++;

                if (line.isBlank()) {
                    continue;
                }

                try {
                    List<String> fields = parseCsvLine(line);

                    int maxIndex = Math.max(
                            Math.max(timestampIndex, sourceIpIndex),
                            Math.max(
                                    Math.max(domainIndex, recordTypeIndex),
                                    responseCodeIndex));

                    if (fields.size() <= maxIndex) {
                        throw new IllegalArgumentException(
                                "Missing required CSV fields.");
                    }

                    Instant timestamp = parseTimestamp(
                            fields.get(timestampIndex));

                    DnsQuery query = new DnsQuery(
                            timestamp,
                            fields.get(sourceIpIndex),
                            fields.get(domainIndex),
                            fields.get(recordTypeIndex),
                            fields.get(responseCodeIndex)
                    );

                    queries.add(query);

                } catch (RuntimeException exception) {
                    skippedRows++;

                    if (skippedRows <= 10) {
                        System.err.println(
                                "Skipping line " + lineNumber +
                                ": " + exception.getMessage());
                    }
                }
            }

            System.out.println(
                    "DNS CSV parsing complete: " +
                    queries.size() + " valid records, " +
                    skippedRows + " skipped rows.");
        }

        if (queries.isEmpty()) {
            throw new IOException(
                    "No valid DNS records found. " +
                    "Check CSV columns, timestamps and field values.");
        }

        return queries;
    }

    private Map<String, Integer> mapColumns(List<String> headers) {
        Map<String, Integer> columns = new HashMap<>();

        for (int i = 0; i < headers.size(); i++) {
            columns.put(normalizeHeader(headers.get(i)), i);
        }

        return columns;
    }

    private int findColumn(
            Map<String, Integer> columns,
            String... aliases) {

        for (String alias : aliases) {
            Integer index = columns.get(normalizeHeader(alias));

            if (index != null) {
                return index;
            }
        }

        return -1;
    }

    private String normalizeHeader(String header) {
        return header.trim()
                .toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]", "");
    }

    private Instant parseTimestamp(String value) {
        String timestamp = value.trim();

        if (timestamp.isEmpty()) {
            throw new IllegalArgumentException(
                    "Timestamp is empty.");
        }

        // ISO-8601 timestamp, e.g. 2026-11-15T10:30:00Z.
        try {
            return Instant.parse(timestamp);
        } catch (DateTimeParseException ignored) {
            // Try other supported formats.
        }

        // ISO-8601 timestamp with an explicit timezone offset.
        try {
            return OffsetDateTime.parse(timestamp).toInstant();
        } catch (DateTimeParseException ignored) {
            // Try Unix timestamp.
        }

        // Unix timestamps in seconds or milliseconds.
        try {
            BigDecimal number = new BigDecimal(timestamp);

            // Values around 10^12 are typically Unix milliseconds.
            if (number.abs().compareTo(
                    new BigDecimal("100000000000")) >= 0) {

                number = number.movePointRight(6);
            } else {
                // Unix seconds, including fractional seconds.
                number = number.movePointRight(9);
            }

            BigInteger totalNanos = number.toBigIntegerExact();

            BigInteger billion = BigInteger.valueOf(1_000_000_000L);

            BigInteger[] parts = totalNanos.divideAndRemainder(billion);

            return Instant.ofEpochSecond(
                    parts[0].longValueExact(),
                    parts[1].longValueExact()
            );

        } catch (NumberFormatException |
                 ArithmeticException exception) {

            throw new IllegalArgumentException(
                    "Unsupported timestamp: " + timestamp,
                    exception);
        }
    }

    // Handles quoted CSV fields and escaped double quotes.
    private List<String> parseCsvLine(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder field = new StringBuilder();

        boolean insideQuotes = false;

        for (int i = 0; i < line.length(); i++) {
            char current = line.charAt(i);

            if (current == '"') {
                if (insideQuotes &&
                        i + 1 < line.length() &&
                        line.charAt(i + 1) == '"') {

                    field.append('"');
                    i++;
                } else {
                    insideQuotes = !insideQuotes;
                }

            } else if (current == ',' && !insideQuotes) {
                fields.add(field.toString().trim());
                field.setLength(0);

            } else {
                field.append(current);
            }
        }

        if (insideQuotes) {
            throw new IllegalArgumentException(
                    "Unclosed quoted CSV field.");
        }

        fields.add(field.toString().trim());

        return fields;
    }
}
