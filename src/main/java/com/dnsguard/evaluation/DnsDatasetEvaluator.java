package com.dnsguard.evaluation;

import com.dnsguard.detector.DnsDetector;
import com.dnsguard.model.DnsQuery;
import com.dnsguard.model.DnsAlert;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public class DnsDatasetEvaluator {

    private static final String EXPECTED_HEADER =
            "timestamp,sourceIp,domain,recordType,responseCode,label";

    public EvaluationResult evaluate(
            Path datasetPath,
            DnsDetector detector) throws IOException {

        return evaluate(datasetPath, detector, Duration.ofMinutes(1));
    }

    public EvaluationResult evaluate(
            Path datasetPath,
            DnsDetector detector,
            Duration episodeWindow) throws IOException {

        if (datasetPath == null
                || !Files.isRegularFile(datasetPath)
                || !Files.isReadable(datasetPath)) {
            throw new IOException(
                    "Dataset file does not exist or is not readable: "
                            + datasetPath);
        }

        if (detector == null) {
            throw new IllegalArgumentException(
                    "Detector must not be null");
        }

        if (episodeWindow == null
                || episodeWindow.isZero()
                || episodeWindow.isNegative()) {
            throw new IllegalArgumentException(
                    "Episode window must be greater than zero");
        }

        List<EvaluatedRecord> records =
                readAndEvaluateRecords(datasetPath, detector);

        Map<String, RulePerformanceStats> ruleStats = createRuleStats();
        for (EvaluatedRecord record : records) {
            for (String ruleId : record.ruleIds) {
                RulePerformanceStats stats = ruleStats.get(ruleId);
                if (stats != null) {
                    stats.recordTrigger(record.actualSuspicious);
                }
            }
        }

        int tp = 0;
        int fp = 0;
        int tn = 0;
        int fn = 0;

        List<DnsQuery> missedRecords = new ArrayList<>();
        List<DnsQuery> falseAlarmRecords = new ArrayList<>();

        for (EvaluatedRecord record : records) {
            if (record.actualSuspicious && record.predictedSuspicious) {
                tp++;
            } else if (!record.actualSuspicious
                    && record.predictedSuspicious) {
                fp++;
                falseAlarmRecords.add(record.query);
            } else if (!record.actualSuspicious) {
                tn++;
            } else {
                fn++;
                missedRecords.add(record.query);
            }
        }

        EpisodeCounts episodes =
                evaluateEpisodes(records, episodeWindow);

        return new EvaluationResult(
                records.size(),
                tp,
                fp,
                tn,
                fn,
                missedRecords,
                falseAlarmRecords,
                episodes.total,
                episodes.truePositives,
                episodes.falsePositives,
                episodes.trueNegatives,
                episodes.falseNegatives,
                ruleStats,
                episodes.diagnostics
        );
    }

    private static Map<String, RulePerformanceStats> createRuleStats() {
        Map<String, RulePerformanceStats> stats = new LinkedHashMap<>();
        String[] ids = {
    DnsDetector.RULE_LONG_DOMAIN,
    DnsDetector.RULE_HIGH_ENTROPY,
    DnsDetector.RULE_REPEATED_QUERY,
    DnsDetector.RULE_UNIQUE_SUBDOMAINS,
    DnsDetector.RULE_QUERY_BURST,
    DnsDetector.RULE_REPEATED_TXT,
    DnsDetector.RULE_TXT_CORRELATION,
    DnsDetector.RULE_REPEATED_NXDOMAIN
};
        for (String id : ids) {
            stats.put(id, new RulePerformanceStats(id));
        }
        return stats;
    }

    private List<EvaluatedRecord> readAndEvaluateRecords(
            Path datasetPath,
            DnsDetector detector) throws IOException {

        List<EvaluatedRecord> records = new ArrayList<>();

        try (BufferedReader reader = Files.newBufferedReader(
                datasetPath, StandardCharsets.UTF_8)) {

            String header = reader.readLine();

            if (header == null
                    || !header.trim().equals(EXPECTED_HEADER)) {
                throw new IOException(
                        "Invalid dataset header. Expected: "
                                + EXPECTED_HEADER);
            }

            String line;
            int lineNumber = 1;

            while ((line = reader.readLine()) != null) {
                lineNumber++;

                if (line.isBlank()) {
                    continue;
                }

                String[] fields = line.split(",", -1);

                if (fields.length != 6) {
                    throw new IOException(
                            "Invalid column count on line " + lineNumber);
                }

                String label = fields[5].trim()
                        .toUpperCase(Locale.ROOT);

                boolean actuallySuspicious;

                if ("SUSPICIOUS".equals(label)) {
                    actuallySuspicious = true;
                } else if ("NORMAL".equals(label)) {
                    actuallySuspicious = false;
                } else {
                    throw new IOException(
                            "Invalid label on line " + lineNumber
                                    + ": " + fields[5]);
                }

                DnsQuery query;

                try {
                    query = new DnsQuery(
                            Instant.parse(fields[0].trim()),
                            fields[1].trim(),
                            fields[2].trim(),
                            fields[3].trim(),
                            fields[4].trim()
                    );
                } catch (RuntimeException exception) {
                    throw new IOException(
                            "Invalid DNS query on line " + lineNumber
                                    + ": " + exception.getMessage(),
                            exception);
                }

                boolean predictedSuspicious;
                Set<String> triggeredRuleIds = new LinkedHashSet<>();

                try {
                    List<DnsAlert> alerts = detector.detect(query);
                    predictedSuspicious = !alerts.isEmpty();
                    for (DnsAlert alert : alerts) {
                        triggeredRuleIds.addAll(alert.getRuleIds());
                    }
                } catch (RuntimeException exception) {
                    throw new IOException(
                            "Detection failed on line " + lineNumber
                                    + ": " + exception.getMessage(),
                            exception);
                }

                records.add(new EvaluatedRecord(
                        query,
                        actuallySuspicious,
                        predictedSuspicious,
                        triggeredRuleIds
                ));
            }
        }

        return records;
    }

    private EpisodeCounts evaluateEpisodes(
            List<EvaluatedRecord> records,
            Duration episodeWindow) {

        List<EvaluatedRecord> chronological =
                new ArrayList<>(records);

        chronological.sort(Comparator.comparing(
                record -> record.query.getTimestamp()));

        Map<EpisodeKey, Episode> activeEpisodes = new HashMap<>();
        List<Episode> completedEpisodes = new ArrayList<>();

        for (EvaluatedRecord record : chronological) {
            DnsQuery query = record.query;

            EpisodeKey key = new EpisodeKey(
                    query.getSourceIp(),
                    query.getDomain(),
                    query.getRecordType(),
                    record.actualSuspicious
            );

            Instant timestamp = query.getTimestamp();
            Episode episode = activeEpisodes.get(key);

            if (episode == null
                    || Duration.between(
                            episode.lastTimestamp, timestamp)
                            .compareTo(episodeWindow) > 0) {

                if (episode != null) {
                    completedEpisodes.add(episode);
                }

                episode = new Episode(
                        query.getSourceIp(),
                        query.getDomain(),
                        query.getRecordType(),
                        record.actualSuspicious,
                        timestamp
                );

                activeEpisodes.put(key, episode);
            }

            episode.lastTimestamp = timestamp;
            episode.queryCount++;

            if (record.predictedSuspicious) {
                episode.detectedQueryCount++;
            }

            if (record.actualSuspicious && !record.predictedSuspicious) {
                episode.missedQueryCount++;
            }

            episode.predictedSuspicious |= record.predictedSuspicious;
        }

        completedEpisodes.addAll(activeEpisodes.values());

        EpisodeCounts counts = new EpisodeCounts();
        counts.total = completedEpisodes.size();

        for (Episode episode : completedEpisodes) {
            counts.diagnostics.add(new EpisodeDiagnostic(
                    episode.sourceIp,
                    episode.domain,
                    episode.recordType,
                    episode.actualSuspicious,
                    episode.queryCount,
                    episode.detectedQueryCount,
                    episode.missedQueryCount,
                    episode.firstTimestamp,
                    episode.lastTimestamp,
                    episode.predictedSuspicious
            ));

            if (episode.actualSuspicious && episode.predictedSuspicious) {
                counts.truePositives++;
            } else if (!episode.actualSuspicious
                    && episode.predictedSuspicious) {
                counts.falsePositives++;
            } else if (!episode.actualSuspicious) {
                counts.trueNegatives++;
            } else {
                counts.falseNegatives++;
            }
        }

        return counts;
    }

    private static class EvaluatedRecord {
        private final DnsQuery query;
        private final boolean actualSuspicious;
        private final boolean predictedSuspicious;
        private final Set<String> ruleIds;

        private EvaluatedRecord(
                DnsQuery query,
                boolean actualSuspicious,
                boolean predictedSuspicious,
                Set<String> ruleIds) {
            this.query = query;
            this.actualSuspicious = actualSuspicious;
            this.predictedSuspicious = predictedSuspicious;
            this.ruleIds = new LinkedHashSet<>(ruleIds);
        }
    }

    private static class EpisodeKey {
        private final String sourceIp;
        private final String domain;
        private final String recordType;
        private final boolean actualSuspicious;

        private EpisodeKey(
                String sourceIp,
                String domain,
                String recordType,
                boolean actualSuspicious) {
            this.sourceIp = sourceIp;
            this.domain = domain;
            this.recordType = recordType;
            this.actualSuspicious = actualSuspicious;
        }

        @Override
        public boolean equals(Object object) {
            if (this == object) {
                return true;
            }

            if (!(object instanceof EpisodeKey other)) {
                return false;
            }

            return actualSuspicious == other.actualSuspicious
                    && Objects.equals(sourceIp, other.sourceIp)
                    && Objects.equals(domain, other.domain)
                    && Objects.equals(recordType, other.recordType);
        }

        @Override
        public int hashCode() {
            return Objects.hash(
                    sourceIp, domain, recordType, actualSuspicious);
        }
    }

    public static final class EpisodeDiagnostic {
        private final String sourceIp;
        private final String domain;
        private final String recordType;
        private final boolean actualSuspicious;
        private final int queryCount;
        private final int detectedQueryCount;
        private final int missedQueryCount;
        private final Instant firstTimestamp;
        private final Instant lastTimestamp;
        private final boolean detected;

        private EpisodeDiagnostic(
                String sourceIp,
                String domain,
                String recordType,
                boolean actualSuspicious,
                int queryCount,
                int detectedQueryCount,
                int missedQueryCount,
                Instant firstTimestamp,
                Instant lastTimestamp,
                boolean detected) {
            this.sourceIp = sourceIp;
            this.domain = domain;
            this.recordType = recordType;
            this.actualSuspicious = actualSuspicious;
            this.queryCount = queryCount;
            this.detectedQueryCount = detectedQueryCount;
            this.missedQueryCount = missedQueryCount;
            this.firstTimestamp = firstTimestamp;
            this.lastTimestamp = lastTimestamp;
            this.detected = detected;
        }

        public String getSourceIp() { return sourceIp; }
        public String getDomain() { return domain; }
        public String getRecordType() { return recordType; }
        public boolean isActualSuspicious() { return actualSuspicious; }
        public int getQueryCount() { return queryCount; }
        public int getDetectedQueryCount() { return detectedQueryCount; }
        public int getMissedQueryCount() { return missedQueryCount; }
        public Instant getFirstTimestamp() { return firstTimestamp; }
        public Instant getLastTimestamp() { return lastTimestamp; }
        public boolean isDetected() { return detected; }
    }

    private static class Episode {
        private final String sourceIp;
        private final String domain;
        private final String recordType;
        private final boolean actualSuspicious;
        private boolean predictedSuspicious;
        private int queryCount;
        private int detectedQueryCount;
        private int missedQueryCount;
        private final Instant firstTimestamp;
        private Instant lastTimestamp;

        private Episode(
                String sourceIp,
                String domain,
                String recordType,
                boolean actualSuspicious,
                Instant timestamp) {
            this.sourceIp = sourceIp;
            this.domain = domain;
            this.recordType = recordType;
            this.actualSuspicious = actualSuspicious;
            this.firstTimestamp = timestamp;
            this.lastTimestamp = timestamp;
        }
    }

    private static class EpisodeCounts {
        private final List<EpisodeDiagnostic> diagnostics = new ArrayList<>();
        private int total;
        private int truePositives;
        private int falsePositives;
        private int trueNegatives;
        private int falseNegatives;
    }

    public static class EvaluationResult {

        private final int recordsEvaluated;
        private final int truePositives;
        private final int falsePositives;
        private final int trueNegatives;
        private final int falseNegatives;

        private final List<DnsQuery> missedRecords;
        private final List<DnsQuery> falseAlarmRecords;

        private final int episodesEvaluated;
        private final int episodeTruePositives;
        private final int episodeFalsePositives;
        private final int episodeTrueNegatives;
        private final int episodeFalseNegatives;
        private final Map<String, RulePerformanceStats> ruleStats;
        private final List<EpisodeDiagnostic> episodeDiagnostics;

        public EvaluationResult(
                int recordsEvaluated,
                int truePositives,
                int falsePositives,
                int trueNegatives,
                int falseNegatives) {

            this(
                    recordsEvaluated,
                    truePositives,
                    falsePositives,
                    trueNegatives,
                    falseNegatives,
                    Collections.emptyList(),
                    Collections.emptyList(),
                    0, 0, 0, 0, 0,
                    Collections.emptyMap(),
                    Collections.emptyList()
            );
        }

        private EvaluationResult(
                int recordsEvaluated,
                int truePositives,
                int falsePositives,
                int trueNegatives,
                int falseNegatives,
                List<DnsQuery> missedRecords,
                List<DnsQuery> falseAlarmRecords,
                int episodesEvaluated,
                int episodeTruePositives,
                int episodeFalsePositives,
                int episodeTrueNegatives,
                int episodeFalseNegatives,
                Map<String, RulePerformanceStats> ruleStats,
                List<EpisodeDiagnostic> episodeDiagnostics) {

            this.recordsEvaluated = recordsEvaluated;
            this.truePositives = truePositives;
            this.falsePositives = falsePositives;
            this.trueNegatives = trueNegatives;
            this.falseNegatives = falseNegatives;

            this.missedRecords = new ArrayList<>(missedRecords);
            this.falseAlarmRecords = new ArrayList<>(falseAlarmRecords);

            this.episodesEvaluated = episodesEvaluated;
            this.episodeTruePositives = episodeTruePositives;
            this.episodeFalsePositives = episodeFalsePositives;
            this.episodeTrueNegatives = episodeTrueNegatives;
            this.episodeFalseNegatives = episodeFalseNegatives;
            Map<String, RulePerformanceStats> copy = new LinkedHashMap<>();
            for (Map.Entry<String, RulePerformanceStats> entry
                    : ruleStats.entrySet()) {
                RulePerformanceStats original = entry.getValue();
                RulePerformanceStats stats =
                        new RulePerformanceStats(original.getRuleId());
                for (int i = 0; i < original.getSuspiciousTriggers(); i++) {
                    stats.recordTrigger(true);
                }
                for (int i = 0; i < original.getNormalTriggers(); i++) {
                    stats.recordTrigger(false);
                }
                copy.put(entry.getKey(), stats);
            }
            this.ruleStats = Collections.unmodifiableMap(copy);
            this.episodeDiagnostics = Collections.unmodifiableList(
                    new ArrayList<>(episodeDiagnostics));
        }

        public List<EpisodeDiagnostic> getEpisodeDiagnostics() {
            return episodeDiagnostics;
        }

        public Map<String, RulePerformanceStats> getRuleStats() {
            return ruleStats;
        }

        public int getRecordsEvaluated() {
            return recordsEvaluated;
        }

        public int getTruePositives() {
            return truePositives;
        }

        public int getFalsePositives() {
            return falsePositives;
        }

        public int getTrueNegatives() {
            return trueNegatives;
        }

        public int getFalseNegatives() {
            return falseNegatives;
        }

        public List<DnsQuery> getMissedRecords() {
            return Collections.unmodifiableList(missedRecords);
        }

        public List<DnsQuery> getFalseAlarmRecords() {
            return Collections.unmodifiableList(falseAlarmRecords);
        }

        public double getPrecision() {
            return ratio(truePositives, truePositives + falsePositives);
        }

        public double getRecall() {
            return ratio(truePositives, truePositives + falseNegatives);
        }

        public double getFalsePositiveRate() {
            return ratio(falsePositives, falsePositives + trueNegatives);
        }

        public double getDetectionRate() {
            return getRecall();
        }

        public int getEpisodesEvaluated() {
            return episodesEvaluated;
        }

        public int getEpisodeTruePositives() {
            return episodeTruePositives;
        }

        public int getEpisodeFalsePositives() {
            return episodeFalsePositives;
        }

        public int getEpisodeTrueNegatives() {
            return episodeTrueNegatives;
        }

        public int getEpisodeFalseNegatives() {
            return episodeFalseNegatives;
        }

        public double getEpisodePrecision() {
            return ratio(
                    episodeTruePositives,
                    episodeTruePositives + episodeFalsePositives);
        }

        public double getEpisodeRecall() {
            return ratio(
                    episodeTruePositives,
                    episodeTruePositives + episodeFalseNegatives);
        }

        public double getEpisodeFalsePositiveRate() {
            return ratio(
                    episodeFalsePositives,
                    episodeFalsePositives + episodeTrueNegatives);
        }

        private double ratio(int numerator, int denominator) {
            return denominator == 0
                    ? 0.0
                    : (double) numerator / denominator;
        }

        private void printRecords(
                String heading,
                List<DnsQuery> records) {

            System.out.println();
            System.out.println(heading);

            if (records.isEmpty()) {
                System.out.println("None");
                return;
            }

            for (int i = 0; i < records.size(); i++) {
                DnsQuery query = records.get(i);

                System.out.println((i + 1) + ". "
                        + "Timestamp: " + query.getTimestamp()
                        + " | Source IP: " + query.getSourceIp()
                        + " | Domain: " + query.getDomain()
                        + " | Type: " + query.getRecordType()
                        + " | Response: " + query.getResponseCode());
            }
        }

        public void printReport() {
            System.out.println();
            System.out.println("==============================================");
            System.out.println("          DNSGuard DATASET EVALUATION");
            System.out.println("==============================================");
            System.out.println("Records evaluated : " + recordsEvaluated);
            System.out.println("True positives    : " + truePositives);
            System.out.println("False positives   : " + falsePositives);
            System.out.println("True negatives    : " + trueNegatives);
            System.out.println("False negatives   : " + falseNegatives);

            System.out.printf(Locale.ROOT,
                    "Precision         : %.2f%%%n",
                    getPrecision() * 100);

            System.out.printf(Locale.ROOT,
                    "Recall            : %.2f%%%n",
                    getRecall() * 100);

            System.out.printf(Locale.ROOT,
                    "False-positive rate: %.2f%%%n",
                    getFalsePositiveRate() * 100);

            System.out.printf(Locale.ROOT,
                    "Detection rate    : %.2f%%%n",
                    getDetectionRate() * 100);

            System.out.println("----------------------------------------------");
            System.out.println("SEQUENCE-LEVEL EVALUATION");
            System.out.println("----------------------------------------------");
            System.out.println("Episodes evaluated: " + episodesEvaluated);
            System.out.println("Episode TP        : " + episodeTruePositives);
            System.out.println("Episode FP        : " + episodeFalsePositives);
            System.out.println("Episode TN        : " + episodeTrueNegatives);
            System.out.println("Episode FN        : " + episodeFalseNegatives);

            System.out.printf(Locale.ROOT,
                    "Episode precision : %.2f%%%n",
                    getEpisodePrecision() * 100);

            System.out.printf(Locale.ROOT,
                    "Episode recall    : %.2f%%%n",
                    getEpisodeRecall() * 100);

            System.out.printf(Locale.ROOT,
                    "Episode FP rate   : %.2f%%%n",
                    getEpisodeFalsePositiveRate() * 100);

            System.out.println("----------------------------------------------");
            System.out.println("EPISODE DIAGNOSTICS");
            System.out.println("----------------------------------------------");

            if (episodeDiagnostics.isEmpty()) {
                System.out.println("No episode diagnostics available.");
            } else {
                for (int i = 0; i < episodeDiagnostics.size(); i++) {
                    EpisodeDiagnostic episode = episodeDiagnostics.get(i);

                    System.out.println((i + 1) + ". Source IP: "
                            + episode.getSourceIp()
                            + " | Domain: " + episode.getDomain()
                            + " | Type: " + episode.getRecordType());
                    System.out.println("   Label           : "
                            + (episode.isActualSuspicious()
                            ? "SUSPICIOUS" : "NORMAL"));
                    System.out.println("   Total queries   : "
                            + episode.getQueryCount());
                    System.out.println("   Detected queries: "
                            + episode.getDetectedQueryCount());
                    System.out.println("   Missed queries  : "
                            + episode.getMissedQueryCount());
                    System.out.println("   Episode status  : "
                            + (episode.isDetected()
                            ? "DETECTED" : "NOT DETECTED"));
                    System.out.println("   First timestamp : "
                            + episode.getFirstTimestamp());
                    System.out.println("   Last timestamp  : "
                            + episode.getLastTimestamp());
                }
            }

            System.out.println("----------------------------------------------");
            System.out.println("RULE-LEVEL PERFORMANCE");
            System.out.println("----------------------------------------------");
            System.out.printf(
                    "%-25s %8s %12s %10s %12s%n",
                    "Rule ID", "Total", "Suspicious", "Normal",
                    "Suspicious %");

            for (RulePerformanceStats stats : ruleStats.values()) {
                System.out.printf(
                        Locale.ROOT,
                        "%-25s %8d %12d %10d %11.2f%%%n",
                        stats.getRuleId(),
                        stats.getTotalTriggers(),
                        stats.getSuspiciousTriggers(),
                        stats.getNormalTriggers(),
                        stats.getSuspiciousTriggerRate() * 100);
            }

            System.out.println(
                    "Suspicious % = suspicious-record triggers / all triggers.");
            System.out.println(
                    "This is descriptive, not per-rule recall or accuracy.");
            System.out.println("==============================================");

            printRecords(
                    "MISSED SUSPICIOUS RECORDS (FALSE NEGATIVES)",
                    missedRecords);

            printRecords(
                    "NORMAL RECORDS INCORRECTLY FLAGGED (FALSE POSITIVES)",
                    falseAlarmRecords);

            System.out.println();
            System.out.println(
                    "Results apply to this labeled dataset only.");
            System.out.println(
                    "Episodes group matching source IP, domain, "
                            + "record type, and label within the time window.");
        }
    }
}
