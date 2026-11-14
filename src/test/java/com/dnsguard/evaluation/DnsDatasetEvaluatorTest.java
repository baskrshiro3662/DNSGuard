package com.dnsguard.evaluation;

import com.dnsguard.detector.DnsDetector;
import com.dnsguard.evaluation.DnsDatasetEvaluator.EvaluationResult;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class DnsDatasetEvaluatorTest {

    @TempDir
    Path tempDir;

    @Test
    void evaluatesLabeledDataset() throws IOException {
        Path dataset = tempDir.resolve("labeled.csv");

        Files.writeString(
                dataset,
                """
                timestamp,sourceIp,domain,recordType,responseCode,label
                2026-10-24T10:00:00Z,192.168.1.10,google.com,A,NOERROR,NORMAL
                2026-10-24T10:00:05Z,192.168.1.11,abcdefghijklmnopqrstuvwxyz1234567890.example.com,TXT,NOERROR,SUSPICIOUS
                """,
                StandardCharsets.UTF_8
        );

        DnsDetector detector = new DnsDetector(
                30,
                3.5,
                100,
                Duration.ofMinutes(1),
                100,
                100
        );

        DnsDatasetEvaluator evaluator = new DnsDatasetEvaluator();

        EvaluationResult result = evaluator.evaluate(dataset, detector);

        assertEquals(2, result.getRecordsEvaluated());
        assertEquals(1, result.getTruePositives());
        assertEquals(0, result.getFalsePositives());
        assertEquals(1, result.getTrueNegatives());
        assertEquals(0, result.getFalseNegatives());

        assertEquals(1.0, result.getPrecision(), 0.0001);
        assertEquals(1.0, result.getRecall(), 0.0001);
        assertEquals(0.0, result.getFalsePositiveRate(), 0.0001);
        assertEquals(1.0, result.getDetectionRate(), 0.0001);
    }

    @Test
    void rejectsUnknownLabels() throws IOException {
        Path dataset = tempDir.resolve("bad-label.csv");

        Files.writeString(
                dataset,
                """
                timestamp,sourceIp,domain,recordType,responseCode,label
                2026-10-24T10:00:00Z,192.168.1.10,google.com,A,NOERROR,UNKNOWN
                """,
                StandardCharsets.UTF_8
        );

        DnsDatasetEvaluator evaluator = new DnsDatasetEvaluator();
        DnsDetector detector = new DnsDetector(30);

        assertThrows(
                IOException.class,
                () -> evaluator.evaluate(dataset, detector)
        );
    }

    @Test
    void rejectsMissingDataset() {
        DnsDatasetEvaluator evaluator = new DnsDatasetEvaluator();
        DnsDetector detector = new DnsDetector(30);

        assertThrows(
                IOException.class,
                () -> evaluator.evaluate(
                        tempDir.resolve("missing.csv"),
                        detector
                )
        );
    }
@Test
void detectsRepeatedTxtSequenceAtEpisodeLevel() throws IOException {
    Path dataset = tempDir.resolve("repeated-txt.csv");

    Files.writeString(
            dataset,
            """
            timestamp,sourceIp,domain,recordType,responseCode,label
            2026-10-24T10:00:00Z,192.168.1.70,transfer.example.com,TXT,NOERROR,SUSPICIOUS
            2026-10-24T10:00:10Z,192.168.1.70,transfer.example.com,TXT,NOERROR,SUSPICIOUS
            2026-10-24T10:00:20Z,192.168.1.70,transfer.example.com,TXT,NOERROR,SUSPICIOUS
            2026-10-24T10:00:30Z,192.168.1.70,transfer.example.com,TXT,NOERROR,SUSPICIOUS
            """,
            StandardCharsets.UTF_8
    );

    DnsDetector detector = new DnsDetector(
            253,
            5.0,
            100,
            Duration.ofMinutes(1),
            100,
            100,
            3
    );

    DnsDatasetEvaluator evaluator = new DnsDatasetEvaluator();

    EvaluationResult result = evaluator.evaluate(
            dataset,
            detector,
            Duration.ofMinutes(1)
    );

    assertEquals(4, result.getRecordsEvaluated());
    assertEquals(1, result.getTruePositives());
    assertEquals(3, result.getFalseNegatives());

    assertEquals(1, result.getEpisodesEvaluated());
    assertEquals(1, result.getEpisodeTruePositives());
    assertEquals(0, result.getEpisodeFalsePositives());
    assertEquals(0, result.getEpisodeFalseNegatives());
    assertEquals(1.0, result.getEpisodeRecall(), 0.0001);
}

@Test
void reportsRuleLevelStatisticsForLabeledRecords() throws IOException {
    Path dataset = tempDir.resolve("rule-stats.csv");

    Files.writeString(
            dataset,
            """
            timestamp,sourceIp,domain,recordType,responseCode,label
            2026-10-24T10:00:00Z,192.168.1.10,google.com,A,NOERROR,NORMAL
            2026-10-24T10:00:05Z,192.168.1.11,abcdefghijklmnopqrstuvwxyz1234567890.example.com,TXT,NOERROR,SUSPICIOUS
            """,
            StandardCharsets.UTF_8
    );

    DnsDetector detector = new DnsDetector(
            30,
            3.5,
            100,
            Duration.ofMinutes(1),
            100,
            100,
            3
    );

    EvaluationResult result =
            new DnsDatasetEvaluator().evaluate(dataset, detector);

    assertEquals(2, result.getRecordsEvaluated());

    assertEquals(8, result.getRuleStats().size());

assertNotNull(
        result.getRuleStats().get(DnsDetector.RULE_REPEATED_NXDOMAIN)
);

    RulePerformanceStats longDomainStats =
            result.getRuleStats().get(DnsDetector.RULE_LONG_DOMAIN);

    assertNotNull(longDomainStats);
    assertEquals(1, longDomainStats.getTotalTriggers());
    assertEquals(1, longDomainStats.getSuspiciousTriggers());
    assertEquals(0, longDomainStats.getNormalTriggers());
    assertEquals(1.0, longDomainStats.getSuspiciousTriggerRate(), 0.0001);
}

@Test
void printsRuleLevelPerformanceSection() throws IOException {
    Path dataset = tempDir.resolve("rule-report.csv");

    Files.writeString(
            dataset,
            """
            timestamp,sourceIp,domain,recordType,responseCode,label
            2026-10-24T10:00:00Z,192.168.1.10,google.com,A,NOERROR,NORMAL
            """,
            StandardCharsets.UTF_8
    );

    DnsDatasetEvaluator evaluator = new DnsDatasetEvaluator();
    EvaluationResult result = evaluator.evaluate(
            dataset,
            new DnsDetector(30)
    );

    java.io.ByteArrayOutputStream output =
            new java.io.ByteArrayOutputStream();

    java.io.PrintStream originalOut = System.out;

    try (java.io.PrintStream capture =
                 new java.io.PrintStream(output, true,
                         StandardCharsets.UTF_8)) {
        System.setOut(capture);
        result.printReport();
    } finally {
        System.setOut(originalOut);
    }

    String report = output.toString(StandardCharsets.UTF_8);

    assertTrue(report.contains("RULE-LEVEL PERFORMANCE"));
    assertTrue(report.contains(DnsDetector.RULE_LONG_DOMAIN));
    assertTrue(report.contains(DnsDetector.RULE_HIGH_ENTROPY));
    assertTrue(report.contains(DnsDetector.RULE_REPEATED_TXT));
}

}

