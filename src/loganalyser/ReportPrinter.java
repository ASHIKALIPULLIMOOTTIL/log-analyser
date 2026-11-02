package loganalyser;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Prints the final analysis report to the terminal. */
public class ReportPrinter {

    private static final int TOP_N = 5;
    private static final String LINE = "=".repeat(60);

    public void print(Path file, int totalLines, List<LoginEvent> events, List<Alert> alerts) {
        Map<String, Integer> failuresByIp = new HashMap<>();
        Map<String, Integer> failuresByUser = new HashMap<>();
        List<LoginEvent> successes = new ArrayList<>();

        for (LoginEvent e : events) {
            if (e.isSuccess()) {
                successes.add(e);
            } else {
                failuresByIp.merge(e.getIp(), 1, Integer::sum);
                failuresByUser.merge(e.getUser(), 1, Integer::sum);
            }
        }
        int failedCount = events.size() - successes.size();

        System.out.println(LINE);
        System.out.println("  SSH LOG ANALYSIS REPORT");
        System.out.println(LINE);
        System.out.println("File analysed      : " + file);
        System.out.println("Total lines        : " + totalLines);
        System.out.println("Failed logins      : " + failedCount);
        System.out.println("Successful logins  : " + successes.size());
        System.out.println("Unique IPs seen    : " + countUniqueIps(events));

        System.out.println();
        System.out.println("Top attacking IPs (by failed logins):");
        printTop(failuresByIp);

        System.out.println();
        System.out.println("Most targeted usernames:");
        printTop(failuresByUser);

        System.out.println();
        System.out.println("Successful logins:");
        if (successes.isEmpty()) {
            System.out.println("  (none)");
        }
        for (LoginEvent e : successes) {
            System.out.printf("  %s  %-10s from %s%n", e.getTime(), e.getUser(), e.getIp());
        }

        System.out.println();
        System.out.println("ALERTS:");
        if (alerts.isEmpty()) {
            System.out.println("  No suspicious activity detected.");
        }
        for (Alert a : alerts) {
            System.out.printf("  [%-8s] %-16s %s%n", a.getSeverity(), a.getIp(), a.getMessage());
        }
        System.out.println(LINE);
    }

    private void printTop(Map<String, Integer> counts) {
        if (counts.isEmpty()) {
            System.out.println("  (none)");
            return;
        }
        counts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(TOP_N)
                .forEach(e -> System.out.printf("  %-18s %6d%n", e.getKey(), e.getValue()));
    }

    private long countUniqueIps(List<LoginEvent> events) {
        return events.stream().map(LoginEvent::getIp).distinct().count();
    }
}
