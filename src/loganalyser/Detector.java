package loganalyser;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Applies simple detection rules to the parsed login events:
 *
 *   1. Brute-force     : many failed logins from one IP within a short time window
 *   2. Username guessing: one IP trying many different usernames
 *   3. Possible break-in: an IP with many failures that then logs in successfully
 */
public class Detector {

    private final int failureThreshold;   // failures needed to call it brute-force
    private final Duration window;         // ...within this much time
    private final int usernameThreshold;  // distinct usernames needed to call it guessing

    public Detector(int failureThreshold, Duration window, int usernameThreshold) {
        this.failureThreshold = failureThreshold;
        this.window = window;
        this.usernameThreshold = usernameThreshold;
    }

    public List<Alert> detect(List<LoginEvent> events) {
        // Group events by IP, keeping log order (which is time order).
        Map<String, List<LoginEvent>> byIp = new LinkedHashMap<>();
        for (LoginEvent e : events) {
            byIp.computeIfAbsent(e.getIp(), k -> new ArrayList<>()).add(e);
        }

        List<Alert> alerts = new ArrayList<>();
        for (Map.Entry<String, List<LoginEvent>> entry : byIp.entrySet()) {
            String ip = entry.getKey();
            List<LoginEvent> ipEvents = entry.getValue();
            checkBruteForce(ip, ipEvents, alerts);
            checkUsernameGuessing(ip, ipEvents, alerts);
            checkBreakIn(ip, ipEvents, alerts);
        }

        alerts.sort(Comparator.comparing(Alert::getSeverity));
        return alerts;
    }

    /** Rule 1: find the busiest time window for this IP using a sliding window. */
    private void checkBruteForce(String ip, List<LoginEvent> ipEvents, List<Alert> alerts) {
        List<LoginEvent> failures = new ArrayList<>();
        for (LoginEvent e : ipEvents) {
            if (!e.isSuccess()) {
                failures.add(e);
            }
        }

        int maxInWindow = 0;
        int start = 0;
        for (int end = 0; end < failures.size(); end++) {
            // Move the start forward until start..end fits inside the window.
            while (Duration.between(failures.get(start).getTime(), failures.get(end).getTime())
                    .compareTo(window) > 0) {
                start++;
            }
            maxInWindow = Math.max(maxInWindow, end - start + 1);
        }

        if (maxInWindow >= failureThreshold) {
            alerts.add(new Alert(Alert.Severity.HIGH, ip, "Brute-force", String.format(
                    "Brute-force: %d failed logins in total, up to %d within %d seconds",
                    failures.size(), maxInWindow, window.getSeconds())));
        }
    }

    /** Rule 2: one IP trying lots of different usernames. */
    private void checkUsernameGuessing(String ip, List<LoginEvent> ipEvents, List<Alert> alerts) {
        Set<String> users = new HashSet<>();
        for (LoginEvent e : ipEvents) {
            if (!e.isSuccess()) {
                users.add(e.getUser());
            }
        }

        if (users.size() >= usernameThreshold) {
            alerts.add(new Alert(Alert.Severity.MEDIUM, ip, "Username guessing", String.format(
                    "Username guessing: tried %d different usernames %s",
                    users.size(), preview(users))));
        }
    }

    /** Rule 3: a successful login that came after many failures from the same IP. */
    private void checkBreakIn(String ip, List<LoginEvent> ipEvents, List<Alert> alerts) {
        int failuresSoFar = 0;
        Set<String> alreadyReported = new HashSet<>();

        for (LoginEvent e : ipEvents) {
            if (!e.isSuccess()) {
                failuresSoFar++;
            } else if (failuresSoFar >= failureThreshold && alreadyReported.add(e.getUser())) {
                alerts.add(new Alert(Alert.Severity.CRITICAL, ip, "Possible break-in", String.format(
                        "Possible break-in: %d failed logins, then SUCCESSFUL login as '%s' at %s",
                        failuresSoFar, e.getUser(), e.getTime())));
            }
        }
    }

    /** Shows up to 5 usernames, e.g. "(admin, oracle, test, ...)". */
    private static String preview(Set<String> users) {
        List<String> sorted = new ArrayList<>(users);
        sorted.sort(null);
        if (sorted.size() <= 5) {
            return "(" + String.join(", ", sorted) + ")";
        }
        return "(" + String.join(", ", sorted.subList(0, 5)) + ", ...)";
    }
}
