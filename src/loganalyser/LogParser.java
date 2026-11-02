package loganalyser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.Year;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads an SSH auth log and turns the interesting lines into LoginEvent objects.
 * All other lines (cron jobs, sudo, disconnects, ...) are ignored.
 */
public class LogParser {

    // "Failed password for root from 203.0.113.45 port 52314 ssh2"
    // "Failed password for invalid user admin from 203.0.113.45 port 52314 ssh2"
    // The username part is greedy (.*) on purpose: an attacker can pick a username like
    // "x from 1.2.3.4 port 1", but sshd always writes the real IP last, so we take the last match.
    private static final Pattern FAILED = Pattern.compile(
            "Failed (?:password|publickey) for (invalid user )?(.*) from (\\S+) port \\d+");

    // "Accepted password for ubuntu from 192.0.2.77 port 61002 ssh2"
    private static final Pattern ACCEPTED = Pattern.compile(
            "Accepted (?:password|publickey) for (.*) from (\\S+) port \\d+");

    // syslog shortens repeated lines: "message repeated 3 times: [ Failed password for root ... ]"
    private static final Pattern REPEATED = Pattern.compile("message repeated (\\d+) times");

    // Older systems:  "Nov  2 03:14:07 server sshd[...]"  (no year!)
    private static final Pattern CLASSIC_TIME = Pattern.compile(
            "^([A-Z][a-z]{2})\\s+(\\d{1,2}) (\\d{2}:\\d{2}:\\d{2})");
    private static final DateTimeFormatter CLASSIC_FORMAT =
            DateTimeFormatter.ofPattern("yyyy MMM d HH:mm:ss", Locale.ENGLISH);

    // Newer systems (e.g. Ubuntu 24.04): "2026-11-02T03:14:07.123456+00:00 server sshd[...]"
    private static final Pattern ISO_TIME = Pattern.compile(
            "^(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})");

    private int totalLines = 0;

    public List<LoginEvent> parse(Path file) throws IOException {
        List<LoginEvent> events = new ArrayList<>();
        // InputStreamReader replaces bad bytes instead of crashing
        // (attackers sometimes send strange characters as usernames).
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(Files.newInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                totalLines++;
                parseLine(line, events);
            }
        }
        return events;
    }

    public int getTotalLines() {
        return totalLines;
    }

    private void parseLine(String line, List<LoginEvent> events) {
        LocalDateTime time = parseTime(line);
        if (time == null) {
            return;
        }

        int repeat = 1;
        Matcher r = REPEATED.matcher(line);
        if (r.find()) {
            repeat = Integer.parseInt(r.group(1));
        }

        Matcher m = FAILED.matcher(line);
        if (m.find()) {
            boolean invalidUser = m.group(1) != null;
            for (int i = 0; i < repeat; i++) {
                events.add(new LoginEvent(time, m.group(2), m.group(3), false, invalidUser));
            }
            return;
        }

        m = ACCEPTED.matcher(line);
        if (m.find()) {
            for (int i = 0; i < repeat; i++) {
                events.add(new LoginEvent(time, m.group(1), m.group(2), true, false));
            }
        }
    }

    private LocalDateTime parseTime(String line) {
        try {
            Matcher iso = ISO_TIME.matcher(line);
            if (iso.find()) {
                return LocalDateTime.parse(iso.group(1));
            }

            Matcher classic = CLASSIC_TIME.matcher(line);
            if (classic.find()) {
                // Classic syslog has no year, so assume the current one.
                int year = Year.now().getValue();
                String text = year + " " + classic.group(1) + " " + classic.group(2) + " " + classic.group(3);
                LocalDateTime time = LocalDateTime.parse(text, CLASSIC_FORMAT);
                // A December log read in January would land in the future: use last year instead.
                if (time.isAfter(LocalDateTime.now().plusDays(1))) {
                    time = time.minusYears(1);
                }
                return time;
            }
        } catch (DateTimeParseException e) {
            // Unreadable timestamp: skip the line.
        }
        return null;
    }
}
