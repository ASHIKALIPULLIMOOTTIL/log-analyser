package loganalyser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Entry point. Prints the report, then offers to block the suspicious IPs.
 *
 * Usage:
 *   ./analyse.sh <logfile> [--threshold N] [--window SECONDS] [--users N]
 *                          [--firewall ufw|iptables] [--allow IP,IP] [--no-block]
 */
public class Main {

    public static void main(String[] args) {
        if (args.length < 1 || args[0].equals("--help")) {
            printUsage();
            System.exit(1);
        }

        Path file = Path.of(args[0]);
        int threshold = 5;        // failed logins that count as brute-force
        int windowSeconds = 60;   // ...within this many seconds
        int userThreshold = 5;    // distinct usernames that count as guessing
        boolean offerBlocking = true;
        Blocker.Firewall firewall = Blocker.Firewall.UFW;
        Set<String> allowList = new HashSet<>();

        try {
            for (int i = 1; i < args.length; i++) {
                switch (args[i]) {
                    case "--threshold": threshold = Integer.parseInt(args[++i]); break;
                    case "--window":    windowSeconds = Integer.parseInt(args[++i]); break;
                    case "--users":     userThreshold = Integer.parseInt(args[++i]); break;
                    case "--no-block":  offerBlocking = false; break;
                    case "--firewall":  firewall = parseFirewall(args[++i]); break;
                    case "--allow":
                        for (String ip : args[++i].split(",")) {
                            allowList.add(ip.trim());
                        }
                        break;
                    default:
                        System.err.println("Unknown option: " + args[i]);
                        printUsage();
                        System.exit(1);
                }
            }
        } catch (NumberFormatException e) {
            System.err.println("Options need a whole number after them, e.g. --threshold 10");
            System.exit(1);
        } catch (ArrayIndexOutOfBoundsException e) {
            System.err.println("Missing value after option " + args[args.length - 1]);
            System.exit(1);
        }

        if (!Files.isReadable(file)) {
            System.err.println("Cannot read file: " + file + "  (try sudo for /var/log/auth.log)");
            System.exit(1);
        }

        try {
            LogParser parser = new LogParser();
            List<LoginEvent> events = parser.parse(file);

            Detector detector = new Detector(threshold, Duration.ofSeconds(windowSeconds), userThreshold);
            List<Alert> alerts = detector.detect(events);

            new ReportPrinter().print(file, parser.getTotalLines(), events, alerts);

            if (offerBlocking && !alerts.isEmpty()) {
                addSafeIps(allowList);
                Blocker blocker = new Blocker(firewall, allowList);
                new BlockMenu(blocker).run(blocker.candidates(alerts));
            }
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Never offer to block localhost, or the IP you are connected from right now. */
    private static void addSafeIps(Set<String> allowList) {
        allowList.add("127.0.0.1");
        allowList.add("::1");
        // e.g. "203.0.113.5 51234 22". Note: sudo clears this variable, so prefer
        // running the tool without sudo (blocking asks for sudo by itself).
        String sshClient = System.getenv("SSH_CLIENT");
        if (sshClient != null && !sshClient.isBlank()) {
            allowList.add(sshClient.split(" ")[0]);
        }
    }

    private static Blocker.Firewall parseFirewall(String name) {
        switch (name.toLowerCase()) {
            case "ufw":      return Blocker.Firewall.UFW;
            case "iptables": return Blocker.Firewall.IPTABLES;
            default:
                System.err.println("Unknown firewall '" + name + "'. Use ufw or iptables.");
                System.exit(1);
                return null;
        }
    }

    private static void printUsage() {
        System.out.println("Usage: ./analyse.sh <logfile> [options]");
        System.out.println();
        System.out.println("Detection options:");
        System.out.println("  --threshold N       failed logins that count as brute-force (default 5)");
        System.out.println("  --window SECONDS    time window for the threshold (default 60)");
        System.out.println("  --users N           distinct usernames that count as guessing (default 5)");
        System.out.println();
        System.out.println("Blocking options:");
        System.out.println("  --firewall NAME     ufw (default) or iptables");
        System.out.println("  --allow IP,IP       IPs that must never be blocked");
        System.out.println("  --no-block          only show the report, don't offer to block");
    }
}
