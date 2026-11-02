package loganalyser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Picks which IPs can be blocked and runs the firewall commands that block them.
 *
 * Commands are started with ProcessBuilder using a list of arguments, not a shell,
 * so text from the log can never be run as a command.
 */
public class Blocker {

    public enum Firewall { UFW, IPTABLES }

    /** One IP offered for blocking in the menu. */
    public static class Candidate {
        private final String ip;
        private Alert.Severity severity;
        private final Set<String> reasons = new LinkedHashSet<>();
        private boolean checked;

        Candidate(String ip, Alert.Severity severity) {
            this.ip = ip;
            this.severity = severity;
        }

        public String getIp()                { return ip; }
        public Alert.Severity getSeverity()  { return severity; }
        public Set<String> getReasons()      { return reasons; }
        public boolean isChecked()           { return checked; }
        public void toggle()                 { checked = !checked; }
    }

    // 0-255 in each of the four parts, e.g. 203.0.113.45
    private static final Pattern IPV4 = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$");
    // Hex digits, colons and dots only (dots allow forms like ::ffff:192.0.2.1)
    private static final Pattern IPV6 = Pattern.compile("^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$");

    private final Firewall firewall;
    private final Set<String> allowList;
    private final Set<String> skipped = new LinkedHashSet<>();
    private final boolean needSudo = !"root".equals(System.getProperty("user.name"));

    public Blocker(Firewall firewall, Set<String> allowList) {
        this.firewall = firewall;
        this.allowList = allowList;
    }

    /**
     * One candidate per alerted IP, most serious first.
     * HIGH and CRITICAL start checked; MEDIUM starts unchecked.
     */
    public List<Candidate> candidates(List<Alert> alerts) {
        Map<String, Candidate> byIp = new LinkedHashMap<>();
        for (Alert a : alerts) {   // alerts are already sorted, most serious first
            String ip = a.getIp();
            if (allowList.contains(ip)) {
                skipped.add(ip + " (on allow list)");
                continue;
            }
            if (!isValidIp(ip)) {
                // The IP text comes from the log, which attackers can influence.
                skipped.add(ip + " (not a valid IP address)");
                continue;
            }
            Candidate c = byIp.get(ip);
            if (c == null) {
                c = new Candidate(ip, a.getSeverity());
                c.checked = a.getSeverity() != Alert.Severity.MEDIUM;
                byIp.put(ip, c);
            }
            c.reasons.add(a.getType());
        }
        return new ArrayList<>(byIp.values());
    }

    /** IPs that had alerts but were deliberately left out of the menu. */
    public List<String> getSkipped() {
        return new ArrayList<>(skipped);
    }

    public boolean needsSudo() {
        return needSudo;
    }

    /** Blocks one IP. Returns true on success. */
    public boolean block(String ip) throws IOException, InterruptedException {
        if (firewall == Firewall.UFW) {
            // "insert 1" puts the rule at the top, so it is checked before any "allow 22" rule.
            // It fails when ufw has no rules yet; then a normal deny is first anyway.
            return run("ufw", "insert", "1", "deny", "from", ip)
                    || run("ufw", "deny", "from", ip);
        }
        // -C checks whether the rule already exists, so blocking twice is harmless.
        if (runQuietly("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP")) {
            return true;
        }
        return run("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP");
    }

    public String unblockCommand(String ip) {
        if (firewall == Firewall.UFW) {
            return "sudo ufw delete deny from " + ip;
        }
        return "sudo iptables -D INPUT -s " + ip + " -j DROP";
    }

    private boolean run(String... command) throws IOException, InterruptedException {
        // inheritIO lets sudo ask for the password in this terminal.
        Process p = new ProcessBuilder(withSudo(command)).inheritIO().start();
        return p.waitFor() == 0;
    }

    private boolean runQuietly(String... command) throws IOException, InterruptedException {
        Process p = new ProcessBuilder(withSudo(command))
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .redirectInput(ProcessBuilder.Redirect.INHERIT)
                .start();
        return p.waitFor() == 0;
    }

    private List<String> withSudo(String... command) {
        List<String> full = new ArrayList<>();
        if (needSudo) {
            full.add("sudo");
        }
        full.addAll(Arrays.asList(command));
        return full;
    }

    static boolean isValidIp(String ip) {
        return IPV4.matcher(ip).matches() || IPV6.matcher(ip).matches();
    }
}
