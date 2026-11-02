package loganalyser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * Interactive checklist shown after the report:
 *
 *   [x] 1. 203.0.113.45     HIGH      Brute-force
 *   [ ] 2. 198.51.100.23    MEDIUM    Username guessing
 *
 * The user types numbers to check/uncheck, then y to block or n to cancel.
 */
public class BlockMenu {

    private final Blocker blocker;
    private final BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

    public BlockMenu(Blocker blocker) {
        this.blocker = blocker;
    }

    public void run(List<Blocker.Candidate> candidates) throws IOException, InterruptedException {
        System.out.println();
        System.out.println("BLOCK SUSPICIOUS IPs");
        for (String s : blocker.getSkipped()) {
            System.out.println("  Not offered: " + s);
        }
        if (candidates.isEmpty()) {
            System.out.println("  No IPs to block.");
            return;
        }

        while (true) {
            printList(candidates);
            System.out.print("Block the checked [x] IPs?  y = yes, n = no, "
                    + "or type numbers to check/uncheck (e.g. 2 or 1,3): ");
            System.out.flush();

            String input = in.readLine();
            if (input == null) {   // Ctrl+D or no terminal
                System.out.println();
                System.out.println("No input. Nothing was blocked.");
                return;
            }
            input = input.trim().toLowerCase();

            if (input.equals("y") || input.equals("yes")) {
                break;
            }
            if (input.equals("n") || input.equals("no")) {
                System.out.println("Cancelled. Nothing was blocked.");
                return;
            }
            toggle(input, candidates);
        }

        List<String> chosen = new ArrayList<>();
        for (Blocker.Candidate c : candidates) {
            if (c.isChecked()) {
                chosen.add(c.getIp());
            }
        }
        if (chosen.isEmpty()) {
            System.out.println("No IPs are checked. Nothing was blocked.");
            return;
        }

        blockAll(chosen);
    }

    private void printList(List<Blocker.Candidate> candidates) {
        System.out.println();
        for (int i = 0; i < candidates.size(); i++) {
            Blocker.Candidate c = candidates.get(i);
            System.out.printf("  [%s] %d. %-16s %-9s %s%n",
                    c.isChecked() ? "x" : " ", i + 1, c.getIp(), c.getSeverity(),
                    String.join(", ", c.getReasons()));
        }
        System.out.println();
    }

    private void toggle(String input, List<Blocker.Candidate> candidates) {
        if (input.isEmpty()) {
            return;
        }
        for (String part : input.split("[,\\s]+")) {
            try {
                int n = Integer.parseInt(part);
                if (n >= 1 && n <= candidates.size()) {
                    candidates.get(n - 1).toggle();
                } else {
                    System.out.println("  No IP number " + n + " in the list.");
                }
            } catch (NumberFormatException e) {
                System.out.println("  Didn't understand '" + part + "'. Type y, n, or numbers.");
            }
        }
    }

    private void blockAll(List<String> ips) throws InterruptedException {
        System.out.println();
        if (blocker.needsSudo()) {
            System.out.println("Blocking needs administrator rights. You may be asked for your password.");
        }

        List<String> blocked = new ArrayList<>();
        for (String ip : ips) {
            try {
                if (blocker.block(ip)) {
                    System.out.println("  Blocked " + ip);
                    blocked.add(ip);
                } else {
                    System.out.println("  FAILED to block " + ip);
                }
            } catch (IOException e) {
                // The firewall program (or sudo) isn't installed.
                System.out.println("  Could not run the firewall command: " + e.getMessage());
                System.out.println("  Install ufw (sudo apt install ufw) or use --firewall iptables.");
                break;
            }
        }

        if (!blocked.isEmpty()) {
            System.out.println();
            System.out.println("Done. " + blocked.size() + " IP(s) blocked. To undo, run:");
            for (String ip : blocked) {
                System.out.println("  " + blocker.unblockCommand(ip));
            }
        }
    }
}
