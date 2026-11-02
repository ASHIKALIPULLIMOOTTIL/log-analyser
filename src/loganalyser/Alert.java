package loganalyser;

/** A suspicious finding produced by the Detector. */
public class Alert {

    /** Ordered from most to least serious. */
    public enum Severity { CRITICAL, HIGH, MEDIUM }

    private final Severity severity;
    private final String ip;
    private final String type;      // short name, e.g. "Brute-force"
    private final String message;   // full details for the report

    public Alert(Severity severity, String ip, String type, String message) {
        this.severity = severity;
        this.ip = ip;
        this.type = type;
        this.message = message;
    }

    public Severity getSeverity() { return severity; }
    public String getIp()         { return ip; }
    public String getType()       { return type; }
    public String getMessage()    { return message; }
}
