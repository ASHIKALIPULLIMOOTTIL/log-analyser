package loganalyser;

import java.time.LocalDateTime;

/**
 * One SSH login attempt pulled out of the log file.
 * Example source line:
 *   Nov  2 03:14:07 server sshd[1201]: Failed password for root from 203.0.113.45 port 52314 ssh2
 */
public class LoginEvent {

    private final LocalDateTime time;
    private final String user;
    private final String ip;
    private final boolean success;
    private final boolean invalidUser;   // true if the username does not exist on the server

    public LoginEvent(LocalDateTime time, String user, String ip, boolean success, boolean invalidUser) {
        this.time = time;
        this.user = user;
        this.ip = ip;
        this.success = success;
        this.invalidUser = invalidUser;
    }

    public LocalDateTime getTime()  { return time; }
    public String getUser()         { return user; }
    public String getIp()           { return ip; }
    public boolean isSuccess()      { return success; }
    public boolean isInvalidUser()  { return invalidUser; }
}
