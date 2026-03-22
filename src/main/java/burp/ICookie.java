package burp;

import java.util.Date;

/**
 * Burp Suite Extender API - ICookie interface.
 */
public interface ICookie {
    String getName();
    String getValue();
    String getDomain();
    String getPath();
    Date getExpiration();
}
