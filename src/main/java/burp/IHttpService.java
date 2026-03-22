package burp;

/**
 * Burp Suite Extender API - IHttpService interface.
 */
public interface IHttpService {
    String getHost();
    int getPort();
    String getProtocol();
}
