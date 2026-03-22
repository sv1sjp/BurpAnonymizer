package burp;

import java.util.List;

/**
 * Burp Suite Extender API - IResponseInfo interface.
 */
public interface IResponseInfo {
    List<String> getHeaders();
    int getBodyOffset();
    short getStatusCode();
    List<ICookie> getCookies();
    String getStatedMimeType();
    String getInferredMimeType();
}
