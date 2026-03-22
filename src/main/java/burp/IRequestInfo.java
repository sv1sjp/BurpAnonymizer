package burp;

import java.util.List;

/**
 * Burp Suite Extender API - IRequestInfo interface.
 */
public interface IRequestInfo {
    String getMethod();
    java.net.URL getUrl();
    List<String> getHeaders();
    List<IParameter> getParameters();
    int getBodyOffset();
    byte getContentType();
    
    static final byte CONTENT_TYPE_NONE = 0;
    static final byte CONTENT_TYPE_URL_ENCODED = 1;
    static final byte CONTENT_TYPE_MULTIPART = 2;
    static final byte CONTENT_TYPE_XML = 3;
    static final byte CONTENT_TYPE_JSON = 4;
    static final byte CONTENT_TYPE_AMF = 5;
    static final byte CONTENT_TYPE_UNKNOWN = -1;
}
