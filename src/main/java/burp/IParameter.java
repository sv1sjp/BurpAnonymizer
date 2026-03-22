package burp;

/**
 * Burp Suite Extender API - IParameter interface.
 */
public interface IParameter {
    static final byte PARAM_URL = 0;
    static final byte PARAM_BODY = 1;
    static final byte PARAM_COOKIE = 2;
    static final byte PARAM_XML = 3;
    static final byte PARAM_XML_ATTR = 4;
    static final byte PARAM_MULTIPART_ATTR = 5;
    static final byte PARAM_JSON = 6;

    byte getType();
    String getName();
    String getValue();
    int getNameStart();
    int getNameEnd();
    int getValueStart();
    int getValueEnd();
}
