package burp;

/**
 * Burp Suite Extender API - IHttpRequestResponse interface.
 */
public interface IHttpRequestResponse {
    byte[] getRequest();
    byte[] getResponse();
    String getComment();
    String getHighlight();
    IHttpService getHttpService();
    void setRequest(byte[] message);
    void setResponse(byte[] message);
    void setComment(String comment);
    void setHighlight(String color);
    void setHttpService(IHttpService httpService);
}
