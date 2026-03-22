package burp;

/**
 * Burp Suite Extender API - IExtensionHelpers interface.
 * Minimal interface for compilation.
 */
public interface IExtensionHelpers {
    IRequestInfo analyzeRequest(byte[] request);
    IRequestInfo analyzeRequest(IHttpService httpService, byte[] request);
    IResponseInfo analyzeResponse(byte[] response);
    byte[] buildHttpMessage(java.util.List<String> headers, byte[] body);
    byte[] stringToBytes(String data);
    String bytesToString(byte[] data);
    String urlDecode(String data);
    String urlEncode(String data);
    byte[] base64Decode(String data);
    String base64Encode(byte[] data);
}
