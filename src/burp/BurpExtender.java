package burp;

import java.io.PrintWriter;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class BurpExtender implements burp.IBurpExtender, burp.IHttpListener
{
    private burp.IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private Boolean DEBUG = Boolean.TRUE;
    private SecurityUtils securityUtils;

    // implement IBurpExtender
    @Override
    public void registerExtenderCallbacks(burp.IBurpExtenderCallbacks callbacks)
    {
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(),true);

        // set our extension name
        callbacks.setExtensionName("RSA Decryption and AES decrpyion");

        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);

        stdout.println("-----     Plugin Loaded   -------");
        stdout.println("-----Author: Xiaogeng Chen-------");
    }

    // implement IHttpListener
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, burp.IHttpRequestResponse messageInfo)
    {

        String[] checks = new String[]{ "\"body\":{\"data\":\"",};

        // only process requests
        if (!messageIsRequest) {

            //get whole response
            String response = new String(messageInfo.getResponse());
            burp.IResponseInfo iResponse = helpers.analyzeResponse(messageInfo.getResponse());
            
            //get response header and body
            String resbody = response.substring(iResponse.getBodyOffset());
            List<String> headers = iResponse.getHeaders();
            if(DEBUG){stdout.println("DEBUG: headers[0]= " + headers.toArray()[0]);}

            //check for sufficient response
            for (String check: checks) {
                while (response.contains(check)) {

                    if(DEBUG){stdout.println("DEBUG: response= " + response);}

                    // capture the secret key in the response
                    String secretStartMatch = "\",\"secret\":\"";
                    String secretEndMatch = "\"}},\"signature\":\"";

                    int secretStartIndex = response.indexOf(secretStartMatch) + secretStartMatch.length();
                    int secretEndIndex = response.indexOf(secretEndMatch, secretStartIndex+1);

                    String encryptedSecretKey = response.substring(secretStartIndex, secretEndIndex);

                    if(DEBUG){stdout.println("DEBUG: encryptedSecretKey= " + encryptedSecretKey);}

                    // capture the data in the response

                    String dataStartMatch = "\"body\":{\"data\":\"";
                    String dataEndMatch = "\",\"secret\":\"";

                    int dataStartIndex = response.indexOf(dataStartMatch) + dataEndMatch.length();
                    int dataEndIndex = response.indexOf(dataEndMatch, dataStartIndex+1);

                    String encryptedData = response.substring(dataStartIndex, dataEndIndex);

                    if(DEBUG){stdout.println("DEBUG: encryptedData= " + encryptedData);}

                    try {
                        // decrypt the secret key using private key
                        String decryptedKey = this.securityUtils.decryptWithRSA(encryptedSecretKey, "UTF-8", "/privatekey/path");
                        byte[] iv = this.securityUtils.detachIV(decryptedKey);
                        byte[] decodedKey = this.securityUtils.detachSecretKeyAES(decryptedKey);

                        // decrypt the data using decrypted secret key
                        SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, Constants.ALGO_AES);
                        String decryptedBody = this.securityUtils.decryptWithAES(encryptedData, "UTF-8", key, iv);
                        if(DEBUG){stdout.println("DEBUG: decryptedBody= " + decryptedBody);}

                        //get the data
                        
                        resbody = resbody + decryptedBody;
                        byte[] message = helpers.buildHttpMessage(headers, resbody.getBytes());
                        messageInfo.setRequest(message);

                    } catch (Exception e) {
                    }

                }
            }
        }
    }
}
