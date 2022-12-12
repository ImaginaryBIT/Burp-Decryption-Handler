package burp;

import java.io.PrintWriter;
import java.util.List;
import java.io.File;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class BurpExtender implements burp.IBurpExtender, burp.IHttpListener
{
    private burp.IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private Boolean DEBUG = Boolean.TRUE;
    private String key_path_unix= "/tmp/keys/private-key.pk8";
    private String key_path_win= "c:\\private-key.pk8";
    private String key_path;
    private String resbody;

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
        stdout.println("-----Created by JPMC Pentest Team-------");
        stdout.println("-----Author: Xiaogeng Chen-------");
        if(DEBUG){
            stdout.println("DEBUG: Check if private key is exist");
            File file1 = new File(key_path_unix);
            File file2 = new File(key_path_win);

            // Check if the linux file exists
            if (file1.exists()) {
                key_path = key_path_unix;
                stdout.println("File exists: " + key_path);
            } else if (file2.exists()) {
                    key_path = key_path_win;
                    stdout.println("File exists: " + key_path);
            }else{
                    stdout.println("File does not exist: " + key_path);
            }
        }
    }

    public String decryptWithRSA(String textToDecrypt, String charset, String privateKeyPath) throws Exception {

        if(DEBUG){
            stdout.println("DEBUG: decryptWithRSA ");
            stdout.println("DEBUG: textToDecrypt= " + textToDecrypt);
            stdout.println("DEBUG: charset= " + charset);
            stdout.println("DEBUG: privateKeyPath= " + privateKeyPath);
        }

        PrivateKey key = getPrivateKeyFromPKCS8(Constants.ALGO_RSA, privateKeyPath);
        return decrypt(Constants.ALGO_RSA, textToDecrypt, key, charset, null);
    }

    private byte[] read(ByteArrayInputStream byteArrayInputStream) throws IOException {

        if(DEBUG){stdout.println("DEBUG: read");};
        Reader reader = new InputStreamReader(byteArrayInputStream);
        StringWriter writer = new StringWriter();
        char[] buffer = new char[2048];
        while (true) {
            int amount = reader.read(buffer);
            if (amount >= 0) {
                writer.write(buffer, 0, amount);
            } else {
                return writer.toString().getBytes();
            }
        }
    }

    public PrivateKey encodePrivateKey(String privateKey, String algorithm) throws Exception {
        if(DEBUG){stdout.println("DEBUG: encodePrivateKey");};
        
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(privateKey.replace(Constants.PRIVATE_KEY_STRING_START, "").replace(Constants.PRIVATE_KEY_STRING_END, "").getBytes());
        if (byteArrayInputStream == null || algorithm == null || algorithm.equalsIgnoreCase("")) {
            return null;
        }
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        byte[] encodeKey = read(byteArrayInputStream);
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(encodeKey)));
    }

    public PrivateKey getPrivateKeyFromPKCS8(String algorithm, String privateKeyPath) throws Exception {

        String key = new String(Files.readAllBytes(Paths.get(privateKeyPath)), "UTF-8");

        String privateKey = key
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replaceAll("\\r\\n", "")
        .replaceAll("\n", "")
        .replace("-----END PRIVATE KEY-----", "");

        if(DEBUG){stdout.println("DEBUG: privateKey= " + privateKey);};

        return encodePrivateKey(privateKey, algorithm);
    }

    
    public String decrypt(String algorithm, String textToDecrypt, Key key, String charset, byte[] iv) throws Exception {
        Cipher cipher;
        byte[] textToDecryptBytes = Base64.getMimeDecoder().decode(textToDecrypt);
        if(DEBUG){stdout.println("DEBUG: decrypt");};

        if (algorithm.equalsIgnoreCase(Constants.ALGO_RSA)) {
            cipher = Cipher.getInstance(Constants.ALGO_RSA_INSTANCE);
            cipher.init(2, key, new OAEPParameterSpec("SHA-256", Constants.ALGO_RSA_MASK, MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
            if(DEBUG){stdout.println("DEBUG: ALGO_RSA_INSTANCE");};
        } else if (algorithm.equalsIgnoreCase(Constants.ALGO_AES)) {
            cipher = Cipher.getInstance(Constants.ALGO_AES_INSTANCE);
            cipher.init(2, key, new GCMParameterSpec(128, iv));
            if(DEBUG){stdout.println("DEBUG: ALGO_AES_INSTANCE");};
        } else {
            cipher = Cipher.getInstance(algorithm);
            cipher.init(2, key);
            if(DEBUG){stdout.println("DEBUG: algorithm");};
        }

        if(DEBUG){stdout.println("DEBUG: decrypt finished" + new String(cipher.doFinal(textToDecryptBytes), charset));};

        
        return new String(cipher.doFinal(textToDecryptBytes), charset);
    }

    public String decryptWithAES(String textToDecrypt, String charset, SecretKey key, byte[] iv) throws Exception {
        if(DEBUG){stdout.println("DEBUG: decryptWithAES");};
        return decrypt(Constants.ALGO_AES, textToDecrypt, key, charset, iv);
    }

    public byte[] detachIV(String decryptedKey) {

        if(DEBUG){stdout.println("DEBUG: detachIV");};

        byte[] iv = null;
        String[] tokens = decryptedKey.split("\\|");
        if (tokens.length > 1) {
            iv = Base64.getDecoder().decode(tokens[0]);
        }
        return iv;
    }

    public byte[] detachSecretKeyAES(String decryptedKey) {
        if(DEBUG){stdout.println("DEBUG: detachSecretKeyAES");};
        byte[] decodedKey = null;
        String[] tokens = decryptedKey.split("\\|");
        if (tokens.length > 1) {
            decodedKey = Base64.getDecoder().decode(tokens[1]);
        }
        return decodedKey;
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
            resbody = response.substring(iResponse.getBodyOffset());
            List<String> headers = iResponse.getHeaders();
            if(DEBUG){stdout.println("DEBUG: headers[0]= " + headers.toArray()[0]);}

            //check for sufficient response

            //if(DEBUG){stdout.println("DEBUG: response= " + response);}

            // capture the secret key in the response
            String secretStartMatch = "\",\"secret\":\"";
            String secretEndMatch = "\"}},\"signature\":\"";

            int secretStartIndex = response.indexOf(secretStartMatch) + secretStartMatch.length();
            int secretEndIndex = response.indexOf(secretEndMatch, secretStartIndex+1);

            String encryptedSecretKeyRaw = response.substring(secretStartIndex, secretEndIndex);
            String encryptedSecretKey = encryptedSecretKeyRaw.replaceAll("\\\r\\\n", "").replaceAll("\\r\\n", "").replaceAll("\r\n", "");

            if(DEBUG){stdout.println("DEBUG: encryptedSecretKey= " + encryptedSecretKey);}

            // capture the data in the response

            String dataStartMatch = "\"body\":{\"data\":\"";
            String dataEndMatch = "\",\"secret\":\"";

            int dataStartIndex = response.indexOf(dataStartMatch) + dataStartMatch.length();
            int dataEndIndex = response.indexOf(dataEndMatch, dataStartIndex+1);

            String encryptedDataRaw = response.substring(dataStartIndex, dataEndIndex);
            String encryptedData = encryptedDataRaw.replaceAll("\\\r\\\n", "").replaceAll("\\r\\n", "").replaceAll("\r\n", "");

            if(DEBUG){stdout.println("DEBUG: encryptedData= " + encryptedData);}

            try {
                
                // decrypt the secret key using private key

                if(DEBUG){stdout.println("DEBUG: key_path= " + key_path);}

                String decryptedKey = decryptWithRSA(encryptedSecretKey, "UTF-8", key_path);
                if(DEBUG){stdout.println("DEBUG: decryptedKey= " + decryptedKey);}
                byte[] iv = detachIV(decryptedKey);
                byte[] decodedKey = detachSecretKeyAES(decryptedKey);

                // decrypt the data using decrypted secret key
                SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, Constants.ALGO_AES);
                String decryptedBody = decryptWithAES(encryptedData, "UTF-8", key, iv);
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