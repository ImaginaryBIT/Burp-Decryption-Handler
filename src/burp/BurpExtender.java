package burp;
// vim: et:ts=4:sts=4:sw=4:fileencoding=utf-8

import java.io.PrintWriter;
import java.util.List;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.text.DateFormat;
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
import java.nio.file.Paths;
import java.nio.file.Files;
import java.nio.file.LinkOption;
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
import org.springframework.core.io.Resource;
import org.springframework.core.io.ClassPathResource;

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
    public String ALGO_RSA = "RSA";
    public String ALGO_RSA_INSTANCE = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public String ALGO_RSA_DIGEST = "SHA-256";
    public String ALGO_RSA_MASK = "MGF1";
    public String ALGO_EC = "EC";
    public String SIGNATURE_ALGO_EC = "SHA256withECDSA";
    public String ALGO_AES = "AES";
    public String ALGO_AES_INSTANCE = "AES/GCM/NoPadding";
    public int AES_KEY_LENGTH = 256;
    public int AES_TAG_LENGTH = 128;
    public int AES_IV_LENGTH_96 = 96;
    public int AES_IV_LENGTH_12 = 12;
    public String SIGNATURE = "SHA256withRSA";
    public String PUBLIC_KEY_STRING_START = "-----BEGIN PUBLIC KEY-----";
    public String PUBLIC_KEY_STRING_END = "-----END PUBLIC KEY-----";
    public String PRIVATE_KEY_STRING_START = "-----BEGIN PRIVATE KEY-----";
    public String PRIVATE_KEY_STRING_END = "-----END PRIVATE KEY-----";
    public String HASHICORP_ROLE_ID = "HASHICORP_ROLE_ID";
    public String HASHICORP_SECRET_ID = "HASHICORP_SECRET_ID";
    public String HASHICORP_TOKEN = "HASHICORP_TOKEN";
    public String HASHICORP_CLIENT_KEYSTORE_PWD = "HASHICORP_CLIENT_KEYSTORE_PWD";
    public String HASHICORP_CLIENT_TRUSTSTORE_PWD = "HASHICORP_CLIENT_TRUSTSTORE_PWD";
    public String HASHICORP_KEY_PREFIX = "vault:v1:";
    public String HASHICORP_TRANSITE_SIGN_PATH = "transit/sign/";
    public String HASHICORP_TRANSITE_VERIFY_PATH = "transit/verify/";
    public String HASHICORP_TRANSITE_ENCRYPT_PATH = "transit/encrypt/";
    public String HASHICORP_TRANSITE_DECRYPT_PATH = "transit/decrypt/";
    public String HASHICORP_SECRET_SIGN_PATH = "secret/sign/";
    public String HASHICORP_SECRET_VERIFY_PATH = "secret/verify/";
    public String HASHICORP_ETHEREUM_ACCOUNT_ENDPOINT = "ethereum/accounts/";
    public String SIGNATURE_ALGORITHM = "pkcs1v15";
    public String HASH_ALGORITHM = "sha2-256";
    public String UTF_8 = "UTF-8";
    public String PROCESSING_UNBOUND_SIGN_REQUEST = "PROCESSING_UNBOUND_SIGN_REQUEST";
    public String UNBOUND_SIGN_ERROR = "ERROR_UNBOUND_SIGN";

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

    public String readFromFilePath(String path) throws IOException {
        String path2 = path.trim();
        if (!Files.exists(Paths.get(path2, new String[0]), new LinkOption[0])) {
            path2 = getAbsolutePath(path2);
        }
        return new String(Files.readAllBytes(Paths.get(path2, new String[0])));
    }

    private String getAbsolutePath(String classPathResource) throws IOException {
        Resource resource = new ClassPathResource(classPathResource);
        return resource.getFile().getAbsolutePath();
    }

    public String decryptWithRSA(String textToDecrypt, String charset, String privateKeyPath) throws Exception {

        if(DEBUG){
            stdout.println("DEBUG: decryptWithRSA ");
            stdout.println("DEBUG: textToDecrypt= " + textToDecrypt);
            stdout.println("DEBUG: charset= " + charset);
            stdout.println("DEBUG: privateKeyPath= " + privateKeyPath);
        }

        PrivateKey key = getPrivateKeyFromPKCS8(ALGO_RSA, privateKeyPath);
        return decrypt(ALGO_RSA, textToDecrypt, key, charset, null);
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
        
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(privateKey.replace(PRIVATE_KEY_STRING_START, "").replace(PRIVATE_KEY_STRING_END, "").getBytes());
        if (byteArrayInputStream == null || algorithm == null || algorithm.equalsIgnoreCase("")) {
            return null;
        }
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        byte[] encodeKey = read(byteArrayInputStream);
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(encodeKey)));
    }

    public PrivateKey getPrivateKeyFromPKCS8(String algorithm, String privateKeyPath) throws Exception {
        if(DEBUG){stdout.println("DEBUG: getPrivateKeyFromPKCS8");};
        String privateKey = readFromFilePath(privateKeyPath);
        return encodePrivateKey(privateKey, algorithm);
    }

    public String decrypt(String algorithm, String textToDecrypt, Key key, String charset, byte[] iv) throws Exception {
        Cipher cipher;
        byte[] textToDecryptBytes = Base64.getMimeDecoder().decode(textToDecrypt);
        if(DEBUG){stdout.println("DEBUG: decrypt");};

        if (algorithm.equalsIgnoreCase(ALGO_RSA)) {
            cipher = Cipher.getInstance(ALGO_RSA_INSTANCE);
            cipher.init(2, key, new OAEPParameterSpec("SHA-256", ALGO_RSA_MASK, MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        } else if (algorithm.equalsIgnoreCase(ALGO_AES)) {
            cipher = Cipher.getInstance(ALGO_AES_INSTANCE);
            cipher.init(2, key, new GCMParameterSpec(128, iv));
        } else {
            cipher = Cipher.getInstance(algorithm);
            cipher.init(2, key);
        }
        return new String(cipher.doFinal(textToDecryptBytes), charset);
    }

    public String decryptWithAES(String textToDecrypt, String charset, SecretKey key, byte[] iv) throws Exception {
        return decrypt(ALGO_AES, textToDecrypt, key, charset, iv);
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
        String response = new String(messageInfo.getResponse());

        for (String check: checks) {

            if (response.contains(check)) {

                // only process response
                if (!messageIsRequest) {
                    
                    //get whole response
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

                    String encryptedSecretKey = response.substring(secretStartIndex, secretEndIndex);

                    if(DEBUG){stdout.println("DEBUG: encryptedSecretKey= " + encryptedSecretKey);}

                    // capture the data in the response

                    String dataStartMatch = "\"body\":{\"data\":\"";
                    String dataEndMatch = "\",\"secret\":\"";

                    int dataStartIndex = response.indexOf(dataStartMatch) + dataStartMatch.length();
                    int dataEndIndex = response.indexOf(dataEndMatch, dataStartIndex+1);

                    String encryptedData = response.substring(dataStartIndex, dataEndIndex);

                    if(DEBUG){stdout.println("DEBUG: encryptedData= " + encryptedData);}

                    try {
                        
                        // decrypt the secret key using private key

                        if(DEBUG){stdout.println("DEBUG: key_path= " + key_path);}

                        String decryptedKey = decryptWithRSA(encryptedSecretKey, "UTF-8", key_path);
                        if(DEBUG){stdout.println("DEBUG: decryptedKey= " + decryptedKey);}
                        byte[] iv = detachIV(decryptedKey);
                        byte[] decodedKey = detachSecretKeyAES(decryptedKey);

                        // decrypt the data using decrypted secret key
                        SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, ALGO_AES);
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
    }
}