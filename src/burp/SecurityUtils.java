package burp;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
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

@Service
/* loaded from: tokenization-0.0.5-SNAPSHOT.jar:BOOT-INF/lib/gateway-security-2.0.16.jar:com/jpmorgan/gateway/security/util/SecurityUtils.class */
public class SecurityUtils {
    public PrivateKey encodePrivateKey(String privateKey, String algorithm) throws Exception {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(privateKey.replace(Constants.PRIVATE_KEY_STRING_START, "").replace(Constants.PRIVATE_KEY_STRING_END, "").getBytes());
        if (byteArrayInputStream == null || algorithm == null || algorithm.equalsIgnoreCase("")) {
            return null;
        }
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        byte[] encodeKey = read(byteArrayInputStream);
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(encodeKey)));
    }

    public PrivateKey getPrivateKeyFromPKCS8(String algorithm, String privateKeyPath) throws Exception {
        String privateKey = FileIOUtil.readFromFilePath(privateKeyPath);
        return encodePrivateKey(privateKey, algorithm);
    }

    public String decrypt(String algorithm, String textToDecrypt, Key key, String charset, byte[] iv) throws Exception {
        Cipher cipher;
        byte[] textToDecryptBytes = Base64.getMimeDecoder().decode(textToDecrypt);
        if (algorithm.equalsIgnoreCase(Constants.ALGO_RSA)) {
            cipher = Cipher.getInstance(Constants.ALGO_RSA_INSTANCE);
            cipher.init(2, key, new OAEPParameterSpec("SHA-256", Constants.ALGO_RSA_MASK, MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        } else if (algorithm.equalsIgnoreCase(Constants.ALGO_AES)) {
            cipher = Cipher.getInstance(Constants.ALGO_AES_INSTANCE);
            cipher.init(2, key, new GCMParameterSpec(128, iv));
        } else {
            cipher = Cipher.getInstance(algorithm);
            cipher.init(2, key);
        }
        return new String(cipher.doFinal(textToDecryptBytes), charset);
    }

    public String decryptWithRSA(String textToDecrypt, String charset, String privateKeyPath) throws Exception {
        PrivateKey key = getPrivateKeyFromPKCS8(Constants.ALGO_RSA, privateKeyPath);
        return decrypt(Constants.ALGO_RSA, textToDecrypt, key, charset, null);
    }

    public byte[] detachIV(String decryptedKey) {
        byte[] iv = null;
        String[] tokens = decryptedKey.split("\\|");
        if (tokens.length > 1) {
            iv = Base64.getDecoder().decode(tokens[0]);
        }
        return iv;
    }

    public byte[] detachSecretKeyAES(String decryptedKey) {
        byte[] decodedKey = null;
        String[] tokens = decryptedKey.split("\\|");
        if (tokens.length > 1) {
            decodedKey = Base64.getDecoder().decode(tokens[1]);
        }
        return decodedKey;
    }
}