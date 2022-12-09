public class Constants {

    public static final String ALGO_RSA = "RSA";
    public static final String ALGO_RSA_INSTANCE = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String ALGO_RSA_DIGEST = "SHA-256";
    public static final String ALGO_RSA_MASK = "MGF1";
    public static final String ALGO_EC = "EC";
    public static final String SIGNATURE_ALGO_EC = "SHA256withECDSA";
    public static final String ALGO_AES = "AES";
    public static final String ALGO_AES_INSTANCE = "AES/GCM/NoPadding";
    public static final int AES_KEY_LENGTH = 256;
    public static final int AES_TAG_LENGTH = 128;
    public static final int AES_IV_LENGTH_96 = 96;
    public static final int AES_IV_LENGTH_12 = 12;
    public static final String SIGNATURE = "SHA256withRSA";
    public static final String PUBLIC_KEY_STRING_START = "-----BEGIN PUBLIC KEY-----";
    public static final String PUBLIC_KEY_STRING_END = "-----END PUBLIC KEY-----";
    public static final String PRIVATE_KEY_STRING_START = "-----BEGIN PRIVATE KEY-----";
    public static final String PRIVATE_KEY_STRING_END = "-----END PRIVATE KEY-----";
    public static final String HASHICORP_ROLE_ID = "HASHICORP_ROLE_ID";
    public static final String HASHICORP_SECRET_ID = "HASHICORP_SECRET_ID";
    public static final String HASHICORP_TOKEN = "HASHICORP_TOKEN";
    public static final String HASHICORP_CLIENT_KEYSTORE_PWD = "HASHICORP_CLIENT_KEYSTORE_PWD";
    public static final String HASHICORP_CLIENT_TRUSTSTORE_PWD = "HASHICORP_CLIENT_TRUSTSTORE_PWD";
    public static final String HASHICORP_KEY_PREFIX = "vault:v1:";
    public static final String HASHICORP_TRANSITE_SIGN_PATH = "transit/sign/";
    public static final String HASHICORP_TRANSITE_VERIFY_PATH = "transit/verify/";
    public static final String HASHICORP_TRANSITE_ENCRYPT_PATH = "transit/encrypt/";
    public static final String HASHICORP_TRANSITE_DECRYPT_PATH = "transit/decrypt/";
    public static final String HASHICORP_SECRET_SIGN_PATH = "secret/sign/";
    public static final String HASHICORP_SECRET_VERIFY_PATH = "secret/verify/";
    public static final String HASHICORP_ETHEREUM_ACCOUNT_ENDPOINT = "ethereum/accounts/";
    public static final String SIGNATURE_ALGORITHM = "pkcs1v15";
    public static final String HASH_ALGORITHM = "sha2-256";
    public static final String UTF_8 = "UTF-8";
    public static final String PROCESSING_UNBOUND_SIGN_REQUEST = "PROCESSING_UNBOUND_SIGN_REQUEST";
    public static final String UNBOUND_SIGN_ERROR = "ERROR_UNBOUND_SIGN";

    /* loaded from: tokenization-0.0.5-SNAPSHOT.jar:BOOT-INF/lib/gateway-security-2.0.16.jar:com/jpmorgan/gateway/security/constants/Constants$PayloadType.class */
    public enum PayloadType {
        BLOCKCHAIN_TRANSACTION,
        PLAINTEXT
    }
    
}
