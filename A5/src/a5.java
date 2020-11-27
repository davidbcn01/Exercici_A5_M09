import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class a5 {

        public static SecretKey keygenKeyGeneration(int keySize) {
            SecretKey sKey = null;
            if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
                try {
                    KeyGenerator kgen = KeyGenerator.getInstance("AES");
                    kgen.init(keySize);
                    sKey = kgen.generateKey();

                } catch (NoSuchAlgorithmException ex) {
                    System.err.println("Generador no disponible.");
                }
            }
            return sKey;
        }

        public static SecretKey passwordKeyGeneration(String text, int keySize) {
            SecretKey sKey = null;
            if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
                try {
                    byte[] data = text.getBytes("UTF-8");
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    byte[] hash = md.digest(data);
                    byte[] key = Arrays.copyOf(hash, keySize/8);
                    sKey = new SecretKeySpec(key, "AES");
                } catch (Exception ex) {
                    System.err.println("Error generant la clau:" + ex);
                }
            }
            return sKey;
        }

        public static byte[] encryptData(SecretKey sKey, byte[] data) {
            byte[] encryptedData = null;
            try {
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, sKey);
                encryptedData =  cipher.doFinal(data);
            } catch (Exception  ex) {
                System.err.println("Error xifrant les dades: " + ex);
            }
            return encryptedData;
        }


        public static byte[] decryptData(SecretKey sKey, byte[] data) {
            byte[] decryptedData = null;
            try {
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, sKey);
                decryptedData =  cipher.doFinal(data);
            } catch (Exception  ex) {
                System.err.println("Error xifrant les dades: " + ex);
            }
            return decryptedData;
        }

    public static KeyPair randomGenerate(int len) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }
    }



