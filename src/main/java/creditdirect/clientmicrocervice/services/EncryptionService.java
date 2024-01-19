package creditdirect.clientmicrocervice.services;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Service
public class EncryptionService {

    private static final String ALGORITHM = "Blowfish";
    private static final String SECRET_KEY = "MySecretKey12345";

    public static String encrypt(String data) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            return Base64.getUrlEncoder().encodeToString(encryptedData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            throw new RuntimeException("Error during encryption", e);
        }
    }

    public static String decrypt(String encryptedData) {
        try {
            // Use URL-safe Base64 decoding
            byte[] decodedData = Base64.getUrlDecoder().decode(encryptedData);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedData = cipher.doFinal(decodedData);
            return new String(decryptedData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            throw new RuntimeException("Error during decryption", e);
        }
    }

}
