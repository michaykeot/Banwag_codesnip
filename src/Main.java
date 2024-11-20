import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws Exception {
        // This is to Generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);  // 128-bit key
        SecretKey secretKey = keyGen.generateKey();

        // To Initialize cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        String textToEncrypt = "This data is sensitive."; //Michelle Banwag

        // To Encrypt text
        byte[] encryptedText = cipher.doFinal(textToEncrypt.getBytes());
        String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedText);
        System.out.println("Encrypted: " + encryptedBase64);

        // Initialize for decryption
        IvParameterSpec ivSpec = new IvParameterSpec(cipher.getIV());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        // To Decrypt text
        byte[] decryptedText = cipher.doFinal(Base64.getDecoder().decode(encryptedBase64));
        String decryptedTextString = new String(decryptedText);
        System.out.println("Decrypted: " + decryptedTextString);
    }
}
