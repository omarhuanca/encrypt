package encrypt;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

public class Encrypt {

  private String password;

  private SecretKey secretKey;

  private Cipher cipher;

  public Encrypt(String encryptKey, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
    this.password = password;
    secretKey = new SecretKeySpec(Hex.decode("301002050f03060700090a0b0c0d0e0f"), "AES");
    cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BCFIPS");
  }

  public String generateEncrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);

    byte[] encryptedBytes = cipher.doFinal(password.getBytes());
    //System.out.println("encryptedBytes " + encryptedBytes);
    return Base64.getEncoder().encodeToString(encryptedBytes);
  }

  public String generateDecrypt(String encrypted) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    // Decryption - re-init same instance
    cipher.init(Cipher.DECRYPT_MODE, secretKey);

    byte[] decodedBytes = Base64.getDecoder().decode(encrypted);
    byte[] decData = this.getCipher().doFinal(decodedBytes);
    return new String(decData);
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public SecretKey getSecretKey() {
    return secretKey;
  }

  public void setSecretKey(SecretKey secretKey) {
    this.secretKey = secretKey;
  }

  public Cipher getCipher() {
    return cipher;
  }

  public void setCipher(Cipher cipher) {
    this.cipher = cipher;
  }
}
