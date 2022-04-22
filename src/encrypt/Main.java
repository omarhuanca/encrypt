package encrypt;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Main {

  public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    Encrypt encrypt = new Encrypt("x2n.ndbw.whtv.v6", "isa123");
    
    String valueEncrypt = encrypt.generateEncrypt();
    System.out.println("encrypt " + valueEncrypt);
    
    String valueDecrypt = encrypt.generateDecrypt(valueEncrypt);
    System.out.println("decrypt " + valueDecrypt);
  }
}
