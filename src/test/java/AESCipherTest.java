import com.rmd.AESCipher;
import com.rmd.AESMessageDTO;
import org.junit.Assert;
import org.junit.Test;

/**
 * Created by randy on 2/17/2017.
 */
public class AESCipherTest {
    @Test
    public void AESEncryptTEST() {

        String plainText = "Don't tell anyone  ... ";
        AESMessageDTO message = new AESMessageDTO();
        message.set_plainText(plainText);

        AESCipher aes = new AESCipher();
        aes.Encrypt(message);

        Assert.assertTrue(!message.get_cipherText().isEmpty());
        Assert.assertTrue(!message.get_iv().isEmpty());
        Assert.assertTrue(!message.get_key().isEmpty());
        Assert.assertNotNull(plainText, message.get_cipherText());

    }

    @Test
    public void AESEncryptDecryptTEST() {
        String plainText = "Don't tell anyone  ... ";
        AESMessageDTO sendingMessage = new AESMessageDTO();
        sendingMessage.set_plainText(plainText);

        AESCipher aesEncrypt = new AESCipher();
        aesEncrypt.Encrypt(sendingMessage);

        //use new object as the message (to prevent cheating)
        AESMessageDTO receivedMessage = new AESMessageDTO();
        receivedMessage.set_iv(sendingMessage.get_iv());
        receivedMessage.set_cipherText(sendingMessage.get_cipherText());
        receivedMessage.set_key(sendingMessage.get_key());

        //use new object for decrypting
        AESCipher aesDecrypt = new AESCipher();
        aesDecrypt.Decrypt(receivedMessage);

        Assert.assertEquals(plainText, receivedMessage.get_plainText());

    }
}
