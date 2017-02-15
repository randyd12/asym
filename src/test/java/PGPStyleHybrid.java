import com.rmd.RSACipher;
import com.rmd.RSAKeyPair;
import org.junit.Assert;
import org.junit.Test;
//import sun.misc.BASE64Decoder;
//import sun.misc.BASE64Encoder;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.PrintWriter;
import java.io.StringReader;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;

/**
 * Created by randy on 2/14/2017.
 */
public class PGPStyleHybrid {

    private final String senderPrivateKeyPathName = "c:\\temp\\sender-private.key";
    private final String senderPublicKeyPathName = "c:\\temp\\sender-public.key";

    private final String receiverPrivateKeyPathName = "c:\\temp\\receiver-private2.key";
    private final String receiverPublicKeyPathName = "c:\\temp\\receiver-public2.key";

    private final String encryptedMessagePath = "c:\\temp\\encryptedMessageWithPublicKey.txt";

    private final String transformation = "RSA/ECB/PKCS1Padding";
    private final String encoding = "UTF-8";
    private final String delimiter = "<|~|>";

    @Test
    public void EncryptDecrypt() throws Exception {

        try {

            RSACipher rsaCipher = new RSACipher();

            PrintWriter out = new PrintWriter(encryptedMessagePath);
            String secretMessage = "My secret message";

            //Create new public and private keys to test with
            RSAKeyPair rsaKeyPair = new RSAKeyPair(2048);
            rsaKeyPair.toFileSystem(senderPrivateKeyPathName, senderPublicKeyPathName);
            rsaKeyPair.toFileSystem(receiverPrivateKeyPathName, receiverPublicKeyPathName);


            //Generate random key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // for example
            SecretKey secretKey = keyGen.generateKey();


            //Create signature so the receiver can verify the message was sent from me.
            Signature instance = Signature.getInstance("SHA256withRSA");
            instance.initSign(rsaKeyPair.getPrivateKey(), new SecureRandom());
            instance.update(secretMessage.getBytes("UTF-8"));
            byte[] signedBytes = instance.sign();
            instance.initVerify(rsaKeyPair.getPublicKey());
            instance.update(secretMessage.getBytes("UTF-8"));

            String encrypted = "";
            boolean signatureVerified = instance.verify(signedBytes);
            if (signatureVerified)
            {
                System.out.println("signature verified...continuing");

                //Add signature to the secret message
                //our delimiter will be "<|~|>" (without the quotes)
                Base64.Encoder b64 = Base64.getEncoder();
                String signatureEncoded = b64.encodeToString(signedBytes);

                //Combine data and signature
                secretMessage = secretMessage + delimiter + signatureEncoded;

                //Encrypt secret message including signature with AES using the secret key we created for this session


                //Encrypt secret key with receiver's public key
                String secretKeyEncoded = b64.encodeToString(secretKey.getEncoded());
                String encryptedSecretKey = rsaCipher.encrypt(secretKeyEncoded, receiverPublicKeyPathName, transformation, encoding);

                //write encrypted string to file
                out.println(encrypted);
                out.flush();
            }
            else
            {
                System.out.println("problem creating signature locally...aborting");
            }


            //Now simulate the receiver decrypting and verifying the signature
            //simulate receiver decrypting  - it knows 2 things...the senders public key (to verify signature) and its own private key

            String decrypted = rsaCipher.decrypt(encrypted, receiverPrivateKeyPathName, transformation, encoding);

            //parse out the delimiter and signature
            String sig = "";
            String decryptedMessage = "";
            String[] parts = decrypted.split(delimiter);
            sig = parts[0];
            decryptedMessage = parts[1];


            Assert.assertEquals(decrypted, secretMessage);

//            //Now encrypt again with senders private key (so receiver can verify sender)
//            String encrypted2 = rsaCipher.encrypt(encrypted, senderPrivateKeyPathName, transformation, encoding);
//
//            //write double encrypted string to file
//            out.println(encrypted2);
//            out.flush();


//            //Now this double encrypted message is ready to send
//            //simulate receiver decrypting  - it knows 2 things...the senders public key and its own private key
//
//            //Decrypt with senders public key
//            String decrypted2 = rsaCipher.decrypt(encrypted2, senderPublicKeyPathName, transformation, encoding);
//            Assert.assertEquals(encrypted, decrypted2);
//
//            //Decrypt single encrypted file with receiver's private key
//            String decrypted = rsaCipher.decrypt(encrypted, receiverPrivateKeyPathName, transformation, encoding);
//            Assert.assertEquals(decrypted, secretMessage);

        } catch(Exception exception) {
            Assert.fail("The EncryptDecrypt() test failed because: " + exception.getMessage());
        }
    }

    @Test
    public void EncryptDecryptWithOwnKeys() throws Exception {
        RSACipher c = new RSACipher();

        try {

            //Create new public and private keys to test with
            RSAKeyPair rsaKeyPair = new RSAKeyPair(2048);
            rsaKeyPair.toFileSystem(senderPrivateKeyPathName, senderPublicKeyPathName);

            RSACipher rsaCipher = new RSACipher();
            String encrypted = rsaCipher.encrypt("John has a long mustache.", senderPublicKeyPathName, transformation, encoding);
            String decrypted = rsaCipher.decrypt(encrypted, senderPrivateKeyPathName, transformation, encoding);
            Assert.assertEquals(decrypted, "John has a long mustache.");

        } catch(Exception exception) {
            Assert.fail("The EncryptDecryptWithOwnKeys() test failed because: " + exception.getMessage());
        }
    }
}
