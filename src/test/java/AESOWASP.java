/**
 * Created by randy on 2/15/2017.
 */

import org.junit.Assert;
import org.junit.Test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

//import sun.misc.BASE64Encoder;
import java.util.Base64;


/**
 * @author Joe Prasanna Kumar
 *         This program provides the following cryptographic functionalities
 *         1. Encryption using AES
 *         2. Decryption using AES
 *         <p>
 *         High Level Algorithm :
 *         1. Generate a AES key (specify the Key size during this phase)
 *         2. Create the Cipher
 *         3. To Encrypt : Initialize the Cipher for Encryption
 *         4. To Decrypt : Initialize the Cipher for Decryption
 *         <p>
 *         <p>
 *         2017-02-15 - updated by Randy Danielson to use java.util.Base64 instead of sun.misc.BASE64Encoder
 */

public class AESOWASP {

    String strDataToEncrypt = new String();
    String strCipherText = new String();
    String strDecryptedText = new String();

    @Test
    public void AESEncryptDecryptTEST() {

        try {
            /**
             * Step 1. Generate an AES key using KeyGenerator Initialize the
             * keysize to 128 bits (16 bytes)
             *
             */
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey secretKey = keyGen.generateKey();

            /**
             * Step 2. Generate an Initialization Vector (IV)
             * 		a. Use SecureRandom to generate random bits
             * 		   The size of the IV matches the blocksize of the cipher (128 bits for AES)
             * 		b. Construct the appropriate IvParameterSpec object for the data to pass to Cipher's init() method
             */

            //to use longer key length need to install:  Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files 8 Download
            //http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
            final int AES_KEYLENGTH = 128;    // change this as desired for the security level you want
            byte[] iv = new byte[AES_KEYLENGTH / 8];    // Save the IV bytes or send it in plaintext with the encrypted data so you can decrypt the data later
            SecureRandom prng = new SecureRandom();
            prng.nextBytes(iv);

            /**
             * Step 3. Create a Cipher by specifying the following parameters
             * 		a. Algorithm name - here it is AES
             * 		b. Mode - here it is CBC mode
             * 		c. Padding - e.g. PKCS7 or PKCS5
             */

            //aparantly PKCS5 in java is actually doing PKCS7 and PKCS7 throws errors
            //Cipher aesCipherForEncryption = Cipher.getInstance("AES/CBC/PKCS7PADDING"); // Must specify the mode explicitly as most JCE providers default to ECB mode!!
            Cipher aesCipherForEncryption = Cipher.getInstance("AES/CBC/PKCS5PADDING"); // Must specify the mode explicitly as most JCE providers default to ECB mode!!

            /**
             * Step 4. Initialize the Cipher for Encryption
             */

            aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

            /**
             * Step 5. Encrypt the Data
             * 		a. Declare / Initialize the Data. Here the data is of type String
             * 		b. Convert the Input Text to Bytes
             * 		c. Encrypt the bytes using doFinal method
             */
            strDataToEncrypt = "Hello World of Encryption using AES ";
            byte[] byteDataToEncrypt = strDataToEncrypt.getBytes();
            byte[] byteCipherText = aesCipherForEncryption.doFinal(byteDataToEncrypt);
            // b64 is done differently on Android
            strCipherText = Base64.getEncoder().encodeToString(byteCipherText);

            System.out.println("Cipher Text generated using AES is " + strCipherText);

            /**
             * Step 6. Decrypt the Data
             * 		a. Initialize a new instance of Cipher for Decryption (normally don't reuse the same object)
             * 		   Be sure to obtain the same IV bytes for CBC mode.
             * 		b. Decrypt the cipher bytes using doFinal method
             */

            Cipher aesCipherForDecryption = Cipher.getInstance("AES/CBC/PKCS5PADDING"); // Must specify the mode explicitly as most JCE providers default to ECB mode!!

            aesCipherForDecryption.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] byteDecryptedText = aesCipherForDecryption.doFinal(byteCipherText);
            strDecryptedText = new String(byteDecryptedText);
            System.out.println(" Decrypted Text message is " + strDecryptedText);

            Assert.assertTrue(true);

        } catch (NoSuchAlgorithmException noSuchAlgo) {
            System.out.println(" No Such Algorithm exists " + noSuchAlgo);
            Assert.fail();
        } catch (NoSuchPaddingException noSuchPad) {
            System.out.println(" No Such Padding exists " + noSuchPad);
            Assert.fail();
        } catch (InvalidKeyException invalidKey) {
            System.out.println(" Invalid Key " + invalidKey);
            Assert.fail();
        } catch (BadPaddingException badPadding) {
            System.out.println(" Bad Padding " + badPadding);
            Assert.fail();
        } catch (IllegalBlockSizeException illegalBlockSize) {
            System.out.println(" Illegal Block Size " + illegalBlockSize);
            Assert.fail();
        } catch (InvalidAlgorithmParameterException invalidParam) {
            System.out.println(" Invalid Parameter " + invalidParam);
            Assert.fail();
        }
    }
}
