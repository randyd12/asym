package com.rmd;

import org.junit.Assert;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Created by randy on 2/17/2017.
 */
public class AESCipher {
    public void Encrypt(AESMessageDTO message) {

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
            byte[] byteDataToEncrypt = message.get_plainText().getBytes();
            byte[] byteCipherText = aesCipherForEncryption.doFinal(byteDataToEncrypt);
            // b64 is done differently on Android


            message.set_cipherText(Base64.getEncoder().encodeToString(byteCipherText));
            message.set_iv(Base64.getEncoder().encodeToString(iv));
            message.set_key(Base64.getEncoder().encodeToString(secretKey.getEncoded()));


        } catch (NoSuchAlgorithmException noSuchAlgo) {
            System.out.println(" No Such Algorithm exists " + noSuchAlgo);
        } catch (NoSuchPaddingException noSuchPad) {
            System.out.println(" No Such Padding exists " + noSuchPad);
        } catch (InvalidKeyException invalidKey) {
            System.out.println(" Invalid Key " + invalidKey);
        } catch (BadPaddingException badPadding) {
            System.out.println(" Bad Padding " + badPadding);
        } catch (IllegalBlockSizeException illegalBlockSize) {
            System.out.println(" Illegal Block Size " + illegalBlockSize);
        } catch (InvalidAlgorithmParameterException invalidParam) {
            System.out.println(" Invalid Parameter " + invalidParam);
        }
    }

    public void Decrypt(AESMessageDTO message) {

        try {

            /**
             *  Decrypt the Data
             * 		a. Initialize a new instance of Cipher for Decryption (normally don't reuse the same object)
             * 		   Be sure to obtain the same IV bytes for CBC mode.
             * 		b. Decrypt the cipher bytes using doFinal method
             */

            Cipher aesCipherForDecryption = Cipher.getInstance("AES/CBC/PKCS5PADDING"); // Must specify the mode explicitly as most JCE providers default to ECB mode!!


            // decode the base64 encoded string
            byte[] decodedKey = Base64.getDecoder().decode(message.get_key());
            // rebuild key using SecretKeySpec
            SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

            byte[] iv = Base64.getDecoder().decode(message.get_iv());
            byte[] byteCipherText = Base64.getDecoder().decode(message.get_cipherText());

            aesCipherForDecryption.init(Cipher.DECRYPT_MODE, originalKey, new IvParameterSpec(iv));
            byte[] byteDecryptedText = aesCipherForDecryption.doFinal(byteCipherText);
            message.set_plainText(new String(byteDecryptedText));

        } catch (NoSuchAlgorithmException noSuchAlgo) {
            System.out.println(" No Such Algorithm exists " + noSuchAlgo);
        } catch (NoSuchPaddingException noSuchPad) {
            System.out.println(" No Such Padding exists " + noSuchPad);
        } catch (InvalidKeyException invalidKey) {
            System.out.println(" Invalid Key " + invalidKey);
        } catch (BadPaddingException badPadding) {
            System.out.println(" Bad Padding " + badPadding);
        } catch (IllegalBlockSizeException illegalBlockSize) {
            System.out.println(" Illegal Block Size " + illegalBlockSize);
        } catch (InvalidAlgorithmParameterException invalidParam) {
            System.out.println(" Invalid Parameter " + invalidParam);
        }
    }
}
