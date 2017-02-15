package com.rmd;

import org.junit.Assert;

public class Main {

    private static final String privateKeyPathName = "/root/sc/sc.pem";
    private static final String publicKeyPathName = "/root/sc/sc-key.pem";
    private static final String transformation = "RSA/ECB/PKCS1Padding";
    private static final String encoding = "UTF-8";


//    Note:  To execute from the command line:
//    java -cp encrypt.jar com.rmd.main


    public static void main(String[] args) {
        RSACipher c = new RSACipher();
        //c.encrypt("this is my secret message", "/root/sc/sc.pem", "")

        try {

//            RSAKeyPair rsaKeyPair = new RSAKeyPair(2048);
//            rsaKeyPair.toFileSystem(privateKeyPathName, publicKeyPathName);

            RSACipher rsaCipher = new RSACipher();
            String encrypted = rsaCipher.encrypt("John has a long mustache.", publicKeyPathName, transformation, encoding);
            //String decrypted = rsaCipher.decrypt(encrypted, privateKeyPathName, transformation, encoding);
            //Assert.assertEquals(decrypted, "John has a long mustache.");

        } catch(Exception exception) {
            Assert.fail("The testEncryptDecryptWithKeyPairFiles() test failed because: " + exception.getMessage());
        }

    }
}
