/**
 * Created by randy on 2/14/2017.
 */


import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;

import com.rmd.RSAKeyPair;

public class RSAKeyPairTest {

    private final String privateKeyPathName = "C:\\temp\\private.key";
    private final String publicKeyPathName = "C:\\temp\\public.key";

    private final String privateDERFromPEMKeyPathName = "C:\\temp\\sc-key.der";
    private final String publicDERFromPEMKeyPathName = "C:\\temp\\sc.der";

    @Test
    public void testToFileSystem()
            throws Exception {

        try {

            RSAKeyPair rsaKeyPair = new RSAKeyPair(2048);
            rsaKeyPair.toFileSystem(privateKeyPathName, publicKeyPathName);

            KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");

            Assert.assertNotNull(rsaKeyPair.getPrivateKey());
            Assert.assertNotNull(rsaKeyPair.getPublicKey());
            Assert.assertEquals(rsaKeyPair.getPrivateKey(), rsaKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(IOUtils.toByteArray(new FileInputStream(privateKeyPathName)))));
            Assert.assertEquals(rsaKeyPair.getPublicKey(), rsaKeyFactory.generatePublic(new X509EncodedKeySpec(IOUtils.toByteArray(new FileInputStream(publicKeyPathName)))));

        } catch(Exception exception) {
            Assert.fail("The testToFileSystem() test failed because: " + exception.getMessage());
        }
    }


    @Test
    public void testFromDERFileSystem()
            throws Exception {

        try {


            KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");

            PrivateKey myprivateKey = rsaKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(IOUtils.toByteArray(new FileInputStream(privateDERFromPEMKeyPathName))));
            Assert.assertNotNull(myprivateKey);


            PublicKey mypublicKey = rsaKeyFactory.generatePublic(new X509EncodedKeySpec(IOUtils.toByteArray(new FileInputStream(publicDERFromPEMKeyPathName))));
            Assert.assertNotNull(mypublicKey);


        } catch(Exception exception) {
            Assert.fail("Exception test failed because: " + exception.getMessage());
        }
    }

}