/**
 * Created by randy on 2/14/2017.
 */

import com.rmd.PEMOperations;

import org.junit.Assert;
import org.junit.Test;

import java.security.PrivateKey;
import java.security.PublicKey;

public class PEMOperationsTest {
    @Test
    public void testLoadPublicFromDER() throws Exception {

        try
        {
            PEMOperations pemOps = new PEMOperations();
            PublicKey pubK = pemOps.getPubKeyFromDER("c:\\temp\\sc.der", "RSA");

            Assert.assertTrue(true);

        }
        catch (Exception ex)
        {
            Assert.fail("failed: " + ex.getMessage());
        }
    }

    @Test
    public void testLoadPrivateKeyFromDER() throws Exception {

        try
        {
            PEMOperations pemOps = new PEMOperations();
            PrivateKey privK = pemOps.getPrivateKeyFromDER("c:\\temp\\sc-key.der", "RSA");

            Assert.assertTrue(true);

        }
        catch (Exception ex)
        {
            Assert.fail("failed: " + ex.getMessage());
        }
    }
}
