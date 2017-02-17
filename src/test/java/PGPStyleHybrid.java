import com.rmd.AESCipher;
import com.rmd.AESMessageDTO;
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
    private final String runLogPath = "c:\\temp\\runLog.txt";

    private final String transformation = "RSA/ECB/PKCS1Padding";
    private final String encoding = "UTF-8";


    private final String delimiter = "<!!>";
    String regExSplitBy = "[<!!>]+";  //brackets mean group of characters the + means treat them all together

    //8563 bytes -> 12,234 bytes after signed and encrypted and keys included
    private final String dataToEncrypt = "[{\"id\":\"156e74ab-8c2b-43a2-aa8e-9afc807b5696\",\"ts\":1487370663176,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"156e74ab-8c2b-43a2-aa8e-9afc807b5696\",\"uuid\":\"00:07:80:EC:39:E1\",\"incomm\":true,\"rng\":-86,\"feature_id\":\"e2f8b272-d1ef-4937-9631-8dbbd70e7525\",\"bat\":100,\"temp\":26,\"x\":0.38,\"y\":0.73,\"z\":-0.06,\"ts\":1487370663176,\"raw1\":\"020106020a030bffffff5664eaf9b20be200\",\"ant\":\"\"},\"en_ts\":1487370663181}, {\"id\":\"f34efd4f-0987-4e08-bfff-e4e39da1a255\",\"ts\":1487370663448,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"f34efd4f-0987-4e08-bfff-e4e39da1a255\",\"uuid\":\"00:07:80:EC:4A:87\",\"incomm\":true,\"rng\":-75,\"feature_id\":\"00cbaa80-5e2e-46d3-bd76-8427bb586a01\",\"bat\":100,\"temp\":34,\"x\":0.5,\"y\":0.7,\"z\":0.08,\"ts\":1487370663448,\"raw1\":\"020106020a030bffffff5e6404f8420bb1fe\",\"ant\":\"\"},\"en_ts\":1487370663451}, {\"id\":\"fe0b241d-62ce-45ab-a047-9288730da83e\",\"ts\":1487370663511,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"fe0b241d-62ce-45ab-a047-9288730da83e\",\"uuid\":\"A0:E6:F8:28:F3:E5\",\"incomm\":true,\"rng\":-44,\"feature_id\":\"72962632-5225-4ab8-a979-c1fa0d715017\",\"bat\":3,\"temp\":11,\"x\":-0.02,\"y\":0.23,\"z\":0.71,\"ts\":1487370663511,\"raw1\":\"0201040efffffe01640247035a00a303a9f4\",\"ant\":\"\"},\"en_ts\":1487370663517}, {\"id\":\"3d1f13c8-8aab-48ed-a249-5a821c5f6646\",\"ts\":1487370663866,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"3d1f13c8-8aab-48ed-a249-5a821c5f6646\",\"uuid\":\"00:07:80:EC:48:A0\",\"incomm\":true,\"rng\":-79,\"feature_id\":\"656da310-6687-4ceb-b25c-e65c5d40f530\",\"bat\":100,\"temp\":24,\"x\":0.62,\"y\":0.84,\"z\":-0.12,\"ts\":1487370663866,\"raw1\":\"020106020a030bffffff54640df66d0de601\",\"ant\":\"\"},\"en_ts\":1487370663869}, {\"id\":\"a027352f-770e-419d-bdcf-2624f7039290\",\"ts\":1487370663913,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"a027352f-770e-419d-bdcf-2624f7039290\",\"uuid\":\"00:07:80:C2:C6:9E\",\"incomm\":true,\"rng\":-86,\"feature_id\":\"b3e9f81a-44c1-4d94-9535-686d757394c3\",\"bat\":100,\"temp\":35,\"x\":0.58,\"y\":0.65,\"z\":-0.39,\"ts\":1487370663913,\"raw1\":\"020106020a030bffffff5f64aaf66b0a5106\",\"ant\":\"\"},\"en_ts\":1487370663915}, {\"id\":\"f3ddb72a-8519-420c-a171-d06fc9af14ae\",\"ts\":1487370663947,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"f3ddb72a-8519-420c-a171-d06fc9af14ae\",\"uuid\":\"00:07:80:EC:48:99\",\"incomm\":true,\"rng\":-84,\"feature_id\":\"0eeaec71-2251-4a50-9212-35bda9f0b026\",\"bat\":100,\"temp\":29,\"x\":0.59,\"y\":0.84,\"z\":-0.13,\"ts\":1487370663947,\"raw1\":\"020106020a030bffffff59648df6670d1402\",\"ant\":\"\"},\"en_ts\":1487370663950}, {\"id\":\"0166bedd-c268-4a66-a736-6751f95ecd7e\",\"ts\":1487370664285,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"0166bedd-c268-4a66-a736-6751f95ecd7e\",\"uuid\":\"00:07:80:EC:39:E1\",\"incomm\":true,\"rng\":-83,\"feature_id\":\"e2f8b272-d1ef-4937-9631-8dbbd70e7525\",\"bat\":100,\"temp\":26,\"x\":0.38,\"y\":0.73,\"z\":-0.06,\"ts\":1487370664285,\"raw1\":\"020106020a030bffffff5664eaf9b20be200\",\"ant\":\"\"},\"en_ts\":1487370664287}, {\"id\":\"9f10fddc-85f5-4583-99b0-10026c136bfa\",\"ts\":1487370664520,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"9f10fddc-85f5-4583-99b0-10026c136bfa\",\"uuid\":\"A0:E6:F8:28:F3:E5\",\"incomm\":true,\"rng\":-61,\"feature_id\":\"72962632-5225-4ab8-a979-c1fa0d715017\",\"bat\":3,\"temp\":10,\"x\":-1.34,\"y\":0.2,\"z\":0.43,\"ts\":1487370664520,\"raw1\":\"0201040efffffe01640246036a152d030df9\",\"ant\":\"\"},\"en_ts\":1487370664526}, {\"id\":\"80da32ca-06c1-48f5-8d88-a28a23833b88\",\"ts\":1487370664558,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"80da32ca-06c1-48f5-8d88-a28a23833b88\",\"uuid\":\"00:07:80:EC:4A:87\",\"incomm\":true,\"rng\":-77,\"feature_id\":\"00cbaa80-5e2e-46d3-bd76-8427bb586a01\",\"bat\":100,\"temp\":34,\"x\":0.45,\"y\":0.62,\"z\":0.06,\"ts\":1487370664558,\"raw1\":\"020106020a030bffffff5e64dff8f009fffe\",\"ant\":\"\"},\"en_ts\":1487370664562}, {\"id\":\"2d9fe301-15e6-4aae-a2c6-cf5c7419be15\",\"ts\":1487370664973,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"2d9fe301-15e6-4aae-a2c6-cf5c7419be15\",\"uuid\":\"00:07:80:EC:48:A0\",\"incomm\":true,\"rng\":-89,\"feature_id\":\"656da310-6687-4ceb-b25c-e65c5d40f530\",\"bat\":100,\"temp\":24,\"x\":0.62,\"y\":0.84,\"z\":-0.12,\"ts\":1487370664973,\"raw1\":\"020106020a030bffffff54640df66d0de601\",\"ant\":\"\"},\"en_ts\":1487370664974}, {\"id\":\"2600c8b8-8bdd-4b43-95f8-551ea376bf47\",\"ts\":1487370665021,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"2600c8b8-8bdd-4b43-95f8-551ea376bf47\",\"uuid\":\"00:07:80:C2:C6:9E\",\"incomm\":true,\"rng\":-71,\"feature_id\":\"b3e9f81a-44c1-4d94-9535-686d757394c3\",\"bat\":100,\"temp\":35,\"x\":0.45,\"y\":0.67,\"z\":-0.44,\"ts\":1487370665021,\"raw1\":\"020106020a030bffffff5f64cff8ac0afc06\",\"ant\":\"\"},\"en_ts\":1487370665025}, {\"id\":\"6ff0216d-194b-469c-9f99-cb632fb9d904\",\"ts\":1487370665055,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"6ff0216d-194b-469c-9f99-cb632fb9d904\",\"uuid\":\"00:07:80:EC:48:99\",\"incomm\":true,\"rng\":-84,\"feature_id\":\"0eeaec71-2251-4a50-9212-35bda9f0b026\",\"bat\":100,\"temp\":29,\"x\":0.59,\"y\":0.84,\"z\":-0.13,\"ts\":1487370665055,\"raw1\":\"020106020a030bffffff59648df6670d1402\",\"ant\":\"\"},\"en_ts\":1487370665061}, {\"id\":\"7e020bf6-f65a-42e4-af74-c1d41e5b7e23\",\"ts\":1487370665529,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"7e020bf6-f65a-42e4-af74-c1d41e5b7e23\",\"uuid\":\"A0:E6:F8:28:F3:E5\",\"incomm\":true,\"rng\":-56,\"feature_id\":\"72962632-5225-4ab8-a979-c1fa0d715017\",\"bat\":3,\"temp\":11,\"x\":0.48,\"y\":0.01,\"z\":0.79,\"ts\":1487370665529,\"raw1\":\"0201040efffffe016402470360f81c004bf3\",\"ant\":\"\"},\"en_ts\":1487370665531}, {\"id\":\"3c7ae3df-46d2-4014-859f-4daa0c524d30\",\"ts\":1487370665662,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"3c7ae3df-46d2-4014-859f-4daa0c524d30\",\"uuid\":\"00:07:80:EC:4A:87\",\"incomm\":true,\"rng\":-84,\"feature_id\":\"00cbaa80-5e2e-46d3-bd76-8427bb586a01\",\"bat\":100,\"temp\":34,\"x\":0.45,\"y\":0.62,\"z\":0.06,\"ts\":1487370665662,\"raw1\":\"020106020a030bffffff5e64dff8f009fffe\",\"ant\":\"\"},\"en_ts\":1487370665663}, {\"id\":\"c3ae98e5-657a-4b1e-97c9-47a2bfc8e845\",\"ts\":1487370666533,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"c3ae98e5-657a-4b1e-97c9-47a2bfc8e845\",\"uuid\":\"A0:E6:F8:28:F3:E5\",\"incomm\":true,\"rng\":-47,\"feature_id\":\"72962632-5225-4ab8-a979-c1fa0d715017\",\"bat\":3,\"temp\":11,\"x\":0.41,\"y\":0.11,\"z\":0.47,\"ts\":1487370666533,\"raw1\":\"0201040efffffe01640247037ef9d3016ef8\",\"ant\":\"\"},\"en_ts\":1487370666537}, {\"id\":\"1c31a52a-6cc2-4fb1-b7b4-9ff634a2d982\",\"ts\":1487370667536,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"1c31a52a-6cc2-4fb1-b7b4-9ff634a2d982\",\"uuid\":\"A0:E6:F8:28:F3:E5\",\"incomm\":true,\"rng\":-46,\"feature_id\":\"72962632-5225-4ab8-a979-c1fa0d715017\",\"bat\":3,\"temp\":11,\"x\":0.2,\"y\":-0.04,\"z\":0.15,\"ts\":1487370667536,\"raw1\":\"0201040efffffe0164024703defc4dffa8fd\",\"ant\":\"\"},\"en_ts\":1487370667538}, {\"id\":\"d6e00d13-1317-4844-b5fa-2df369a55469\",\"ts\":1487370669542,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"d6e00d13-1317-4844-b5fa-2df369a55469\",\"uuid\":\"A0:E6:F8:28:F3:E5\",\"incomm\":true,\"rng\":-46,\"feature_id\":\"72962632-5225-4ab8-a979-c1fa0d715017\",\"bat\":3,\"temp\":11,\"x\":0.06,\"y\":-0.14,\"z\":-0.01,\"ts\":1487370669542,\"raw1\":\"0201040efffffe0164024703f6fec0fd2100\",\"ant\":\"\"},\"en_ts\":1487370669545}, {\"id\":\"4b78f1a7-f1be-4b69-a43b-d0c7a910a856\",\"ts\":1487370669545,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"4b78f1a7-f1be-4b69-a43b-d0c7a910a856\",\"uuid\":\"A0:E6:F8:28:F3:E5\",\"incomm\":true,\"rng\":-47,\"feature_id\":\"72962632-5225-4ab8-a979-c1fa0d715017\",\"bat\":3,\"temp\":11,\"x\":0.06,\"y\":-0.14,\"z\":-0.01,\"ts\":1487370669545,\"raw1\":\"0201040efffffe0164024703f6fec0fd2100\",\"ant\":\"\"},\"en_ts\":1487370669550}, {\"id\":\"6fb396f3-75b0-44cb-a8e0-b395d2d2d906\",\"ts\":1487370671556,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"6fb396f3-75b0-44cb-a8e0-b395d2d2d906\",\"uuid\":\"A0:E6:F8:28:F3:E5\",\"incomm\":true,\"rng\":-35,\"feature_id\":\"72962632-5225-4ab8-a979-c1fa0d715017\",\"bat\":3,\"temp\":10,\"x\":-0.26,\"y\":-0.19,\"z\":0.26,\"ts\":1487370671556,\"raw1\":\"0201040efffffe01640246033804ebfcdafb\",\"ant\":\"\"},\"en_ts\":1487370671563}, {\"id\":\"26eb180e-9e57-42b2-b718-7ca7ea04de8f\",\"ts\":1487370672559,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"26eb180e-9e57-42b2-b718-7ca7ea04de8f\",\"uuid\":\"A0:E6:F8:28:F3:E5\",\"incomm\":true,\"rng\":-41,\"feature_id\":\"72962632-5225-4ab8-a979-c1fa0d715017\",\"bat\":3,\"temp\":11,\"x\":-0.55,\"y\":-0.06,\"z\":0.38,\"ts\":1487370672559,\"raw1\":\"0201040efffffe0164024703c10816ffdef9\",\"ant\":\"\"},\"en_ts\":1487370672563}, {\"id\":\"dcbff623-f10d-45e6-a29a-ed38252386f0\",\"ts\":1487370673564,\"ec\":\"SensorEvent\",\"et\":\"Sensor_Reading\",\"detail\":{\"id\":\"dcbff623-f10d-45e6-a29a-ed38252386f0\",\"uuid\":\"A0:E6:F8:28:F3:E5\",\"incomm\":true,\"rng\":-38,\"feature_id\":\"72962632-5225-4ab8-a979-c1fa0d715017\",\"bat\":3,\"temp\":11,\"x\":-0.86,\"y\":0.1,\"z\":0.49,\"ts\":1487370673564,\"raw1\":\"0201040efffffe0164024703b60da20137f8\",\"ant\":\"\"},\"en_ts\":1487370673568}]";


    @Test
    public void EncryptDecrypt() throws Exception {

        try {

            RSACipher rsaCipher = new RSACipher();

            PrintWriter out = new PrintWriter(encryptedMessagePath);
            PrintWriter runLog = new PrintWriter(encryptedMessagePath);

            //NOTE:  the string "My secret message"  842 bytes after signing and encrypting  4900 % increase
            //String secretMessage = "My secret message";

            //String secretMessage = dataToEncrypt; //8563 bytes -> 12,234 bytes after signed and encrypted and keys included 43% increase
            String secretMessage = dataToEncrypt + dataToEncrypt;  //17,126 -> 23,670 bytes after signed and encrypted and keys included  38% increase

            //Create new public and private keys to test with
            RSAKeyPair rsaKeyPairSender = new RSAKeyPair(2048);
            rsaKeyPairSender.toFileSystem(senderPrivateKeyPathName, senderPublicKeyPathName);

            RSAKeyPair rsaKeyPairReceiver = new RSAKeyPair(2048);
            rsaKeyPairReceiver.toFileSystem(receiverPrivateKeyPathName, receiverPublicKeyPathName);


            //Generate random key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // for example
            SecretKey secretKey = keyGen.generateKey();


            //Create signature so the receiver can verify the message was sent from me.
            Signature instance = Signature.getInstance("SHA256withRSA");
            instance.initSign(rsaKeyPairSender.getPrivateKey(), new SecureRandom());
            instance.update(secretMessage.getBytes("UTF-8"));
            byte[] signedBytes = instance.sign();

            String entireMessage = "";

            //Add signature to the secret message
            String signatureEncoded = Base64.getEncoder().encodeToString(signedBytes);
            //System.out.println("Signature: " + signatureEncoded);

            //Combine data and signature
            secretMessage = secretMessage + delimiter + signatureEncoded;

            //Encrypt secret message including signature with AES using the secret key we created for this session

            AESCipher aesCipher = new AESCipher();
            AESMessageDTO messageToSend = new AESMessageDTO();
            messageToSend.set_plainText(secretMessage);
            aesCipher.Encrypt(messageToSend);
            //System.out.println("Encrypted message including signature: " + messageToSend.get_cipherText());

            //Encrypt secret key with receiver's public key
            String secretKeyEncoded = messageToSend.get_key();
            String keyAndIVBeforeEncryption = messageToSend.get_key() + delimiter + messageToSend.get_iv();
            //System.out.println("Pre-encryption secret key and IV: " + keyAndIVBeforeEncryption);

            String encryptedSecretKeyAndIV = rsaCipher.encrypt(keyAndIVBeforeEncryption, receiverPublicKeyPathName, transformation, encoding);
            //System.out.println("Encrypted secret key and IV: " + encryptedSecretKeyAndIV);

            //combined message end encrypted key with AES - this is what is sent
            entireMessage = messageToSend.get_cipherText() + delimiter + encryptedSecretKeyAndIV;
            System.out.println("Final secretMessage: " + messageToSend.get_cipherText());
            System.out.println("Final encryptedSecretKeyAndIV: " + encryptedSecretKeyAndIV);

            //write entire encrypted message ((encrypted (date+signature)) + encrypted key)  string to file
            out.println(entireMessage);
            out.flush();


            //Now simulate the receiver decrypting and verifying the signature
            //simulate receiver decrypting  - it knows 2 things...the senders public key (to verify signature) and its own private key


            //1) split message into:  encrypted message and encrypted key
            String[] encryptedMessageParts = entireMessage.split(regExSplitBy);
            String encryptedMessage = encryptedMessageParts[0];
            String encryptedKeyAndIV = encryptedMessageParts[1];

            System.out.println("encryptedMessage (recvd): " + encryptedMessage);
            System.out.println("encryptedKeyAndIV (recvd): " + encryptedKeyAndIV);

            Assert.assertTrue(encryptedMessage.equals(messageToSend.get_cipherText()));
            Assert.assertTrue(encryptedKeyAndIV.equals(encryptedSecretKeyAndIV));

            //2) decrypt the encrypted key into the original key and IV with the receiver's private key via RSA
            String originalSecretKeyAndIV = rsaCipher.decrypt(encryptedKeyAndIV, receiverPrivateKeyPathName, transformation, encoding);
            //System.out.println("Pre-encryption secret key and IV (recvd): " + originalSecretKeyAndIV);


            Assert.assertTrue(originalSecretKeyAndIV.equals(keyAndIVBeforeEncryption));


            String[] keyParts = originalSecretKeyAndIV.split(regExSplitBy);
            String originalKey = keyParts[0];
            String originalIV = keyParts[1];

            //3) decrypt the encrypted message using the original key and IV with AES
            AESMessageDTO receivedMessage = new AESMessageDTO();
            receivedMessage.set_key(originalKey);
            receivedMessage.set_iv(originalIV);
            receivedMessage.set_cipherText(encryptedMessage);

            //System.out.println("Encrypted message including signature (recvd): " + encryptedMessage);

            //use new object for decrypting
            AESCipher aesDecrypt = new AESCipher();
            aesDecrypt.Decrypt(receivedMessage);

            //4) split the decrypted messaged into original message and signature
            String[] plainTextParts = receivedMessage.get_plainText().split(regExSplitBy);
            String originalPlainText = plainTextParts[0];
            String originalSignature = plainTextParts[1];

            //System.out.println("Signature (recvd): " + originalSignature);

            //5) verify the signature using RSA and the senders public key
            Signature sigVerifier = Signature.getInstance("SHA256withRSA");
            sigVerifier.initVerify(rsaKeyPairSender.getPublicKey());
            sigVerifier.update(originalPlainText.getBytes("UTF-8"));

            byte[] originalSignatureBytes = Base64.getDecoder().decode(originalSignature);
            boolean signatureVerifiedByReceiver = sigVerifier.verify(originalSignatureBytes);
            if (signatureVerifiedByReceiver) {
                Assert.assertEquals(originalPlainText, originalPlainText);
            }
            else
            {
                //signature not correct
                Assert.fail();
            }





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
