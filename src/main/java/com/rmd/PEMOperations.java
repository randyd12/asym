package com.rmd;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

//import org.apache.commons.codec.binary.Base64;

/**
 * Created by randy on 2/14/2017.
 */
public class PEMOperations {
//    public PrivateKey getPemPrivateKey(String filename, String algorithm) throws Exception {
//        File f = new File(filename);
//        FileInputStream fis = new FileInputStream(f);
//        DataInputStream dis = new DataInputStream(fis);
//        byte[] keyBytes = new byte[(int) f.length()];
//        dis.readFully(keyBytes);
//        dis.close();
//
//        String temp = new String(keyBytes);
//        String privKeyPEM = temp.replace("-----BEGIN PRIVATE KEY-----", "");
//        privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
//        //System.out.println("Private key\n"+privKeyPEM);
//
//        BASE64Decoder b64 = new BASE64Decoder();
//        byte[] decoded = b64.decodeBuffer(privKeyPEM);
//
//        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
//        KeyFactory kf = KeyFactory.getInstance(algorithm);
//        return kf.generatePrivate(spec);
//    }

    public PrivateKey getPrivateKeyFromDER(String filename, String algorithm) throws Exception {
        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePrivate(spec);
    }

    public PublicKey getPubKeyFromDER(String filename, String algorithm) throws Exception {
        PublicKey rv = null;

        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePublic(spec);
    }


}


