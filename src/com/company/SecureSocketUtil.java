package com.company;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.CharBuffer;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.regex.Pattern.CASE_INSENSITIVE;
import static javax.crypto.Cipher.DECRYPT_MODE;

public class SecureSocketUtil {

    public static KeyStore truststore(String certificateLocation) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        //load the certificate
        X509Certificate cert = null;
        try(InputStream is = new FileInputStream(certificateLocation)){
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate)cf.generateCertificate(is);
        }

        //store the certificate key truststore
        KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
        ts.load(null); // create truststore on the fly
        ts.setCertificateEntry("client", cert); //store the certificate

        return ts;
    }

    public static KeyStore keystore(String certificateChianFileLocation,String privateKeyLocation, Optional<String> keyPassword) throws IOException, GeneralSecurityException {
        PKCS8EncodedKeySpec encodedKeySpec =
                SecureSocketUtil.readPrivateKey(new File(privateKeyLocation),Optional.empty());
        PrivateKey key;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            key = keyFactory.generatePrivate(encodedKeySpec);
        }
        catch (InvalidKeySpecException ignore) {
            KeyFactory keyFactory = KeyFactory.getInstance("DSA");
            key = keyFactory.generatePrivate(encodedKeySpec);
        }

        List<X509Certificate> certificateChain =
                SecureSocketUtil.readCertificateChain(new File(certificateChianFileLocation));
        if (certificateChain.isEmpty()) {
            throw new CertificateException("Certificate file does not contain any certificates: " + certificateChianFileLocation);
        }

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, "secret".toCharArray());

        keyStore.setKeyEntry("key", key, keyPassword.orElse("secret").toCharArray(),
                certificateChain.stream().toArray(Certificate[]::new));

        return keyStore;
    }

    private static PKCS8EncodedKeySpec readPrivateKey(File keyFile, Optional<String> keyPassword)
            throws IOException, GeneralSecurityException
    {
        String content = readFile(keyFile);

        Pattern KEY_PATTERN = Pattern.compile(
                "-+BEGIN\\s+.*PRIVATE\\s+KEY[^-]*-+(?:\\s|\\r|\\n)+" + // Header
                        "([a-z0-9+/=\\r\\n]+)" +                       // Base64 text
                        "-+END\\s+.*PRIVATE\\s+KEY[^-]*-+",            // Footer
                CASE_INSENSITIVE);

        Matcher matcher = KEY_PATTERN.matcher(content);
        if (!matcher.find()) {
            throw new KeyStoreException("found no private key: " + keyFile);
        }
        byte[] encodedKey = base64Decode(matcher.group(1));

        if (!keyPassword.isPresent()) {
            return new PKCS8EncodedKeySpec(encodedKey);
        }

        EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(encodedKey);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.getAlgName());
        SecretKey secretKey = keyFactory.generateSecret(new PBEKeySpec(keyPassword.get().toCharArray()));

        Cipher cipher = Cipher.getInstance(encryptedPrivateKeyInfo.getAlgName());
        cipher.init(DECRYPT_MODE, secretKey, encryptedPrivateKeyInfo.getAlgParameters());

        return encryptedPrivateKeyInfo.getKeySpec(cipher);
    }

    private static byte[] base64Decode(String base64)
    {
        return Base64.getMimeDecoder().decode(base64.getBytes(US_ASCII));
    }

    private static String readFile(File file)
            throws IOException
    {
        try (Reader reader = new InputStreamReader(new FileInputStream(file), US_ASCII)) {
            StringBuilder stringBuilder = new StringBuilder();

            CharBuffer buffer = CharBuffer.allocate(2048);
            while (reader.read(buffer) != -1) {
                buffer.flip();
                stringBuilder.append(buffer);
                buffer.clear();
            }
            return stringBuilder.toString();
        }
    }

    private static List<X509Certificate> readCertificateChain(File certificateChainFile)
            throws IOException, GeneralSecurityException
    {
        String contents = readFile(certificateChainFile);
        Pattern CERT_PATTERN = Pattern.compile(
                "-+BEGIN\\s+.*CERTIFICATE[^-]*-+(?:\\s|\\r|\\n)+" + // Header
                        "([a-z0-9+/=\\r\\n]+)" +                    // Base64 text
                        "-+END\\s+.*CERTIFICATE[^-]*-+",            // Footer
                CASE_INSENSITIVE);
        Matcher matcher = CERT_PATTERN.matcher(contents);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certificates = new ArrayList<>();

        int start = 0;
        while (matcher.find(start)) {
            byte[] buffer = base64Decode(matcher.group(1));
            certificates.add((X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(buffer)));
            start = matcher.end();
        }

        return certificates;
    }
}

// https://godoc.org/net#UDPConn.SetDeadline
