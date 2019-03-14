import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Main {
    private static String src = "章贵敏";

    public static void main(String[] args) {
        jdkRSA();
    }


    public static void jdkRSA() {
        try {
            //1.初始化密钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            //私钥
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
            //公钥
            RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();

            System.out.println("Private Key（公钥） : " + Base64.encodeBase64String(rsaPrivateKey.getEncoded()));
            System.out.println("Public Key （私钥）: " + Base64.encodeBase64String(rsaPublicKey.getEncoded()));

            //2.私钥加密、公钥解密——加密
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("私钥加密: " + Base64.encodeBase64String(result));

            //3.私钥加密、公钥解密——解密
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            result = cipher.doFinal(result);
            System.out.println("公钥解密：" + new String(result));

            System.out.println("------------------------------------------------------------------");

            //4.公钥加密、私钥解密——加密
            x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            result = cipher.doFinal(src.getBytes());
            System.out.println("公钥加密: " + Base64.encodeBase64String(result));

            //5.公钥加密、私钥解密——解密
            pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
            keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            result = cipher.doFinal(result);
            System.out.println("私钥解密：" + new String(result));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
