package com.grad.encryption;

import com.grad.encryption.Utils.ArrayUtils;
import com.grad.encryption.Utils.Base64Utils;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;



    public class Encryption {

        public static final String KEY_ALGORITHM = "RSA";

        public static int KEYSIZE = 1024;

        public static int decodeLen = KEYSIZE / 8;

        public static int encodeLen = KEYSIZE / 8 - 11;

        private static final String PUBLIC_KEY = "publicKey";

        private static final String PRIVATE_KEY = "privateKey";

        private static final String MODULES = "RSAModules";

        public static  String SIGNATURE_ALGORITHM = "MD5withRSA";

        public static final String ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";

        public static Map<String, Object> generateKeyPair() throws Exception {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            keyPairGen.initialize(KEYSIZE);
            KeyPair keyPair = keyPairGen.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            BigInteger modules = privateKey.getModulus();
            Map<String, Object> keys = new HashMap<String, Object>(3);
            keys.put(PUBLIC_KEY, publicKey);
            keys.put(PRIVATE_KEY, privateKey);
            keys.put(MODULES, modules);
            return keys;
        }

        public static String getPrivateKeyBytes(Map<String, Object> keys) throws Exception {
            Key key = (Key) keys.get(PRIVATE_KEY);
            return Base64Utils.encode(key.getEncoded());
        }

        public static String getPublicKeyBytes(Map<String, Object> keys) throws Exception {
            Key key = (Key) keys.get(PUBLIC_KEY);
            return Base64Utils.encode(key.getEncoded());
        }

        public static byte[] encryptPublicKey(byte[] encryptedData, String key) throws Exception {
            if (encryptedData == null){
                throw  new IllegalArgumentException("Input encryption data is null");
            }
            byte[] encode = new byte[] {};
            for (int i = 0; i < encryptedData.length; i += encodeLen) {
                byte[] subarray = ArrayUtils.subarray(encryptedData, i, i + encodeLen);
                byte[] doFinal = encryptByPublicKey(subarray, key);
                encode = ArrayUtils.addAll(encode, doFinal);
            }
            return encode;
        }


            byte [] buffers = new byte[]{};
            for (int i = 0; i < encode.length; i += decodeLen) {
                byte[] subarray = ArrayUtils.subarray(encode, i, i + decodeLen);
                byte[] doFinal = decryptByPrivateKey(subarray, key);
                buffers = ArrayUtils.addAll(buffers, doFinal);
            }
            return buffers;
        }

        public static PublicKey loadPublicKey(String publicKeyStr) throws Exception {
            try {
                byte[] buffer = Base64Utils.decode(publicKeyStr);
                KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
                return keyFactory.generatePublic(keySpec);
            }  catch (NoSuchAlgorithmException e) {
                throw new Exception("NoSuchAlgorithmException");
            } catch (InvalidKeySpecException e) {
                throw new Exception("InvalidKeySpecException");
            } catch (NullPointerException e) {
                throw new Exception("NullPointerException");
            }
        }

        public static PrivateKey loadPrivateKey(String privateKeyStr) throws Exception {
            try {
                byte[] buffer = Base64Utils.decode(privateKeyStr);
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
                KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
                return keyFactory.generatePrivate(keySpec);
            } catch (NoSuchAlgorithmException e) {
                throw new Exception("NoSuchAlgorithmException");
            } catch (InvalidKeySpecException e) {
                throw new Exception("InvalidKeySpecException");
            } catch (NullPointerException e) {
                throw new Exception("NullPointerException");
            }
        }


            Key privateKey = loadPrivateKey(key);

            Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            return cipher.doFinal(data);
        }


            return cipher.doFinal(data);
        }

       

    }




