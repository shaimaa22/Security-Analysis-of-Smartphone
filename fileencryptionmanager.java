package com.grad.encryption;
import android.util.Log;
import com.grad.encryption.Utils.Base64Utils;
import com.grad.encryption.Utils.FileUtils;
import java.io.File;
import java.util.Map;

import static com.grad.encryption.Encryption.encryptPublicKey;



public class FileEncryptionManager {
    private static FileEncryptionManager INSTANCE;
    private String publicKey;
    private String privateKey;

    private FileEncryptionManager() {
    }

    public static FileEncryptionManager getInstance(){
        if (INSTANCE == null){
            INSTANCE = new FileEncryptionManager();
        }
        return INSTANCE;
    }
    public void setEncryptionType(String Type)

    {
        Encryption.setEncryptionType(Type);
    }


    public void setRSAKey(String publicKey, String privateKey, boolean isEncode) throws Exception {
        if (isEncode){
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }else {
            this.publicKey = Base64Utils.encode(publicKey.getBytes());
            this.privateKey = Base64Utils.encode(privateKey.getBytes());
        }
    }

    public void generateKey() throws Exception {
        Map<String, Object> map = Encryption.generateKeyPair();
        this.privateKey = Encryption.getPrivateKeyBytes(map);
        this.publicKey = Encryption.getPublicKeyBytes(map);
    }



    public byte[] encryptFileByPublicKey(File inputFile, File outFile) throws Exception {
        if (publicKey == null || publicKey.isEmpty()){
            throw new IllegalArgumentException("PublicKey is empty, you should invoke setRSAKey or generateKey");
        }
        byte[] data = FileUtils.getDataFromFile(inputFile);
        byte[] encryData = encryptPublicKey(data, publicKey);

        return encryData;
    }


        byte[] data = FileUtils.getDataFromFile(inputFile);
        byte[] decryData = Encryption.decryptPrivateKey(data, privateKey);
        if (outFile != null){
            boolean result = FileUtils.saveDataToFile(decryData, outFile);
            Log.d("FileEncryptionManager", "save file result "+result);
        }
        return decryData;
    }






}