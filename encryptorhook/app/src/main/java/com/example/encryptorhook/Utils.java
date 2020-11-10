package com.example.encryptorhook;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class Utils {

    // generates sha256sum of an input file
    public static String getFileChecksum(String path_src) throws NoSuchAlgorithmException, IOException {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        //Get file input stream for reading the file content
        FileInputStream fis = new FileInputStream(path_src);

        //Create byte array to read data in chunks
        byte[] byteArray = new byte[1024 * 4];
        int bytesCount = 0;

        //Read file data and update in message digest
        while ((bytesCount = fis.read(byteArray)) != -1) {
            digest.update(byteArray, 0, bytesCount);
        }

        fis.close();

        //Get the hash's bytes
        byte[] bytes = digest.digest();

        //This bytes[] has bytes in decimal format;
        //Convert it to hexadecimal format
        StringBuilder sb = new StringBuilder();
        for(int i=0; i< bytes.length ;i++)
        {
            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }

        //return complete hash
        return sb.toString();
    }

}
