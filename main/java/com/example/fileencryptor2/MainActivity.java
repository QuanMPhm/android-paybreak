package com.example.fileencryptor2;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import org.apache.commons.io.IOUtils;


import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class MainActivity extends AppCompatActivity {

    public static final int PERMISSIONS_REQUEST_READ_EXTERNAL_STORAGE = 1;
    Button btnEncryptFS;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        btnEncryptFS = (Button) findViewById(R.id.btnEncryptFS);

        btnEncryptFS.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    requestReadExternalStoragePermission();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (InvalidAlgorithmParameterException e) {
                    e.printStackTrace();
                }
            }
        });
    }

    //Reads a txt file from a fixed location in emulator
    public void readFile() {
        try {
            FileInputStream input = new FileInputStream("/sdcard/Download/sample3.docx");
            InputStreamReader isr = new InputStreamReader(input);
            BufferedReader br = new BufferedReader(isr);
            StringBuilder sb = new StringBuilder();
            String text = br.readLine();
            sb.append(text);
            input.close();
            Log.v("Original Text", String.valueOf(sb));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    private void encryptFS() throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        Toast.makeText(this, "Encrypting files...", Toast.LENGTH_LONG).show();

        readFile();

        //Opening the sample file and reading a line
        File input = new File("/sdcard/Download/sample3.docx");
        byte[] b = Files.readAllBytes(input.toPath());
        String bs = "";
        for (int i = 0; i < b.length; i++){
            bs = bs + (char) b[i];
        }

        Log.v("Byte text", bs);
        Log.v("Byte text encoded", Base64.getEncoder().encodeToString(b));
        /*
        InputStreamReader isr = new InputStreamReader(input);
        BufferedReader br = new BufferedReader(isr);
        String text = br.readLine();

         */

        /*
        FileInputStream fis = new FileInputStream("/sdcard/Download/sample3.docx");
        byte[] b = IOUtils.toByteArray(fis);
        String bs = "";
        for (int i = 0; i < b.length; i++){
            bs = bs + (char) b[i];
        }

        Log.v("Byte text", bs);

         */


        byte[] keyStart = "this is a key".getBytes();
        KeyGenerator kgen = KeyGenerator.getInstance("AES"); //Provides a KeyGenerator object that will generate keys for AES
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG"); //Provides SecureRandom object to provide randomness in key generation? SHA1PRNG is said to be deprecated?
        sr.setSeed(keyStart);
        kgen.init(128, sr); // 192 and 256 bits may not be available
        SecretKey skey = kgen.generateKey();
        byte[] key = skey.getEncoded();
        //Method to encrypt a line of text
        byte[] encryptedData = encrypt(key, b);
        String bec = "";
        for (int i = 0; i < encryptedData.length; i++){
            bec = bec + (char) encryptedData[i];
        }
        Log.v("Encrypted byte", bec);
        Log.v("Byte encrypted encoded", Base64.getEncoder().encodeToString(encryptedData));

        //Print the encrypted line of text to Logcat
        //String encryptedText = Base64.getEncoder().encodeToString(encryptedData);
        //Log.v("Encrypted Text", encryptedText);

        //Write to file
        FileOutputStream output = new FileOutputStream("/sdcard/Download/sample4.docx");
        output.write(encryptedData);
        output.close();

        File dir = new File("/sdcard/Download");
        String[] filenames = dir.list();
        for (String file : filenames) {
            Log.v("Files are:", file);
        }

    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private byte[] encrypt(byte[] key, byte[] b) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES"); //Creates a secret key from a given byte array(?)
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); //Instantiate and Provide Encryption algorithm to Cipher
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec); //Initialize mode, provide key, and randomly generate IV
        byte[] encrypted = cipher.doFinal(b); //Encrypt text

        return encrypted;
    }



    public void requestReadExternalStoragePermission() throws IllegalBlockSizeException, NoSuchAlgorithmException, IOException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (ContextCompat.checkSelfPermission(this,
                        Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
                    if (ActivityCompat.shouldShowRequestPermissionRationale(this,
                            Manifest.permission.READ_EXTERNAL_STORAGE)) {
                        AlertDialog.Builder builder = new AlertDialog.Builder(this);
                        builder.setTitle("Read External Storage permission");
                        builder.setPositiveButton(android.R.string.ok, null);
                        builder.setMessage("Please enable access to external storage.");
                        builder.setOnDismissListener(new DialogInterface.OnDismissListener() {
                            @TargetApi(Build.VERSION_CODES.M)
                            @Override
                            public void onDismiss(DialogInterface dialog) {
                                requestPermissions(
                                        new String[]
                                                {Manifest.permission.READ_EXTERNAL_STORAGE,
                                                Manifest.permission.WRITE_EXTERNAL_STORAGE,
                                                Manifest.permission.ACCESS_NETWORK_STATE,
                                                Manifest.permission.INTERNET}
                                        , PERMISSIONS_REQUEST_READ_EXTERNAL_STORAGE);
                            }
                        });
                        builder.show();
                    } else {
                        ActivityCompat.requestPermissions(this,
                                new String[]{Manifest.permission.READ_EXTERNAL_STORAGE,
                                        Manifest.permission.WRITE_EXTERNAL_STORAGE,
                                        Manifest.permission.ACCESS_NETWORK_STATE,
                                        Manifest.permission.INTERNET},
                                PERMISSIONS_REQUEST_READ_EXTERNAL_STORAGE);
                    }
                } else {
                    encryptFS();
                }
            } else {
                encryptFS();
            }
        }

    @Override
    public void onRequestPermissionsResult(int requestCode,
                                           String permissions[], int[] grantResults) {
        switch (requestCode) {
            case PERMISSIONS_REQUEST_READ_EXTERNAL_STORAGE: {
                if (grantResults.length > 0
                        && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    try {
                        encryptFS();
                    } catch (IOException e) {
                        e.printStackTrace();
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    } catch (IllegalBlockSizeException e) {
                        e.printStackTrace();
                    } catch (InvalidKeyException e) {
                        e.printStackTrace();
                    } catch (BadPaddingException e) {
                        e.printStackTrace();
                    } catch (NoSuchPaddingException e) {
                        e.printStackTrace();
                    } catch (InvalidAlgorithmParameterException e) {
                        e.printStackTrace();
                    }
                } else {
                    Toast.makeText(this, "You have disabled a file read permission",
                            Toast.LENGTH_LONG).show();
                }
            }
        }
    }
}