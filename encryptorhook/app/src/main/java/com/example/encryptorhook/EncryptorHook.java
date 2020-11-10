package com.example.encryptorhook;

import android.os.Build;

import androidx.annotation.RequiresApi;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.Base64;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;

public class EncryptorHook implements IXposedHookLoadPackage {

    private Socket socket;
    private static final String SERVER_IP = "192.168.100.4";
    private static final int SERVERPORT = 6000;

    // exclude built-in apps and root/hook related packages
    static boolean isSystemApp(String pkgName) {
        return (pkgName.matches("^(com\\.android\\.|com\\.google\\.android\\.|eu\\.chainfire\\.supersu|de\\.robv\\.).*$"));
    }


    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        XposedBridge.log("Loaded app: " + lpparam.packageName);


        if (isSystemApp(lpparam.packageName))
            return;
        
        XposedBridge.log("App detected!");

        String srcDir = lpparam.appInfo.sourceDir;
        final String sha256sum = Utils.getFileChecksum(srcDir);


        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "init", int.class, Key.class,  new XC_MethodHook() {

            @RequiresApi(api = Build.VERSION_CODES.O)
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                // this will be called after the clock was updated by the original method
                XposedBridge.log("Inside encryptor init of Cipher class");
                XposedBridge.log("Now retrieve key and generated IV");


                Cipher xcipher = (Cipher) param.thisObject;
                byte[] xiv = xcipher.getIV();
                String encryptmode = xcipher.getAlgorithm();
                SecretKeySpec sks = (SecretKeySpec) param.args[1];
                String keymode = sks.getAlgorithm();
                byte[] key = sks.getEncoded();

                String sxiv = Base64.getEncoder().encodeToString(xiv);
                String skey = Base64.getEncoder().encodeToString(key);


                XposedBridge.log("Creating sockets");
                new Thread(new ClientThread(sha256sum, encryptmode, keymode, sxiv, skey)).start();
                XposedBridge.log("Finished sockets");


            }
        });


    }

    class ClientThread implements Runnable {

        private final String sha256sum;
        private final String mode;
        private final String iv;
        private final String key;
        private final String keymode;

        ClientThread(String sha256sum, String ciphermode, String kmode, String iv2, String key) {
            this.sha256sum = sha256sum;
            this.mode = ciphermode;
            this.iv = iv2;
            this.key = key;
            this.keymode = kmode;
        }

        @Override
        public void run() {

            try {

                XposedBridge.log("Socket made");
                String payloadString = sha256sum + "\n" + iv + "\n" + mode + "\n" + key + "\n" + keymode;
                byte[] payload = payloadString.getBytes();
                DatagramSocket d_socket = new DatagramSocket();
                InetAddress d_IPaddr = InetAddress.getByName(SERVER_IP);
                DatagramPacket d_packet = new DatagramPacket(payload, payload.length, d_IPaddr, SERVERPORT);
                d_socket.send(d_packet);

                /*
                InetAddress serverAddr = InetAddress.getByName(SERVER_IP);
                socket = new Socket(serverAddr, SERVERPORT);
                XposedBridge.log("Socket made");
                BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
                bw.write(iv );
                bw.newLine();
                bw.write(mode);
                bw.newLine();
                bw.write(key );
                bw.newLine();
                bw.write(keymode);
                bw.flush();
                */

                XposedBridge.log("mode is " + mode);
                XposedBridge.log("iv is " + iv);
                XposedBridge.log("key is " + key);
                XposedBridge.log("keymode is " + keymode);

                d_socket.close();
                XposedBridge.log("Socket closed");

            } catch (UnknownHostException e1) {
                e1.printStackTrace();
            } catch (IOException e1) {
                e1.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            }

        }

    }

}


