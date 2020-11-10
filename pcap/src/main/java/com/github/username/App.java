// App.java
package com.github.username;

import java.io.IOException;
import java.io.*;
import java.util.*;
import java.util.Base64;
import java.lang.Object;
import java.nio.file.Files;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.BpfProgram.BpfCompileMode;

import org.apache.tika.exception.TikaException;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.mime.MediaType;
import org.apache.tika.parser.ParseContext;
import org.apache.tika.sax.BodyContentHandler;
import org.apache.tika.parser.AbstractParser;
import org.apache.tika.parser.AutoDetectParser;
import org.apache.tika.sax.XHTMLContentHandler;

public class App {

    final static HashMap<String, ArrayList<String>> keyDictionary = new HashMap<String, ArrayList<String>>();


    public static void main(String[] args) throws Throwable {


        //Parsese files to find file type, allows determination of encrypted files
    	 /*
        File[] files = new File("C:\\Users\\Quan Minh Pham\\Documents\\Projects\\Ransomware 2020\\TestFolder").listFiles();
        for (File file : files) {

            InputStream stream = new FileInputStream(file);

            AutoDetectParser parser = new AutoDetectParser();s
            BodyContentHandler handler = new BodyContentHandler();
            Metadata metadata = new Metadata();

            try {
                // This step here is a little expensive
                parser.parse(stream, handler, metadata);
            } finally {
                stream.close();
            }

            
            if (mimetype == "application/x-tika-ooxml") {
                tika = new Tika(new DefaultDetector());
                TikaInputStream tis = TikaInputStream.get(stream);
                mimetype = tika.detect(tis);
                System.out.println(mimetype);
            }
            

            String contentType = metadata.get("Content-Type");
            System.out.println(contentType);
        }
        */

        
        //Code to parse a pcap file and filter through packets to find packets. packets are filtered using string
        
        PcapHandle handle;

        
		try {
   			handle = Pcaps.openOffline("C:\\Users\\Quan Minh Pham\\Documents\\Projects\\Ransomware 2020\\testTraffic", TimestampPrecision.NANO);
		} catch (PcapNativeException e) {
    		handle = Pcaps.openOffline("C:\\Users\\Quan Minh Pham\\Documents\\Projects\\Ransomware 2020\\testTraffic");
		}
        

        //Filter string for udp packets with port number 6000 on them
		String filter = "udp port 6000";
		handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

		PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                // Override the default gotPacket() function and process packet
                //Parses udp packet for key data
                
                //System.out.println(new String(packet.getRawData()));

                //From observation, it seems the 42th bit is where the keydata is located within a udp
                byte[] pdata = packet.getRawData();
                byte[] keydata = Arrays.copyOfRange(pdata, 42, pdata.length); 
                String keys = new String(keydata);
                String[] keyarray = keys.split("\n");
                

                String hash = keyarray[0];
                String iv = keyarray[1];
                //byte[] iv = Base64.getDecoder().decode(keyarray[0]);
				String mode = keyarray[2];
                String key = keyarray[3];
				//byte[] key = Base64.getDecoder().decode(keyarray[2]);
				String keymode = keyarray[4];

                ArrayList<String> keyinfo = new ArrayList<String>(Arrays.asList(iv, mode, key, keymode));
                keyDictionary.put(hash, keyinfo); //This keyDictionary can then be written to an key vault, exported elsewhere


                /*
				try {
					File input = new File("C:\\Users\\Quan Pham\\Desktop\\Projects\\2020 Ransomware\\sample4.docx");
					//System.out.println(encrypted);
					byte[] bytetxt = Files.readAllBytes(input.toPath());
					System.out.println(Base64.getEncoder().encodeToString(bytetxt));
					byte[] decrypted = decrypt(bytetxt, iv, mode, key, keymode);
					//System.out.println(decrypted);
					FileOutputStream output = new FileOutputStream("C:\\Users\\Quan Pham\\Desktop\\Projects\\2020 Ransomware\\sample5.docx");
					output.write(decrypted);
					output.close();

				} catch (Exception e) {
					e.printStackTrace();
				}
                */
            }
        };

        // Tell the handle to loop using the listener we created
        try {
            int maxPackets = 1000;
            handle.loop(maxPackets, listener);
        } catch (Exception e) {
            e.printStackTrace();
        }


        // Cleanup when complete
        handle.close();
		
        BufferedWriter bw = new BufferedWriter(new FileWriter("C:\\Users\\Quan Minh Pham\\Documents\\Projects\\Ransomware 2020\\dictionary.txt"));
        bw.write(keyDictionary.toString());
        bw.close();
    }

    //Decryption function
    static byte[] decrypt(byte[] txt, byte[] iv, String mode, byte[] key, String keymode) throws Exception {
		SecretKeySpec skeySpec = new SecretKeySpec(key, keymode); //Get key
        Cipher decipher = Cipher.getInstance(mode); //Set algorhythm
        GCMParameterSpec ivspec = new GCMParameterSpec(key.length*8,iv); //Get IV
        decipher.init(Cipher.DECRYPT_MODE, skeySpec, ivspec); //Intialize with all parameters
        byte[] decryptedData = decipher.doFinal(txt); //Decrypt
        //String decrytedText = new String(decryptedData);
        return decryptedData;
    }


    static String getCipherText(String filepath) throws Exception {
    	BufferedReader txtbr = new BufferedReader(new InputStreamReader(new FileInputStream(filepath)));
    	String encrypted = txtbr.readLine();
    	return encrypted;
    }

}