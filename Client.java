package chat;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.Scanner;

public class Client {
	
	//used exclusively by RSA method()
	public static BigInteger p, q, theta, e, n, d, exponent, temp;	//all private for client
	public static BigInteger server_e, server_n;	//sever's public keys
	
	public static void main(String[] args) throws IOException, UnknownHostException, NoSuchAlgorithmException{
		//gets local host address
		Socket socket = new Socket("127.0.0.1", 5555);
		
		System.out.println("[Client]");
		
		//read from socket to ObjectInputStream object
		BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		
		//gets client's input
		BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));
		
		//sends to server
		PrintWriter send = new PrintWriter(socket.getOutputStream(), true);
		

		//System.out.println("[Client step2]");	//testing purposes
		//setup for sending (encryption and decryption)
		RSA();
		
		System.out.println("client_e is: " + e);
		System.out.println("client_n is: " + n);
		
		sendServerPublicKey(send);	//test it out
		
		getServerPublicKey(socket);	//test it out
		
		handshake(send);
		
		while(true) {
			//signify user input
			System.out.print("\n> ");
			
			//gets user input
			String command = keyboard.readLine();
			//String command = scan.nextLine();
						
			//encrypts text
			String cipher = encrypt(command, server_e, server_n);
			
			//send encrypted text to socket
			//send.println(command);	//works for strings only
			send.println(cipher);
			
	        //gets server text and displays it
			String serverCipher = input.readLine();
			//uses server's private key d
			System.out.print(decrypt(serverCipher));	             
	        
			//exits on client's command
			if(command.equals("exit")) break;
			
		}
		//closes server
		input.close();
		socket.close();
	}
	
	public static String encrypt(String message, BigInteger x_e, BigInteger x_n) {
		//ciphertext=(plaintext)^e mod n
		String ciphertext = "";
		
		//convert string into char array
		//convert each char to ascii (array of ints) cast int as BigIntger
		//run rsa encrypt into each int array and send to client  
		
		//encrypted with clients public key e
		
		//breaks up plaintext to char array
		char[] ch = message.toCharArray();
		
		BigInteger big[] = new BigInteger[ch.length];
		int ascii[] = new int[ch.length];
		
		for(int i=0; i < ch.length; i++) {
			
			//converts char to ascii(int)
			ascii[i] = (int) ch[i]; 
			
			//calculates the plaintext with exponent value of each bigint (performs plaintext^e) mod n
			big[i] = BigDecimal.valueOf(Math.pow(ascii[i], x_e.intValue())).toBigInteger().mod(x_n);
			
			//convert it back to int value
			ascii[i] = big[i].intValue();
		}
		
		//adds it to start cipher
		ciphertext = String.valueOf(ascii[0]);
		
		//makes cipher text of only int
		for(int i = 1; i<ascii.length; i++) {
			ciphertext = ciphertext + "," + String.valueOf(ascii[i]);
		}
		
		//send back to send to socket
		//System.out.println("ciphertext is: " + ciphertext);
		return ciphertext;
	}
	
	public static String decrypt(String ciphertext) {
		//plaintext=(ciphertext)^d mod n 
		
		//changes ciphertext string to string array
		String[] ciphertextSplit = ciphertext.split(",");
		
		//System.out.println("ciphertextSplit is: " + Arrays.toString(ciphertextSplit)); //testing
		int[] cipher = new int[ciphertextSplit.length];
		
		//changes it to an integer array from a string
		for(int i=0; i< ciphertextSplit.length; i++) {
			cipher[i] = Integer.parseInt(ciphertextSplit[i]);
		}
		
		//does regular operations/calculations
		BigInteger big[] = new BigInteger[cipher.length];
		String message = "";
		
		//ciphertext^d	
		for(int b=0; b<cipher.length; b++) {
			//converts int to bigint
			big[b] = BigInteger.valueOf(cipher[b]);
			big[b] = big[b].pow(d.intValue());
			
			//mod n
			big[b] = big[b].mod(n);
		}
		
		
		char tempChar;
		int tempInt;
		
		//convert BigInt to text
		for(int i= 0; i<cipher.length; i++) {
			//convert string to int
			tempInt = big[i].intValue();
			
			//convert int to char
			tempChar = (char) tempInt;
			
			//Concatenate in messahe
			message = message + tempChar;

		}
	 	
		//send back plaintext
		//message = new String(stringChar);
		return message;
	}
	
	public static void handshake(PrintWriter send) throws NoSuchAlgorithmException {
		//username
		String username = "alex";
		//company
		String corp = "c";
		//one time key
		//String otk;
		
		String fullPacket = hash();
		
		//one time key
		String otk = "1010011000101110011101010101011010001110";
		
 
		//encrypt name with server's public Key
		String cipherUsername = encrypt(username, server_e, server_n);
		
		//encrypt company with client's private key
		String cipherCorp = encrypt(corp, d, n);
		
		//encrypt otk with server's public key
		String cipherOtk = encrypt(otk, server_e, server_n);
		
		//System.out.println("Fullpacket under handshake before XOR: " + fullPacket); //testing
		//System.out.println("Fullpacket under handshake before XOR SIZE: " + fullPacket.length()); //testing
		//System.out.println("otk under handshake before XOR SIZE: " + otk.length()); //testing
		
		
		//encode fullPacket with otk in bitwise exclusive or
		String cipherFullPacket = "";	
		for(int d = 0; d<otk.length(); d++) {
			cipherFullPacket = cipherFullPacket + String.valueOf(Character.getNumericValue(fullPacket.charAt(d)) ^ Character.getNumericValue(otk.charAt(d)));
		}
		
		//System.out.println("cipherfullpacket under handshake: " + cipherFullPacket);
		
		//send all to server
		send.println(cipherUsername);
		send.println(cipherCorp);
		send.println(cipherOtk);
		send.println(cipherFullPacket);
		
	}
	
	public static String hash() {
		//generates checksum with values
		String[] data_bytes = {"0","1","1","0","0","1","0","1",  "1","0","1","1","0","1","0","1"  ,"0","0","0","0","0","0","0","0"};
		String databBytes = "";	//copy of the above in string form
		int ndatabytes = 2;
		int intncheckbytes = 1;
		int k = 7;
		String[] pattern = {"0", "1", "1", "1", "1", "0", "1", "1"}; //123
		String temp = ""; //will hold *k value
		String temp2;
		String checkSum1 = "";
		String checkSum2 = "";
		String checkSum3 = "";
		int decValue;
		String binary = "";
		
		//creating new checksum
		//checsum1
		int y = 0;
		for(int i=0; i<8; i++) {
			temp2 = String.valueOf(Integer.parseInt(data_bytes[i]) & Integer.parseInt(pattern[y]));
			y = y + 1;
			
			//concatinate after done for fill value
			checkSum1 = checkSum1 + temp2;
		}
		
		//checksum2
		y=0;
		for(int i=8; i<16; i++) {
			temp2 = String.valueOf(Integer.parseInt(data_bytes[i]) & Integer.parseInt(pattern[y]));
			y = y + 1;
			
			//concatinate after done for fill value
			checkSum2 = checkSum2 + temp2;
		}
		
		//checksum3
		y=0;
		for(int i=16; i<data_bytes.length; i++) {
			temp2 = String.valueOf(Integer.parseInt(data_bytes[i]) & Integer.parseInt(pattern[y]));
			y = y + 1;
			
			//concatinate after done for fill value
			checkSum3 = checkSum3 + temp2;
		}
		
		//add all values of check sums as decimal value
		decValue = Integer.parseInt(checkSum1,2) + Integer.parseInt(checkSum2,2) + Integer.parseInt(checkSum3,2);
		//System.out.println("binary is before decimal is: " + temp); //testing
				
		//* k
		decValue = (decValue * k);
		
		//decimal to binary
		temp = Integer.toBinaryString(decValue);
		//System.out.println("binary after *k is: " + temp); //testing
		
		//finds difference to get 8 from string
		int tt=0;
		for(int r=0; r<temp.length(); r++ ) {
			tt++;
			if(temp.length() - tt == 8) {r = temp.length()+1;}
		}
		//convert to string and keep last 8 digits as value
		for(int a = tt; a < temp.length() ;a++) {	//will show up reversed
			binary = binary + String.valueOf(temp.charAt(a));
		}
		
		//for conversion reasons to get as string
		for(int u = 0; u< data_bytes.length; u++) {
			databBytes = databBytes + data_bytes[u];
		}
		
		//full packet that must be sent as binary string
		String fullPacket = String.format("%8s", Integer.toBinaryString(ndatabytes)).replaceAll(" ", "0") + databBytes + binary.toString();
		
		//System.out.println("binary after *k is: " + fullPacket);	//testing
		return fullPacket;
	}
	
	public static void getServerPublicKey(Socket server_socket) throws IOException {
        //used to get from client
        //ObjectInputStream objIn = new ObjectInputStream(server_socket.getInputStream());
        Scanner scan = new Scanner(new InputStreamReader(server_socket.getInputStream()));
        
        //receives client's public key e then n
        server_e = scan.nextBigInteger();
        server_n = scan.nextBigInteger();
        System.out.println("[SERVER] Received public key ");
        
        System.out.println("server_e is: " + server_e);
        System.out.println("server_n is: " + server_n);
        
	}
	
	public static void sendServerPublicKey(PrintWriter send) {
		//sending public key e and n to server
		send.println(e);
		send.println(n);
		
	}
	
	public static void RSA() {
		
		//public key is {e,n}
		//private key is {d,n}
		
		//generate public and private key in RSA algorithm
		//BigInteger p, q, theta, e, n, d, exponent, temp;
		BigInteger one = new BigInteger("1");
		
		Random rand = new Random();
		
		//generate large prime p using big int
		//generate large prime q using big int
		p = BigInteger.probablePrime(4, rand);
		q = BigInteger.probablePrime(4, rand);
		
		
		while(!(p.isProbablePrime(1)) ) {
			if(p.isProbablePrime(1)) {
				//p = BigInteger.probablePrime(4, rand);
				p = p.add(one);
			}
		}
		
		while(!(q.isProbablePrime(1))) {
			if(q.isProbablePrime(1)) {
				//q = BigInteger.probablePrime(4, rand);
				q = q.add(one);
			}
		}
		
		//calculate n
		n = p.multiply(q);
		//System.out.println("n is: " + n); //testing
		
		//calculate theta(n)
		theta = phi(n);
		
		//System.out.println("theta is: "+ theta); //for testing
		
		//calculate e that is relatively prime
		e = new BigInteger("2") ;
		while(!(theta.gcd(e).compareTo(one) == 0)) {
			e = e.add(one);
		}
		
		//System.out.println("e is: " + e);//for testing
		
		//calculate d
		exponent = phi(theta);
		exponent = exponent.subtract(one);
		
		//System.out.println("exponent is: " + exponent);	//testing
		
		d = e;
		temp = e;
		
		while( !(exponent.compareTo(new BigInteger("1")) == 0) ) {
			d = d.multiply(temp);
			exponent = exponent.subtract(one);
		}
		d = d.mod(theta);
		
		//System.out.println("d is: " + d);//for testing
		
	}
	
	public static BigInteger phi(BigInteger n) {
		BigInteger result = new BigInteger("1");
		BigInteger one = new BigInteger("1");
		BigInteger i = new BigInteger("2");
		
		while(i.compareTo(n) == -1) {	// if i is less than n
			//System.out.println("i: " + i + ", n: " + n + ", gcd: " + i.gcd(n));//testing
			if( i.gcd(n).compareTo(one) == 0) {
				result = result.add(one);
			}
			i = i.add(one);
		}
		return result;
	}
	
}