package chat;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.Scanner;


public class Server {
	
	//used exclusively by RSA method()
	public static BigInteger p, q, theta, e, n, d, exponent, temp;	//private to server
	
	public static BigInteger client_e, client_n; //client's public key
	public static String username, corp;
	public static Boolean handshakeState = true;
	
	//used to open server
	private static ServerSocket socket;	
	private static final int port = 5555;
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException{
		//to start server
		//must open a local socket to start local host for client
		socket = new ServerSocket(port);
		
		//testing server
		System.out.println("Server Started on port: " + port);
		
		//creating socket and waiting for client's connection
		System.out.println("[SERVER] Waiting for the client connection...");
        Socket server_socket = socket.accept();
        System.out.println("[SERVER] Connected to client"); //displays once connected
        
        //receiving message and stores it
        //read from socket to InputStreamReader object
        BufferedReader inputMessage = new BufferedReader(new InputStreamReader(server_socket.getInputStream()));
        
        //create object to broadcast data
        PrintWriter outputMessage = new PrintWriter(server_socket.getOutputStream(), true);
        
        //setup for sending (encryption and decryption)
        RSA();
        
        //gets public key from client
        getClientsPublicKey(server_socket);
        
        //sends server's public key
        sendServerPublicKey(outputMessage);
        
        //setup handshake
        handshake(inputMessage);
        
        //listens for incoming messages
  		//decides what to do with messages
        try {
        	System.out.println("Welcome "+ username + " from " + corp);
        	while(handshakeState) {
    	        //stores encrypted data to variable
    	        String cipher = inputMessage.readLine();
    	        
    	        //prints received message
    	        System.out.println("[SERVER] Message Received: " + cipher);
    	        
    	        //write object to Socket (broadcast to client)
    	        //decrypts text to make a decision
    	        String message = decrypt(cipher, d, n);
    	        if(message.equals("hello")) {
    	        	System.out.println("From client: "+ message);
    		        //outputMessage.println("[SERVER] Hi");
    	        	outputMessage.println(encrypt("[SERVER] Hi", client_e, client_n));
    	        }
    	        
    	        //exits loop to close entire server
    	        else if(message.equals("exit")) {
    	        	outputMessage.println(encrypt("[SERVER] Bye", client_e, client_n));
    	        	break;
    	        }
    	        
    	        else {
    	        	outputMessage.println(encrypt( "[SERVER] not a command, try again" , client_e, client_n));
    	        }
            }
        } finally {
      		//closes server
            //closes the input and output stream
            //System.out.println("HERE");
            outputMessage.close();
            inputMessage.close();
            socket.close();
        }  		
	}
	
	public static void handshake(BufferedReader inputMessage) throws IOException, NoSuchAlgorithmException {
		//receive data (4) from client
		String userCipher = inputMessage.readLine();
		String corpCipher = inputMessage.readLine();
		String otkCipher = inputMessage.readLine();
		String cipherFullPacket = inputMessage.readLine();
		
		//decrypt username with server's private key
		username = decrypt(userCipher, d, n);
		
		//decrypt company with client's public key
		corp = decrypt(corpCipher, client_e, client_n);
		
		//decrypt otk with servers private key
		otkCipher = decrypt(otkCipher, d, n);
		
		//decrypt cipher with otk bitwise or
		String fullPacket = "";
		for(int d = 0; d<cipherFullPacket.length(); d++) {
			fullPacket = fullPacket + String.valueOf(Character.getNumericValue(cipherFullPacket.charAt(d)) ^ Character.getNumericValue(otkCipher.charAt(d)));
		}
		
		//get data bits size on start of packet
		int nDataBytesSize; //= Character.getNumericValue(fullPacket.charAt(0));
		String temp = "";
		for(int e =0; e < 8 ; e++) {
			temp = temp + fullPacket.charAt(e); //String.valueOf(fullPacket.charAt(e));
		}
		//binary to int 
		nDataBytesSize = Integer.parseInt(temp,2);  
		
		//determine proper data byte size and if there is a filler (assuming that packet is size of 5)
		String[] data_bytes = new String [24];
			//makes them all 0
		for(int g = 8; g < data_bytes.length; g++) {
			data_bytes[g] = "0";
		}
			//overrides withh correct values
		for(int f =8; f < (8 * nDataBytesSize)+8 ; f++) {
			data_bytes[f-8] = 
					String.valueOf(fullPacket.charAt(f));
		}
		
		////////////////////////////////////////////////////////////////
		//compare checksum and determine state 
		String checkSum = hash(data_bytes);
		////////////////////////////////////////////////////////////////
		//compare with fullpacket checksum
		for(int h = 24; h < fullPacket.length(); h++) {
			//if one digit doesnt match then it boots user out
			if(fullPacket.charAt(h) != checkSum.charAt(h) ) {
				handshakeState = false;
			}
		}
	}
	
	public static String hash(String[] data_bytes) {
		//generates checksum with values 
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
		
		return fullPacket;
	}
	
	public static void getClientsPublicKey(Socket server_socket) throws IOException {
        //used to get from client
        //ObjectInputStream objIn = new ObjectInputStream(server_socket.getInputStream());
        Scanner scan = new Scanner(new InputStreamReader(server_socket.getInputStream()));
        
        //receives client's public key e then n
        client_e = scan.nextBigInteger();
        client_n = scan.nextBigInteger();
        System.out.println("[SERVER] Received public key ");
        
        System.out.println("client_e is: " + client_e);
        System.out.println("client_n is: " + client_n);
        
	}
	
	public static void sendServerPublicKey(PrintWriter send) {
		send.println(e);
		send.println(n);
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
		//System.out.println("ciphertextSplit is: " + ciphertext);
		return ciphertext;
	}
	
	public static String decrypt(String ciphertext, BigInteger x_d, BigInteger x_n) {
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
			//big[b] = BigDecimal.valueOf(Math.pow(cipher[b], d.intValue())).toBigInteger();
			big[b] = BigInteger.valueOf(cipher[b]);
			big[b] = big[b].pow(x_d.intValue());
			
			//mod n
			big[b] = big[b].mod(x_n);
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
	
	public static void RSA() {
		
		//public key is {e,n}
		//private key is {d,n}
		
		//generate public and private key in RSA algorithm
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
		//System.out.println("exponoent is: " + exponent);	//testing
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
