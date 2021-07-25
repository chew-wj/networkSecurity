package Bob;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Scanner;
import java.util.Base64;
import javax.sound.midi.SysexMessage;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;
import java.security.*;
import static java.nio.charset.StandardCharsets.UTF_8;



public class Client{
    //session username and password
    public static String username;
    public static String password;
    //session ssk
    public static byte Bssk[]=null;
    public static boolean online = true;
    public static boolean sendtoggle = false;
    public static boolean recievetoggle = true;


    public static void main(String args[]) throws IOException,Exception,InvalidKeyException
    {   
        //ask clientside for username and password
        usernameAndPassword();

        //handshake protocol by bob
        ClientSideHandshake();

        while(online)
        {
            while(sendtoggle)
            {
                ClientSend();
            }
            while(recievetoggle)
            {
                ClientRecieve();
            }
        }
    }

    public static void ClientSend() throws IOException,Exception
    {
        Scanner sc = new Scanner(System.in);
        DatagramSocket ds = new DatagramSocket();
 
        InetAddress ip = InetAddress.getLocalHost();
        byte buf[] = null;
        byte h[] = null;
         // loop while user not enters "bye"
         while (true)
         {
             System.out.print("\nClient: ");
             String inp = sc.nextLine();
             //concate ssk||m||ssk
             String hValue = convertBytesToHex(Bssk) + inp + convertBytesToHex(Bssk);

             //encode h using SHA-1
             MessageDigest sha1 = MessageDigest.getInstance("SHA1");
             h = sha1.digest(hValue.getBytes());
             

             //create SKEssk (RC4 key)
             SecretKeySpec rc4Key = new SecretKeySpec (Bssk,"RC4");

             //encrypt m||h to get c
             String mandh = inp+","+convertBytesToHex(h);
             System.out.println("m||h before SKEssk(RC4 Encryption): "+ mandh);
             String C = encryptRC4(mandh, rc4Key);
             System.out.println("Message sent to Alice after RC4 encryption: "+C);

  
             // convert the String input into the byte array.
             buf =C.getBytes();
  
             // Step 2 : Create the datagramPacket for sending
             // the data.
             DatagramPacket DpSend =
                   new DatagramPacket(buf, buf.length, ip, 12345);
  
             // Step 3 : invoke the send call to actually send
             // the data.
             ds.send(DpSend);

             sendtoggle = false;
             recievetoggle = true;
             
  
             // break the loop if user enters "bye"
             if (inp.equals("exit"))
             {
                online = false;
                System.exit(0);
                break;
             }
               

            if(sendtoggle == false)
            {
                break;   
            }

         }
         ds.close();

    }

    public static void ClientRecieve() throws IOException,Exception
    {
        // Step 1 : Create a socket to listen at port 12345
        DatagramSocket ds = new DatagramSocket(22345);
        byte[] receive = new byte[65535];
 
        DatagramPacket DpReceive = null;
        byte hprime[] = null;
        while (true)
        {
 
            // Step 2 : create a DatgramPacket to receive the data.
            DpReceive = new DatagramPacket(receive, receive.length);
 
            // Step 3 : revieve the data in byte buffer.
            ds.receive(DpReceive);

            //create rc4 key
            SecretKeySpec rc4Key = new SecretKeySpec(Bssk,"RC4");
            //decrypt message
            String decryptRecieve = decryptRC4(data(receive).toString(), rc4Key);

            //split h from message 
            String [] mandh = decryptRecieve.split(",");
            String m = mandh[0];
            String hfromA = mandh[1];

            //bob compute ssk||m||ssk
            String sskandm = convertBytesToHex(Bssk) + m + convertBytesToHex(Bssk);
            //encode h' using SHA-1
            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            hprime = sha1.digest(sskandm.getBytes());


            if(hfromA.equals(convertBytesToHex(hprime))){
                System.out.println("\nDecryption Sucessful!");
                System.out.println("Server: " + data(receive));
                System.out.println("RC4 Decrypted Message: " +m);
                //System.out.println("h': "+ convertBytesToHex(hprime) + "h: "+ hfromA); 
            }else{
                System.out.println("Decryption Error!");
            }
            


            recievetoggle = false;
            sendtoggle = true;
            
            // Exit the server if the client sends "bye"
            if (m.equals("exit"))
            {
                online = false;
                System.out.println("Server exited the program!");
                System.exit(0);
                break;
            }
 
            // Clear the buffer after every message.
            receive = new byte[65535];

            if (recievetoggle == false)
            {
                 break;
            }
        }

        ds.close();
    }

    public static void usernameAndPassword()
    {
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter username:");
        username = sc.nextLine();
        System.out.print("Enter Password:");
        password = sc.nextLine();
    }

    public static void ClientSideHandshake() throws IOException,InvalidKeyException,Exception
    {
        //create socket object to send NB to Alice(server)
        DatagramSocket ds1 = new DatagramSocket();
        InetAddress ip = InetAddress.getLocalHost();
        byte buf[] = null;

        //create NB (128 bits random number)
        Random rand = new SecureRandom();
        byte [] nb = new byte[16];
        rand.nextBytes(nb);
        buf = nb;
        //send NB over to Alice (Server) on port 12345
        System.out.println("\nSending NB over to Alice: "+ convertBytesToHex(nb));
        DatagramPacket nbsend = new DatagramPacket(buf, buf.length,ip,12345);
        ds1.send(nbsend);
        ds1.close();

        //listen on port 22345 for Alice's PK and NA
        DatagramSocket ds2 = new DatagramSocket(22345);
        byte[] pkandna = new byte[310];
        DatagramPacket pknaRecieve = null;
        pknaRecieve = new DatagramPacket(pkandna,pkandna.length);
        ds2.receive(pknaRecieve);

        //break the pk and na package recieved into pk and na respectively
        byte [] APK = new byte[294];
        for (int i =0;i<294;i++)
        {
            APK[i] = pkandna[i];
        }
        //System.out.println("\n\nAlice pk: "+convertBytesToHex(APK));
        //get alice's NA
        byte [] ANA = Arrays.copyOfRange(pkandna,294,310);
        //System.out.println("\nAlice na: "+convertBytesToHex(ANA));

        System.out.println("\nAlice's PK and NA: " + convertBytesToHex(pkandna));
        //alice's public key object
        PublicKey Apublickey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(APK));
        //System.out.println("\n"+Apublickey);
        ds2.close();
        System.out.println();

        //generate random number to get string from PKE
        Random randstring = new Random();
        int upperbound = 294;
        int randomUpper = rand.nextInt(upperbound);
        int randomLower = rand.nextInt(randomUpper);
        int noOfChar = randomUpper - randomLower;
        while(noOfChar>50||noOfChar<10){
            randomUpper = rand.nextInt(upperbound);
            randomLower = rand.nextInt(randomUpper);
            noOfChar = randomUpper - randomLower;
        }
        
        //System.out.println("lower: "+ randomLower+ " higher: "+ randomUpper+ " no :"+noOfChar);

        //bob random K
        byte [] randomK = Arrays.copyOfRange(APK, randomLower, randomUpper);
       // System.out.println("RandomK: "+randomK);
        //System.out.println(convertBytesToHex(randomK));

        //encrypt the K with Alice's PK
        String randomKstring = convertBytesToHex(randomK);
        System.out.println("Randomly generated K(to be encrypted using Alice's PK): "+randomKstring);
        //System.out.println("number of bytes: "+ randomK.length);

        //encrypt C1
        String C1 = encrypt(randomKstring, Apublickey);
        System.out.println("K encrypted using Alice's PK(C1): "+randomKstring);
        // System.out.println("C1 sent to alice: "+C1);

        //create key K
        SecretKeySpec rc4Key = new SecretKeySpec(randomKstring.getBytes(),"RC4");

        //encrypt C2 with a delimiter 
        String concateC2 = username +","+ password;
        String C2 = encryptRC4(concateC2,rc4Key);
        System.out.println("\nUsername and password(after rc4 encryption using K): "+C2);
        // String decC2 = decryptRC4(C2, rc4Key);
        // System.out.println(decC2);

        //prepare the package to be sent in step 3
        DatagramSocket ds3 = new DatagramSocket();
        String step3package = C1+","+C2;
        byte C1andC2[] = step3package.getBytes();
        DatagramPacket sendC1C2 = new DatagramPacket(C1andC2,C1andC2.length,ip,32345);
        ds3.send(sendC1C2);
        ds3.close();

        //prepare for Alice to send if authentication sucess or failed
        DatagramSocket ds4 = new DatagramSocket(42345);
        byte[]receiveAuth = new byte [6556];
        DatagramPacket AuthReceive = null;
        AuthReceive = new DatagramPacket(receiveAuth,receiveAuth.length);
        ds4.receive(AuthReceive);
        System.out.println("\nAlice : "+data(receiveAuth));

        if(data(receiveAuth).toString().equals("Authentication Failed"))
        {
            System.out.println("Exiting program now!");
            System.exit(0);
        }
        else{
            System.out.println("Authentication sucess!");
        }

        String HKNBNA = randomKstring+convertBytesToHex(nb)+convertBytesToHex(ANA);
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        Bssk = sha1.digest(HKNBNA.getBytes());
        System.out.println("\npre SHA-1 hash: "+HKNBNA);
        System.out.println("post SHA-1 hash: "+convertBytesToHex(Bssk));



        




    }

    //encryption using RC4
    public static String encryptRC4(String plainText, SecretKeySpec publicKey)throws Exception{
        Cipher rc4 = Cipher.getInstance("RC4");
        rc4.init(Cipher.ENCRYPT_MODE,publicKey);
        byte [] cipherText = rc4.doFinal(plainText.getBytes(UTF_8));
        return Base64.getEncoder().encodeToString(cipherText);
    }
    //decryption using RC4
    public static String decryptRC4(String cipherText, SecretKeySpec publicKey) throws Exception{
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        Cipher decriptCipher = Cipher.getInstance("RC4");
        decriptCipher.init(Cipher.DECRYPT_MODE,publicKey);

        return new String(decriptCipher.doFinal(bytes),UTF_8);
    }
    //encryption using RSA
    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }
    //decryption using RSA
    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    //RSA key generation
    public static KeyPair generateKeyPair() throws Exception
    {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        return pair;
    }

    //convert bytes to hex
    private static String convertBytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte temp : bytes) {
            result.append(String.format("%02x", temp));
        }
        return result.toString();
    }
    

    public static StringBuilder data(byte[] a)
    {
        if (a == null)
            return null;
        StringBuilder ret = new StringBuilder();
        int i = 0;
        while (a[i] != 0)
        {
            ret.append((char) a[i]);
            i++;
        }
        return ret;
    }
    
}
