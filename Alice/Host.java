package Alice;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.*;
import java.util.Base64;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.FileWriter;
import java.util.Scanner;
import java.util.Random;
import javax.crypto.spec.SecretKeySpec;

public class Host {
    public static byte Assk[]=null;
    public static boolean online = true;
    public static boolean sendtoggle = true;
    public static boolean recievetoggle = false;
    public static void main(String args[]) throws IOException,Exception
    {
        //handshake protocol by alice 
        ServerSideHandShake();
        
        while(online)
        {
           while(recievetoggle)
           {
               ServerRecieve();
           }
           while(sendtoggle)
           {
               ServerSend();
           }
        }
      

    }
    public static void ServerSend() throws IOException, Exception
    {
        Scanner sc = new Scanner(System.in);
        DatagramSocket ds = new DatagramSocket();
 
        InetAddress ip = InetAddress.getLocalHost();
        byte buf[] = null;
        byte h[] = null;
        
         // loop while user not enters "exit"
         while (true)
         {
            System.out.print("\nServer: ");
            String inp = sc.nextLine();
            //concate ssk||m||ssk
            String hValue = convertBytesToHex(Assk) + inp+convertBytesToHex(Assk);
            //encode h using SHA-1
            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            h = sha1.digest(hValue.getBytes());
            //System.out.println("h value computed by Alice: "+ convertBytesToHex(h));

            //create SKEssk (RC4 key)
            SecretKeySpec rc4Key = new SecretKeySpec(Assk,"RC4");

            //encrypt m||h to get c
            String mandh = inp + "," + convertBytesToHex(h);
            System.out.println("m||h before SKEssk(RC4 Encryption): "+ mandh);
            String C = encryptRC4(mandh, rc4Key);
            System.out.println("Message sent to Bob after RC4 encryption: "+C);


        
             // convert the String input into the byte array.
             buf = C.getBytes();
  
             // Step 2 : Create the datagramPacket for sending
             // the data.
             DatagramPacket DpSend =
                   new DatagramPacket(buf, buf.length, ip, 22345);
  
             // Step 3 : invoke the send call to actually send
             // the data.
             ds.send(DpSend);

             sendtoggle = false;
             recievetoggle = true;
             
  
             // break the loop if user enters "bye"
            if (inp.equals("exit"))
            {
                online = false;
                break;
            }
                
            if(sendtoggle == false)
            {
                break;
            }
                

         }
         ds.close();

    }

    public static void ServerRecieve() throws IOException,Exception
    {
          // Step 1 : Create a socket to listen at port 12345
        DatagramSocket ds = new DatagramSocket(12345);
        byte[] receive = new byte[65535];
        byte hprime[] = null;
          DatagramPacket DpReceive = null;
          while (true)
          {
   
              // Step 2 : create a DatgramPacket to receive the data.
              DpReceive = new DatagramPacket(receive, receive.length);
   
              // Step 3 : revieve the data in byte buffer.
              ds.receive(DpReceive);

              //create rc4 key
              SecretKeySpec rc4key = new SecretKeySpec(Assk, "RC4");

              //decrypt message
              String decryptRecieve = decryptRC4(data(receive).toString(), rc4key);

              //split h from message
              String[] mandh = decryptRecieve.split(",");
              String m = mandh[0];
              String hfromA = mandh[1];

              //bob compute ssk||m||ssk
              String sskandm = convertBytesToHex(Assk)+m+convertBytesToHex(Assk);
              //encode h' using SHA-1
              MessageDigest sha1 = MessageDigest.getInstance("SHA1");
              hprime = sha1.digest(sskandm.getBytes());

            if(hfromA.equals(convertBytesToHex(hprime))){
                System.out.println("\nDecryption Sucessful!");
                System.out.println("Client: " + data(receive));
                System.out.println("RC4 Decrypted Message: " +m);
                //System.out.println("h': "+ convertBytesToHex(hprime) + "h: "+ hfromA); 
            }else{
                System.out.println("Decryption Error!");
            }

              //Change server to send mode
              recievetoggle = false;
              sendtoggle = true;
              // Exit the server if the client sends "bye"
              if (data(receive).toString().equals("exit"))
              {
                  online = false;
                  System.out.println("Client exited the program!");
                  System.exit(0);
                  break;
              }
              
              // Clear the buffer after every message.
              receive = new byte[65535];

              if(recievetoggle == false)
              {
                  break;
              }
                
          }
          
        ds.close();
    }

    public static void ServerSideHandShake() throws IOException,Exception
    {   
        //generate public and private key and store in keyfile.txt for Alice
        KeyPair pair = generateKeyPair();
        FileWriter keyFile = new FileWriter("KeyFile.txt");
        keyFile.write(pair.getPublic().toString());
        keyFile.write("\n");
        keyFile.write(pair.getPrivate().toString());
        keyFile.close();

        //recieve NB from bob
        DatagramSocket ds1 = new DatagramSocket(12345);
        byte[] receiveNB = new byte[16];
        DatagramPacket NBReceive = null;
        NBReceive = new DatagramPacket(receiveNB,receiveNB.length);
        ds1.receive(NBReceive);

        System.out.println("\nBob's NB : " + convertBytesToHex(receiveNB));
        ds1.close();

        //send bob PK and NA
        DatagramSocket ds2 = new DatagramSocket();
        InetAddress ip = InetAddress.getLocalHost();
        byte pk[] = null;
        pk = pair.getPublic().getEncoded();

        //generate NA
        Random rand = new SecureRandom();
        byte [] na = new byte[16];
        rand.nextBytes(na);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(pk);
        outputStream.write(na);
        byte pkandna[] = outputStream.toByteArray();
        System.out.println("\nSending PK over to Bob: "+ convertBytesToHex(pk)+"\n\nSending NA over to Bob: "+convertBytesToHex(na));
        DatagramPacket pknasend = new DatagramPacket(pkandna,pkandna.length,ip,22345);
        ds2.send(pknasend);
        ds2.close();

        //recieve c1 and c2 from bob
        DatagramSocket ds3 = new DatagramSocket (32345);
        byte[]receiveC1C2 = new byte [6556];
        DatagramPacket C1C2Recieve = null;
        C1C2Recieve = new DatagramPacket(receiveC1C2,receiveC1C2.length);
        ds3.receive(C1C2Recieve);
        System.out.println("\nBob's C1 and C2: "+data(receiveC1C2));
        ds3.close();

        //delimit c1c2recieve to get c1 and c2 seperately
        String concatec1c2 = data(receiveC1C2).toString();
        String[] splitc1c2 = concatec1c2.split(",");
        // System.out.println(splitc1c2[0]);
        // System.out.println(splitc1c2[1]);
        String kValue = decrypt(splitc1c2[0],pair.getPrivate());
        // System.out.print(kValue);

        //create key K to decrypt ciphertext of username and password
        SecretKeySpec rc4Key = new SecretKeySpec(kValue.getBytes(), "RC4");

        //decrypt C2
       // byte [] keyK = kValue.getBytes();
       //System.out.println("Byte keyk: " +keyK);
        String userAndPass = decryptRC4(splitc1c2[1], rc4Key);
        System.out.println("\nUsername and password sent by bob(after RC4 decryption): "+userAndPass);


        String [] splitUserAndPass = userAndPass.split(",");
        String username = splitUserAndPass[0];
        String password = splitUserAndPass[1];
        //System.out.println(username+password);

        //open password file and check if client sent the correct username and password
        Scanner infile = new Scanner(new File("PasswordFile.txt"));
        StringBuilder sb = new StringBuilder();
        while(infile.hasNext())
        {
            sb.append(infile.nextLine());
        }
        infile.close();

        String [] fileUsernPass = sb.toString().split(",");
        String fileUser = fileUsernPass[0];
        String filePass = fileUsernPass[1];
        // System.out.println("user: " +fileUser+" Password: "+filePass);
        DatagramSocket ds4 = new DatagramSocket();
        if (!(username.equals(fileUser) && password.equals(filePass)))
        {   
            String failed = "Authentication Failed";
            byte failedAuth[] = failed.getBytes();
            DatagramPacket sendFailed = new DatagramPacket(failedAuth,failedAuth.length,ip,42345);
            ds4.send(sendFailed);
            ds4.close();
            System.out.println("\nClient Authentication failed, quitting program now!");
            System.exit(0);
        }
        else
        {
            String Passed = "Authentication Passed";
            byte PassedAuth[] = Passed.getBytes();
            DatagramPacket sendPassed = new DatagramPacket(PassedAuth,PassedAuth.length,ip,42345);
            ds4.send(sendPassed);
            ds4.close();
            System.out.println("\nClient Authentication sucess!");

        }


        //compute shared session key ssk
        String HKNBNA = kValue +convertBytesToHex(receiveNB)+convertBytesToHex(na);
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        Assk = sha1.digest(HKNBNA.getBytes());
        System.out.println("\nssk pre SHA-1 hash: "+HKNBNA);
        System.out.println("ssk post SHA-1 hash: "+convertBytesToHex(Assk));


        


    }

    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    public static String encryptRC4(String plainText, SecretKeySpec publicKey)throws Exception{
        Cipher rc4 = Cipher.getInstance("RC4");
        rc4.init(Cipher.ENCRYPT_MODE,publicKey);
        byte [] cipherText = rc4.doFinal(plainText.getBytes(UTF_8));
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decryptRC4(String cipherText, SecretKeySpec publicKey) throws Exception{
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        Cipher decriptCipher = Cipher.getInstance("RC4");
        decriptCipher.init(Cipher.DECRYPT_MODE,publicKey);

        return new String(decriptCipher.doFinal(bytes),UTF_8);
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

    //RSA Generation 
    public static KeyPair generateKeyPair() throws Exception
    {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        return pair;
    }
}