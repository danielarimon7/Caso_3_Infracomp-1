import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ServerIterativo extends Thread{

    private final int PUERTO;
    private ArrayList<Integer> idClientes;
    private HashMap<Integer, EstadoPaquete> paquetes;
    private int numeroConsultas;
    private final CyclicBarrier barreraMenu;
    private static final String PRIVATE_KEY_FILE = "privateKey.ser";
    private static final String PUBLIC_KEY_FILE = "publicKey.ser";
    private Socket socket;

    public ServerIterativo(int PUERTO, ArrayList<Integer> idClientes, HashMap<Integer, EstadoPaquete> paquetes, int numeroConsultas, CyclicBarrier barreraMenu){
        this.PUERTO = PUERTO;
        this.idClientes = idClientes;
        this.paquetes = paquetes;
        this.numeroConsultas = numeroConsultas;
        this.barreraMenu = barreraMenu;
    }


    public void run() {
        ServerSocket ss = null;
        try {
            ss = new ServerSocket(PUERTO);
            System.out.println("Servidor escuchando en el puerto " + PUERTO);

            // Esperar conexiones y crear delegados
            while (numeroConsultas>0) {
                socket = ss.accept();
                protocoloServidor();
                numeroConsultas--;

            }

            
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (ss != null)
                try {
                    ss.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
        }


        //Barrera para que no se muestre el menú de opciones hasta que todos terminen
        try {
            barreraMenu.await();
        } catch (InterruptedException e) {
            
            e.printStackTrace();
        } catch (BrokenBarrierException e) {
            
            e.printStackTrace();
        }
    }


    private void protocoloServidor(){
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
        
        try {
            // Leer las llaves
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
            privateKey = (PrivateKey) ois.readObject();
            System.out.println("Llave privada leída exitosamente.");
            ObjectInputStream ois2 = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
            publicKey = (PublicKey) ois2.readObject();
            System.out.println("Llave pública leída exitosamente.");


            BufferedReader lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter escritor = new PrintWriter(socket.getOutputStream(), true);

            System.out.println(lector.readLine());

            // Recibir el mensaje cifrado, desencriptarlo y enviarlo de vuelta
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            String receivedMessage = lector.readLine();
            byte[] decodedMessage = Base64.getDecoder().decode(receivedMessage);
            byte[] mensajeBytes = cipher.doFinal(decodedMessage);
            String mensajeDesencriptado = new String(mensajeBytes);
            escritor.println(mensajeDesencriptado);


            if(lector.readLine().equals("OK")){
                System.out.println("Servidor autenticado");
            }else{
                System.out.println("Error en la autenticación");
                System.out.println("Conexión terminada");
                ois.close();
                ois2.close();
                throw new Exception("Error en la autenticación");
            }
            ProcessBuilder processBuilder = new ProcessBuilder("Caso3\\lib\\OpenSSL-1.1.1h_win32\\openssl.exe", "dhparam", "-text", "1024");

            Process process = processBuilder.start();
            // Leer la salida del commando
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            while (errorReader.readLine() != null) {
            }
            String line;
            StringBuilder hexPrime = new StringBuilder();
            BigInteger primeNumber = null;
            int generatorNumber=0;

            boolean readingPrime = false;
            while ((line = reader.readLine()) != null) {
                if (line.contains("prime:")) {
                    readingPrime = true;
                } else if (line.contains("generator:")) {
                    readingPrime = false;
                    String[] parts = line.split(" ");
                    generatorNumber = Integer.parseInt(parts[9]); 
                } else if (readingPrime) {
                    // Extraer el valor en hexadecimal
                    hexPrime.append(line.trim().replace(":", ""));
                }
            }

            // Convertir el número primo en hexadecimal a BigInteger
            primeNumber = new BigInteger(hexPrime.toString(), 16);
            long x = Math.round(Math.random());

            int generatorNumberX = (int) Math.pow(generatorNumber, x);

            escritor.println(generatorNumber);
            escritor.println(primeNumber.toString());
            escritor.println(generatorNumberX);
            
            BigInteger firmar = BigInteger.valueOf(generatorNumber)
                .add(BigInteger.valueOf(generatorNumberX))
                .add(primeNumber);

            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(privateKey);

            byte[] datos_firma = firmar.toByteArray();
            signature.update(datos_firma);

            byte[] firmaBytes = signature.sign();
            String firmaBase64 = Base64.getEncoder().encodeToString(firmaBytes);

            // Enviar la firma en Base64
            escritor.println(firmaBase64);

            if (lector.readLine().equals("OK")) {
                System.out.println("Firma correcta");
            } else {
                System.out.println("Firma no correcta");
                System.out.println("Conexión terminada");
                ois.close();
                ois2.close();
                return;
            }

            int Y= Integer.parseInt(lector.readLine());

            int generatorNumberXY= (int)Math.pow(Y, x);

            BigInteger masterkey = BigInteger.valueOf(generatorNumberXY).mod(primeNumber);

            SecureRandom random = new SecureRandom();
            byte[] ivBytes = new byte[16];
            random.nextBytes(ivBytes);

            escritor.println(Base64.getEncoder().encodeToString(ivBytes));

            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");

            byte[] hash = sha512.digest(masterkey.toByteArray());

            byte[] key1 = new byte[32];
            byte[] key2 = new byte[32];

            System.arraycopy(hash, 0, key1, 0, 32);
            System.arraycopy(hash, 32, key2, 0, 32);

            SecretKey K_AB1 = new SecretKeySpec(key1, "AES");
            SecretKey K_AB2 = new SecretKeySpec(key2, "HmacSHA384");
            System.out.println("Llaves simétricas generadas exitosamente.");

            String uid = lector.readLine();
            String hmac_uid = lector.readLine();

            // Verificar HMAC del usuario
            byte[] uidDecoded64 = Base64.getDecoder().decode(uid);
            Cipher cipherSimetricaUID = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipherSimetricaUID.init(Cipher.DECRYPT_MODE, K_AB1, iv);
            byte[] UIDDecoded=cipherSimetricaUID.doFinal(uidDecoded64);
            Mac mac = Mac.getInstance("HmacSHA384");
            mac.init(K_AB2);
            byte[] computedHmacUid = mac.doFinal(UIDDecoded);
            String computedHmacUidBase64 = Base64.getEncoder().encodeToString(computedHmacUid);

            String paquete_id = lector.readLine();
            String hmac_paquete = lector.readLine();

            // Verificar HMAC del paquete
            byte[] paqueteIdDecoded64 = Base64.getDecoder().decode(paquete_id);
            Cipher cipherSimetrica = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipherSimetrica.init(Cipher.DECRYPT_MODE, K_AB1, iv);
            byte[] paqueteIdDecoded=cipherSimetrica.doFinal(paqueteIdDecoded64);
            mac.init(K_AB2);
            byte[] computedHmacPaquete = mac.doFinal(paqueteIdDecoded);
            String computedHmacPaqueteBase64 = Base64.getEncoder().encodeToString(computedHmacPaquete);

            if (!computedHmacPaqueteBase64.equals(hmac_paquete) || !computedHmacUidBase64.equals(hmac_uid)) {
                escritor.println("ERROR EN LA CONSULTA");
                System.out.println("Conexión terminada");
                ois.close();
                ois2.close();
                return;
            }else{
                escritor.println("OK");
            }


            EstadoPaquete estadoRespuesta = EstadoPaquete.DESCONOCIDO;
            try {
                idClientes.get(Integer.parseInt(new String(UIDDecoded)));
                estadoRespuesta = paquetes.get(Integer.parseInt(new String(paqueteIdDecoded)));
            } catch (Exception e) {
                System.out.println("Paquete o cliente no encontrado");
            }


            cipherSimetrica.init(Cipher.ENCRYPT_MODE, K_AB1, iv);
            String estadoRespuestaCifrado = Base64.getEncoder().encodeToString(cipherSimetrica.doFinal(estadoRespuesta.toString().getBytes()));
            mac.init(K_AB2);
            byte[] hmacEstadoRespuesta = mac.doFinal(estadoRespuesta.toString().getBytes());
            String hmacEstadoRespuestaBase64 = Base64.getEncoder().encodeToString(hmacEstadoRespuesta);

            escritor.println(estadoRespuestaCifrado);
            escritor.println(hmacEstadoRespuestaBase64);

            if (lector.readLine().equals("ERROR")) {
                System.out.println("Error en la consulta");
                ois.close();
                ois2.close();
                return;
            }

            // Terminar la conexión
            if (lector.readLine().equals("TERMINAR")){
                System.out.println("Conexión terminada");
            }


            reader.close();
            process.waitFor();
            process.destroy();
            socket.close();
            ois.close();
            ois2.close();
            escritor.close();
            lector.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
