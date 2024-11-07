import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Cliente extends Thread{
    public static final int PUERTO = 3400;
	public static final String SERVIDOR = "localhost";
    public static final String PUBLIC_KEY_FILE = "publicKey.ser";
    private static final String CARACTERES = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final SecureRandom random = new SecureRandom();
    private int numeroConsultas;
    private final CyclicBarrier barreraMenu;
    

    public Cliente(int numeroConsultas, CyclicBarrier barreraMenu){
        this.numeroConsultas = numeroConsultas;
        this.barreraMenu = barreraMenu;
    }
    
	
	public void run() {
		
		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;

        ArrayList<Integer> idCliente = new ArrayList<>();
        ArrayList<Integer> paquetes = new ArrayList<>();

        for (int i = 1; i <= 40; i++) {
            idCliente.add(i);
            paquetes.add(i+i);
        }
		
		System.out.println("Comienza cliente");
		PublicKey publicKey = null;
        for (int consultas = 0; consultas < numeroConsultas;  consultas++) {
		    try {
                socket = new Socket(SERVIDOR, PUERTO);
                escritor = new PrintWriter(socket.getOutputStream(), true);
                lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                ObjectInputStream ois = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
                publicKey = (PublicKey) ois.readObject();
                System.out.println("Llave pública leída exitosamente.");
                escritor.println("SECINIT");
                String mensaje = generarCadena(16);
                String encodedMessage = cifrar(publicKey, mensaje, "RSA");
                escritor.println(encodedMessage);
                String respuesta = lector.readLine();
                if (respuesta.equals(mensaje)){
                    escritor.println("OK");
                }else{
                    escritor.println("ERROR");
                }

                int generatorNumber = Integer.parseInt(lector.readLine());
                String prime = lector.readLine();
                int generatorNumberX = Integer.parseInt(lector.readLine());

                BigInteger primeNumber = new BigInteger(prime);

                BigInteger comprobanteFirma = BigInteger.valueOf(generatorNumber)
                    .add(BigInteger.valueOf(generatorNumberX))
                    .add(primeNumber);

                byte[] comprobante = comprobanteFirma.toByteArray();

                byte[] decodedSign = Base64.getDecoder().decode(lector.readLine());

                Signature firma = Signature.getInstance("SHA1withRSA");
                firma.initVerify(publicKey);
                firma.update(comprobante);

                if (firma.verify(decodedSign)) {
                    escritor.println("OK");
                } else {
                    escritor.println("ERROR");
                }

                int Y = (int) Math.random();

                int generatorNumberXY= (int)Math.pow(generatorNumberX, Y);

                BigInteger masterkey = BigInteger.valueOf(generatorNumberXY).mod(primeNumber);

                escritor.println((int)Math.pow(generatorNumber, Y));

                String ivBase64 = lector.readLine();

                byte[] ivBytes = Base64.getDecoder().decode(ivBase64);

                IvParameterSpec iv = new IvParameterSpec(ivBytes);

                MessageDigest sha512 = MessageDigest.getInstance("SHA-512");

                byte[] hash = sha512.digest(masterkey.toByteArray());

                byte[] key1 = new byte[32];
                byte[] key2 = new byte[32];

                System.arraycopy(hash, 0, key1, 0, 32);
                System.arraycopy(hash, 32, key2, 0, 32);
                Random random = new Random();

                // Seleccionar un índice aleatorio, 
                int randomIndex = random.nextInt(idCliente.size());

                SecretKey K_AB1 = new SecretKeySpec(key1, "AES");
                SecretKey K_AB2 = new SecretKeySpec(key2, "HmacSHA384");

                System.out.println("Llaves simétricas generadas exitosamente.");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, K_AB1, iv);
                String uid = Base64.getEncoder().encodeToString(cipher.doFinal(idCliente.get(randomIndex).toString().getBytes()));

                Mac mac = Mac.getInstance("HmacSHA384");
                
                mac.init(K_AB2);
                byte[] hmacBytes = mac.doFinal(idCliente.get(randomIndex).toString().getBytes());
                String hmac_uid=Base64.getEncoder().encodeToString(hmacBytes);

                escritor.println(uid);
                escritor.println(hmac_uid);

                cipher.init(Cipher.ENCRYPT_MODE, K_AB1, iv);
                String paquete_id = Base64.getEncoder().encodeToString(cipher.doFinal(paquetes.get(randomIndex).toString().getBytes()));
                mac.init(K_AB2);
                byte[] hmac = mac.doFinal(paquetes.get(randomIndex).toString().getBytes());
                String hmac_paquete=Base64.getEncoder().encodeToString(hmac);

                escritor.println(paquete_id);
                escritor.println(hmac_paquete);

                String respuestaHmac = lector.readLine();

                if (respuestaHmac.equals("ERROR")) {
                    System.out.println("Error en la consulta");
                    ois.close();
                    return;
                }

                String respuestaEstado = lector.readLine();
                String hmacEstado = lector.readLine();

                byte[] respuestaEstadoDecoded64 = Base64.getDecoder().decode(respuestaEstado);
                cipher.init(Cipher.DECRYPT_MODE, K_AB1, iv);
                byte[] respuestaEstadoDecoded=cipher.doFinal(respuestaEstadoDecoded64);
                mac.init(K_AB2);
                byte[] computedHmacEstado = mac.doFinal(respuestaEstadoDecoded);
                String computedHmacEstadoBase64 = Base64.getEncoder().encodeToString(computedHmacEstado);

                if (!computedHmacEstadoBase64.equals(hmacEstado)) {
                    escritor.println("ERROR");
                    System.out.println("Error en la consulta");
                    ois.close();
                    return;
                }else{
                    escritor.println("OK");
                }

                String EstadoPaquete = new String(respuestaEstadoDecoded);
                System.out.println("Estado del paquete: " + EstadoPaquete);

                escritor.println("TERMINAR");

                ois.close();
        
            }
            catch (Exception e) {
                e.printStackTrace();
            }
            
            try {
                socket.close();
                escritor.close();
                lector.close();
            } catch (IOException e) {
                
                e.printStackTrace();
            }
        }

		
        try {
            barreraMenu.await();
        } catch (InterruptedException e) {
            
           e.printStackTrace();
        } catch (BrokenBarrierException e) {
            
           e.printStackTrace();
        }

	}

    public static String generarCadena(int longitud) {
        StringBuilder sb = new StringBuilder(longitud);
        for (int i = 0; i < longitud; i++) {
            int indiceAleatorio = random.nextInt(CARACTERES.length());
            sb.append(CARACTERES.charAt(indiceAleatorio));
        }
        return sb.toString();
    }

    public static String cifrar(PublicKey llave, String mensaje, String algoritmo) {
        try {          
            byte[] R = null;
            Cipher cipher = Cipher.getInstance(algoritmo);
            cipher.init(Cipher.ENCRYPT_MODE, llave);
            R = cipher.doFinal(mensaje.getBytes());
            String encodedMessage = Base64.getEncoder().encodeToString(R);
            
            return encodedMessage;
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
            return null;
        }
    }

}