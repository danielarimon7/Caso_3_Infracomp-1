import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
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

public class ServidorDelegado extends Thread {
    private final CyclicBarrier barrierSync;
    private static final String PRIVATE_KEY_PATH = "privateKey.ser";
    private static final String PUBLIC_KEY_PATH = "publicKey.ser";
    private Socket socketClient;
    private ArrayList<Integer> clienteIds;
    private HashMap<Integer, Estados> estadoPaquetes;

    public ServidorDelegado(ArrayList<Integer> clienteIds, HashMap<Integer, Estados> estadoPaquetes, Socket socketClient, CyclicBarrier barrierSync) {
        this.clienteIds = clienteIds;
        this.estadoPaquetes = estadoPaquetes;
        this.socketClient = socketClient;
        this.barrierSync = barrierSync;
    }

    public void run() {
        PublicKey llavePublica = null;
        PrivateKey llavePrivada = null;

        try {
            ObjectInputStream keyInputPrivate = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_PATH));
            llavePrivada = (PrivateKey) keyInputPrivate.readObject();
            ObjectInputStream keyInputPublic = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_PATH));
            llavePublica = (PublicKey) keyInputPublic.readObject();

            BufferedReader lector = new BufferedReader(new InputStreamReader(socketClient.getInputStream()));
            PrintWriter escritor = new PrintWriter(socketClient.getOutputStream(), true);

            // Mensaje encriptado y autenticación del cliente
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, llavePrivada);
            String mensajeCifrado = lector.readLine();
            byte[] mensajeDescifradoBytes = Base64.getDecoder().decode(mensajeCifrado);
            String mensajeDescifrado = new String(rsaCipher.doFinal(mensajeDescifradoBytes));
            escritor.println(mensajeDescifrado);

            if (!lector.readLine().equals("OK")) {
                throw new Exception("Error en la autenticación");
            }

            // Generación de parámetros DH y cálculo de la clave
            ProcessBuilder dhProceso = new ProcessBuilder("lib\\OpenSSL-1.1.1h_win32\\openssl.exe", "dhparam", "-text", "1024");
            Process proceso = dhProceso.start();
            BufferedReader procesoSalida = new BufferedReader(new InputStreamReader(proceso.getInputStream()));
            StringBuilder primoHex = new StringBuilder();
            BigInteger numeroPrimo = null;
            int numeroGenerador = 0;

            String linea;
            while ((linea = procesoSalida.readLine()) != null) {
                if (linea.contains("prime:")) {
                    primoHex.append(linea.trim().replace(":", ""));
                } else if (linea.contains("generator:")) {
                    numeroGenerador = Integer.parseInt(linea.split(" ")[9]);
                }
            }
            numeroPrimo = new BigInteger(primoHex.toString(), 16);
            int potenciaGenerador = (int) Math.pow(numeroGenerador, Math.round(Math.random()));

            escritor.println(numeroGenerador);
            escritor.println(numeroPrimo.toString());
            escritor.println(potenciaGenerador);

            // Cálculo de la clave maestra y configuración de IV y HMAC
            int valorY = Integer.parseInt(lector.readLine());
            BigInteger claveMaestra = BigInteger.valueOf((int) Math.pow(valorY, Math.round(Math.random()))).mod(numeroPrimo);

            byte[] ivBytes = new byte[16];
            new SecureRandom().nextBytes(ivBytes);
            escritor.println(Base64.getEncoder().encodeToString(ivBytes));

            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            MessageDigest digestSha512 = MessageDigest.getInstance("SHA-512");
            byte[] hashDigest = digestSha512.digest(claveMaestra.toByteArray());
            SecretKey aesKey = new SecretKeySpec(hashDigest, 0, 32, "AES");
            SecretKey hmacKey = new SecretKeySpec(hashDigest, 32, 32, "HmacSHA384");

            // Procesamiento del UID y verificación HMAC
            String uidCodificado = lector.readLine();
            String hmacUid = lector.readLine();
            Mac hmac = Mac.getInstance("HmacSHA384");
            hmac.init(hmacKey);
            byte[] uidDescifradoBytes = Base64.getDecoder().decode(uidCodificado);
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
            byte[] uidDescifrado = aesCipher.doFinal(uidDescifradoBytes);
            byte[] hmacCalculado = hmac.doFinal(uidDescifrado);

            if (!Base64.getEncoder().encodeToString(hmacCalculado).equals(hmacUid)) {
                escritor.println("ERROR");
                return;
            }

            // Verificación del paquete y envío de estado
            String paqueteIdCodificado = lector.readLine();
            Estados estadoPaquete = estadoPaquetes.getOrDefault(Integer.parseInt(new String(aesCipher.doFinal(Base64.getDecoder().decode(paqueteIdCodificado)))), Estados.DESCONOCIDO);

            escritor.println(Base64.getEncoder().encodeToString(aesCipher.doFinal(estadoPaquete.toString().getBytes())));
            escritor.println(Base64.getEncoder().encodeToString(hmac.doFinal(estadoPaquete.toString().getBytes())));

            if (lector.readLine().equals("TERMINAR")) {
                System.out.println("Conexión cerrada");
            }

            // Liberación de recursos y cierre de conexión
            procesoSalida.close();
            proceso.waitFor();
            socketClient.close();
            keyInputPrivate.close();
            keyInputPublic.close();
            escritor.close();
            lector.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
