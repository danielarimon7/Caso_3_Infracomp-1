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
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ServidorDelegado extends Thread {
    private ArrayList<Integer> listaClientes;
    private HashMap<Integer, Estados> mapaPaquetes;
    private Socket conexionSocket;


    private static final String ARCHIVO_LLAVE_PRIVADA = "privateKey.ser";
    private static final String ARCHIVO_LLAVE_PUBLICA = "publicKey.ser";

    public ServidorDelegado(ArrayList<Integer> idCliente, HashMap<Integer, Estados> paquetes, Socket socket) {
        this.listaClientes = idCliente;
        this.mapaPaquetes = paquetes;
        this.conexionSocket = socket;
    }

    public void run() {
        PrivateKey llavePrivada = null;
        PublicKey llavePublica = null;

        try {
            ObjectInputStream lectorLlavePrivada = new ObjectInputStream(new FileInputStream(ARCHIVO_LLAVE_PRIVADA));
            llavePrivada = (PrivateKey) lectorLlavePrivada.readObject();
            System.out.println("Se leyó la llave privada");

            ObjectInputStream lectorLlavePublica = new ObjectInputStream(new FileInputStream(ARCHIVO_LLAVE_PUBLICA));
            llavePublica = (PublicKey) lectorLlavePublica.readObject();
            System.out.println("Se leyó la llave pública");

            BufferedReader lectorEntrada = new BufferedReader(new InputStreamReader(conexionSocket.getInputStream()));
            PrintWriter escritorSalida = new PrintWriter(conexionSocket.getOutputStream(), true);
            System.out.println(lectorEntrada.readLine());

            Cipher cifrador = Cipher.getInstance("RSA");
            cifrador.init(Cipher.DECRYPT_MODE, llavePrivada);
            String mensajeRecibido = lectorEntrada.readLine();
            byte[] mensajeDecodificado = Base64.getDecoder().decode(mensajeRecibido);
            byte[] bytesMensaje = cifrador.doFinal(mensajeDecodificado);
            String mensajeDesencriptado = new String(bytesMensaje);
            escritorSalida.println(mensajeDesencriptado);

            if (lectorEntrada.readLine().equals("OK") == false) {
                System.out.println("Error, no se autenticó el servidor");
                System.out.println("Fin de la conexión");
                lectorLlavePrivada.close();
                lectorLlavePublica.close();
                throw new Exception("Error, no se autenticó el servidor");
            } else {
                System.out.println("Servidor autenticado");
            }

            ProcessBuilder constructorProceso = new ProcessBuilder("/opt/homebrew/opt/openssl/bin/openssl", "dhparam", "-text", "1024");
            Process proceso = constructorProceso.start();

            BufferedReader lectorProceso = new BufferedReader(new InputStreamReader(proceso.getInputStream()));
            BufferedReader lectorErrores = new BufferedReader(new InputStreamReader(proceso.getErrorStream()));

            while (lectorErrores.readLine() != null) {}

            String linea;
            StringBuilder numeroPrimoHex = new StringBuilder();
            BigInteger numeroPrimo = null;
            int numeroGenerador = 0;
            boolean leyendoPrimo = false;

            while ((linea = lectorProceso.readLine()) != null) {
                if (linea.contains("prime:")) {
                    leyendoPrimo = true;
                } else if (linea.contains("generator:")) {
                    leyendoPrimo = false;
                    String[] partes = linea.split(" ");
                    numeroGenerador = Integer.parseInt(partes[9]);
                } else if (leyendoPrimo) {
                    numeroPrimoHex.append(linea.trim().replace(":", ""));
                }
            }

            numeroPrimo = new BigInteger(numeroPrimoHex.toString(), 16);
            long x = Math.round(Math.random());
            int generadorNumeroX = (int) Math.pow(numeroGenerador, x);

            escritorSalida.println(numeroGenerador);
            escritorSalida.println(numeroPrimo.toString());
            escritorSalida.println(generadorNumeroX);

            BigInteger valorFirmado = BigInteger.valueOf(numeroGenerador)
                .add(BigInteger.valueOf(generadorNumeroX))
                .add(numeroPrimo);

            Signature firmador = Signature.getInstance("SHA1withRSA");
            firmador.initSign(llavePrivada);

            byte[] datosFirma = valorFirmado.toByteArray();
            firmador.update(datosFirma);
            byte[] bytesFirma = firmador.sign();
            String firmaCodificada = Base64.getEncoder().encodeToString(bytesFirma);
            escritorSalida.println(firmaCodificada);

            if (lectorEntrada.readLine().equals("OK") == false) {
                System.out.println("Firma no válida");
                System.out.println("Conexión terminada");
                lectorLlavePrivada.close();
                lectorLlavePublica.close();
                return;
            } else {
                System.out.println("Firma correcta");
            }

            int Y = Integer.parseInt(lectorEntrada.readLine());
            int generadorNumeroXY = (int) Math.pow(Y, x);
            BigInteger claveMaestra = BigInteger.valueOf(generadorNumeroXY).mod(numeroPrimo);

            SecureRandom generadorAleatorio = new SecureRandom();
            byte[] ivBytes = new byte[16];
            generadorAleatorio.nextBytes(ivBytes);

            escritorSalida.println(Base64.getEncoder().encodeToString(ivBytes));

            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            MessageDigest digestorSha512 = MessageDigest.getInstance("SHA-512");

            byte[] hashClave = digestorSha512.digest(claveMaestra.toByteArray());
            byte[] claveAES = new byte[32];
            byte[] claveHmac = new byte[32];
            System.arraycopy(hashClave, 0, claveAES, 0, 32);
            System.arraycopy(hashClave, 32, claveHmac, 0, 32);

            SecretKey K_AES = new SecretKeySpec(claveAES, "AES");
            SecretKey K_HMAC = new SecretKeySpec(claveHmac, "HmacSHA384");
            System.out.println("Llaves simétricas generadas exitosamente.");

            String uid = lectorEntrada.readLine();
            String hmacUid = lectorEntrada.readLine();

            byte[] uidDecodificado64 = Base64.getDecoder().decode(uid);
            Cipher cifradorSimetricoUID = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cifradorSimetricoUID.init(Cipher.DECRYPT_MODE, K_AES, iv);
            byte[] uidDescifrado = cifradorSimetricoUID.doFinal(uidDecodificado64);

            Mac calculadorMac = Mac.getInstance("HmacSHA384");
            calculadorMac.init(K_HMAC);
            byte[] hmacUidCalculado = calculadorMac.doFinal(uidDescifrado);
            String hmacUidCalculadoBase64 = Base64.getEncoder().encodeToString(hmacUidCalculado);

            String idPaquete = lectorEntrada.readLine();
            String hmacPaquete = lectorEntrada.readLine();

            byte[] idPaqueteDecodificado64 = Base64.getDecoder().decode(idPaquete);
            Cipher cifradorSimetricoPaquete = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cifradorSimetricoPaquete.init(Cipher.DECRYPT_MODE, K_AES, iv);
            byte[] idPaqueteDescifrado = cifradorSimetricoPaquete.doFinal(idPaqueteDecodificado64);

            calculadorMac.init(K_HMAC);
            byte[] hmacPaqueteCalculado = calculadorMac.doFinal(idPaqueteDescifrado);
            String hmacPaqueteCalculadoBase64 = Base64.getEncoder().encodeToString(hmacPaqueteCalculado);

            if (!hmacPaqueteCalculadoBase64.equals(hmacPaquete) || !hmacUidCalculadoBase64.equals(hmacUid)) {
                escritorSalida.println("ERROR EN LA CONSULTA");
                System.out.println("Conexión terminada");
                lectorLlavePrivada.close();
                lectorLlavePublica.close();
                return;
            } else {
                escritorSalida.println("OK");
            }

            Estados estado = Estados.DESCONOCIDO;
            try {
                listaClientes.get(Integer.parseInt(new String(uidDescifrado)));
                estado = mapaPaquetes.get(Integer.parseInt(new String(idPaqueteDescifrado)));
            } catch (Exception e) {
                System.out.println("Paquete o cliente no encontrado");
            }

            cifradorSimetricoPaquete.init(Cipher.ENCRYPT_MODE, K_AES, iv);
            String estadoCifrado = Base64.getEncoder().encodeToString(cifradorSimetricoPaquete.doFinal(estado.toString().getBytes()));

            calculadorMac.init(K_HMAC);
            byte[] hmacEstado = calculadorMac.doFinal(estado.toString().getBytes());
            String hmacEstadoCodificado = Base64.getEncoder().encodeToString(hmacEstado);

            escritorSalida.println(estadoCifrado);
            escritorSalida.println(hmacEstadoCodificado);

            if (lectorEntrada.readLine().equals("ERROR")) {
                System.out.println("Error en la consulta");
                lectorLlavePrivada.close();
                lectorLlavePublica.close();
                return;
            }

            if (lectorEntrada.readLine().equals("TERMINAR")) {
                System.out.println("Conexión terminada");
            }

            lectorProceso.close();
            proceso.waitFor();
            proceso.destroy();
            conexionSocket.close();
            lectorLlavePrivada.close();
            lectorLlavePublica.close();
            escritorSalida.close();
            lectorEntrada.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] firmarDatos(byte[] datos, PrivateKey llavePrivada) throws Exception {
        Signature firmador = Signature.getInstance("SHA1withRSA");
        firmador.initSign(llavePrivada);
        firmador.update(datos);
        return firmador.sign();
    }
}
