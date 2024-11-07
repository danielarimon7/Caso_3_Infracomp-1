import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;

public class Main {
    private static final int PUERTO = 3400;
    private static final String PUBLIC_KEY_FILE = "publicKey.ser";
    private static final String PRIVATE_KEY_FILE = "privateKey.ser";

    public static void main(String[] args) throws IOException {
        ArrayList<Integer> idClientes = new ArrayList<>();
        HashMap<Integer, Estados> mapaPaquetes = new HashMap<>();

        HashMap<Integer, Estados> estadosDict = new HashMap<>();
        estadosDict.put(0, Estados.ENOFICINA);
        estadosDict.put(1, Estados.RECOGIDO);
        estadosDict.put(2, Estados.ENCLASIFICACION);
        estadosDict.put(3, Estados.DESPACHADO);
        estadosDict.put(4, Estados.ENENTREGA);
        estadosDict.put(5, Estados.ENTREGADO);
        
        for (int i = 1; i <= 32; i++) {
            idClientes.add(i);
            Random random = new Random();
            int randomInt = random.nextInt(5);
            mapaPaquetes.put(i+i, estadosDict.get(randomInt));
        }

        boolean continuar = true;

        Scanner sc = new Scanner(System.in);
        
        while (continuar) {

            System.out.println("Servidor iniciado. Selecciona una opción:");
            System.out.println("1. Generar pareja de llaves asimétricas");
            System.out.println("2. Ejecutar y crear delegados concurrentes");
            System.out.println("3. Servidor y cliente iterativo");
            System.out.println("4. Salir");


            int opcion = sc.nextInt();

            switch (opcion) {
                case 1 -> generarLlaves();
                case 2 ->                     {
                        System.out.println("Ingrese el número de clientes concurrentes");
                        int numeroClientes = sc.nextInt();
                        CyclicBarrier barrierMenu = new CyclicBarrier(numeroClientes+1);
                        ServidorConcurrente servidorPrincipal = new ServidorConcurrente(PUERTO, idClientes, mapaPaquetes, numeroClientes, barrierMenu);
                        servidorPrincipal.start();
                        for(int i = 0; i < numeroClientes; i++){
                            Cliente cliente = new Cliente(1, barrierMenu);
                            cliente.start();
                        }       try {
                            barrierMenu.await();
                            continuar = false;
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        } catch (BrokenBarrierException e) {
                            e.printStackTrace();
                        }                          }
                case 3 ->                     {
                        System.out.println("Ingrese el número de consultas:");
                        int numeroConsultas = sc.nextInt();
                        CyclicBarrier barrierMenu = new CyclicBarrier(3);
                        ServidorIterativo servidor = new ServidorIterativo(PUERTO, idClientes, mapaPaquetes, numeroConsultas, barrierMenu);
                        servidor.start();
                        Cliente cliente = new Cliente(numeroConsultas, barrierMenu);
                        cliente.start();
                        try {
                            barrierMenu.await();
                            continuar = false;
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        } catch (BrokenBarrierException e) {
                            e.printStackTrace();
                        }                          }
                case 4 -> continuar = false;
                default -> System.out.println("Opción no válida, intentelo de nuevo.");
            }
        }

    }

    private static void generarLlaves() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair keyPair = keyGen.generateKeyPair();

            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(PUBLIC_KEY_FILE))) {
                oos.writeObject(publicKey);
            }
            System.out.println("Llave pública guardada correctamente");

            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(PRIVATE_KEY_FILE))) {
                oos.writeObject(privateKey);
            }
            System.out.println("Llave privada guardada correctamente");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
