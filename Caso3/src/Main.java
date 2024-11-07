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
        HashMap<Integer, Estados> paquetes = new HashMap<>();

        //TODO al menos que sea random

        // Predefinir 32 paquetes con estados iniciales

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
            paquetes.put(i+i, estadosDict.get(randomInt));
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

            if (opcion == 1) {

                generarLlaves();

            } else if (opcion == 2) {

                
                System.out.println("Ingrese el número de clientes concurrentes");
                int numeroClientes = sc.nextInt();

                //Barrera que una vez llegan todos los clientes, el servidor principal y el main, permite que se vuelva a mostrar el menú de opciones
                //Necesitamos que terminen todos los clientes, el main, y el servidor principal para que se vuelva a mostrar el menú
                CyclicBarrier barrierMenu = new CyclicBarrier(numeroClientes+1);
                //Creo el servidor principal
                ServidorConcurrente servidorPrincipal = new ServidorConcurrente(PUERTO, idClientes, paquetes, numeroClientes, barrierMenu);
                servidorPrincipal.start();

                //Creamos los clientes concurrentes
                for(int i = 0; i < numeroClientes; i++){
                    //Cada cliente hace solo una consulta
                    Cliente cliente = new Cliente(1, barrierMenu);
                    cliente.start();
                }


                try {
                    barrierMenu.await();
                    continuar = false;
                } catch (InterruptedException e) {
                    e.printStackTrace();
                } catch (BrokenBarrierException e) {
                    e.printStackTrace();
                }

                

            } else if (opcion == 3) {

                System.out.println("Ingrese el número de consultas (que hará el cliente iterativamente)");
                int numeroConsultas = sc.nextInt();

                //Barrera que una vez llegan todos el cliente, el servidor y el main, permite que se vuelva a mostrar el menú de opciones
                CyclicBarrier barrierMenu = new CyclicBarrier(3);
                //Creo el servidor principal
                ServidorIterativo servidor = new ServidorIterativo(PUERTO, idClientes, paquetes, numeroConsultas, barrierMenu);
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
                }



            } else if (opcion == 4) {
                
                continuar = false;

            } else {
                System.out.println("Opción no válida, intenta de nuevo.");
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
            System.out.println("Llave pública guardada en " + PUBLIC_KEY_FILE);

            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(PRIVATE_KEY_FILE))) {
                oos.writeObject(privateKey);
            }

            System.out.println("Llave privada guardada en " + PRIVATE_KEY_FILE);
            
            System.out.println("¡Pareja de llaves generada correctamente!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //TODO verificar que se hayan utilizado todos los algortimos
}
