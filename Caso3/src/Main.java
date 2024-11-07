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
    private static final String RUTA_LLAVE_PUBLICA = "publicKey.ser";
    private static final String RUTA_LLAVE_PRIVADA = "privateKey.ser";

    public static void main(String[] args) throws IOException {
        ArrayList<Integer> clientes = inicializarClientes(32);
        HashMap<Integer, Estados> paquetes = inicializarPaquetes(clientes);

        boolean ejecutando = true;
        try (Scanner entrada = new Scanner(System.in)) {
            while (ejecutando) {
                mostrarMenu();
                int opcion = entrada.nextInt();
                ejecutando = ejecutarOpcion(opcion, clientes, paquetes, entrada);
            }
        }
    }

    private static ArrayList<Integer> inicializarClientes(int cantidad) {
        ArrayList<Integer> clientes = new ArrayList<>();
        for (int i = 1; i <= cantidad; i++) {
            clientes.add(i);
        }
        return clientes;
    }

    private static HashMap<Integer, Estados> inicializarPaquetes(ArrayList<Integer> clientes) {
        HashMap<Integer, Estados> paquetes = new HashMap<>();
        HashMap<Integer, Estados> estados = new HashMap<>();
        estados.put(0, Estados.ENOFICINA);
        estados.put(1, Estados.RECOGIDO);
        estados.put(2, Estados.ENCLASIFICACION);
        estados.put(3, Estados.DESPACHADO);
        estados.put(4, Estados.ENENTREGA);
        estados.put(5, Estados.ENTREGADO);

        Random aleatorio = new Random();
        for (Integer id : clientes) {
            paquetes.put(id + id, estados.get(aleatorio.nextInt(5)));
        }
        return paquetes;
    }

    private static void mostrarMenu() {
        System.out.println("======== MENÚ ========");
        System.out.println("1. Generar llaves RSA");
        System.out.println("2. Iniciar servidor concurrente");
        System.out.println("3. Ejecutar modo iterativo de servidor y cliente");
        System.out.println("4. Salir");
        System.out.print("Seleccione una opción: ");
    }

    private static boolean ejecutarOpcion(int opcion, ArrayList<Integer> clientes, HashMap<Integer, Estados> paquetes, Scanner entrada) {
        switch (opcion) {
            case 1 -> generarLlaves();
            case 2 -> iniciarServidorConcurrente(clientes, paquetes, entrada);
            case 3 -> iniciarModoIterativo(clientes, paquetes, entrada);
            case 4 -> {
                System.out.println("Saliendo del programa...");
                return false;
            }
            default -> System.out.println("Opción inválida, intente de nuevo.");
        }
        return true;
    }

    private static void generarLlaves() {
        try {
            KeyPairGenerator generadorLlaves = KeyPairGenerator.getInstance("RSA");
            generadorLlaves.initialize(1024);
            KeyPair parLlaves = generadorLlaves.generateKeyPair();
            guardarLlave(parLlaves.getPublic(), RUTA_LLAVE_PUBLICA, "Llave pública generada y guardada.");
            guardarLlave(parLlaves.getPrivate(), RUTA_LLAVE_PRIVADA, "Llave privada generada y guardada.");
        } catch (Exception e) {
            System.err.println("Error al generar llaves: " + e.getMessage());
        }
    }

    private static void guardarLlave(Object llave, String ruta, String mensajeExito) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(ruta))) {
            oos.writeObject(llave);
            System.out.println(mensajeExito + " Archivo: " + ruta);
        } catch (IOException e) {
            System.err.println("Error al guardar la llave en " + ruta + ": " + e.getMessage());
        }
    }

    private static void iniciarServidorConcurrente(ArrayList<Integer> clientes, HashMap<Integer, Estados> paquetes, Scanner entrada) {
        System.out.print("Número de clientes concurrentes: ");
        int numeroClientes = entrada.nextInt();
        CyclicBarrier barrera = new CyclicBarrier(numeroClientes + 1);

        new ServidorConcurrente(PUERTO, clientes, paquetes, numeroClientes).start();
        for (int i = 0; i < numeroClientes; i++) {
            new Cliente(1, barrera).start();
        }
        esperarBarrera(barrera);
    }

    private static void iniciarModoIterativo(ArrayList<Integer> clientes, HashMap<Integer, Estados> paquetes, Scanner entrada) {
        System.out.print("Número de consultas: ");
        int numeroConsultas = entrada.nextInt();
        CyclicBarrier barrera = new CyclicBarrier(3);

        new ServidorIterativo(PUERTO, clientes, paquetes, numeroConsultas, barrera).start();
        new Cliente(numeroConsultas, barrera).start();
        esperarBarrera(barrera);
    }

    private static void esperarBarrera(CyclicBarrier barrera) {
        try {
            barrera.await();
        } catch (InterruptedException | BrokenBarrierException e) {
            System.err.println("Error en la sincronización: " + e.getMessage());
        }
    }
}
