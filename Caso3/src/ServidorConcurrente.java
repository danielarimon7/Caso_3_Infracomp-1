import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;

public class ServidorConcurrente extends Thread{

    private final int PUERTO;
    private ArrayList<Integer> idClientes;
    private HashMap<Integer, Estados> paquetes;
    private int numeroClientes;
    private final CyclicBarrier barreraMenu;
    private CyclicBarrier barrierServidor;

    public ServidorConcurrente(int PUERTO, ArrayList<Integer> idClientes, HashMap<Integer, Estados> paquetes, int numeroClientes, CyclicBarrier barreraMenu){
        this.PUERTO = PUERTO;
        this.idClientes = idClientes;
        this.paquetes = paquetes;
        this.numeroClientes = numeroClientes;
        this.barreraMenu = barreraMenu;
    }


    public void run() {
        ServerSocket ss = null;
        try {
            ss = new ServerSocket(PUERTO);
            System.out.println("Servidor escuchando en el puerto " + PUERTO);

            //Barrera para que el servidor concurrente solo termine cuando terminen los delegados
            barrierServidor = new CyclicBarrier(numeroClientes+1);
            // Esperar conexiones y crear delegados
            for(int i = 0; i < numeroClientes; i++) {
                Socket socket = ss.accept();
                //TODO no debería incluir el id del servidor delegado?
                //TODO hacer que el cliente le pase al id el numero de proceso
                ServidorDelegado servidor = new ServidorDelegado(idClientes, paquetes, socket, barrierServidor);
                servidor.start();
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

        // //Barrera para esperar a los delegados
        // try {
        //     barrierServidor.await();
        // } catch (InterruptedException e) {
            
        //     e.printStackTrace();
        // } catch (BrokenBarrierException e) {
            
        //     e.printStackTrace();
        // }

        // //Barrera para que no se muestre el menú de opciones hasta que todos terminen
        // try {
        //     barreraMenu.await();
        // } catch (InterruptedException e) {
            
        //     e.printStackTrace();
        // } catch (BrokenBarrierException e) {
            
        //     e.printStackTrace();
        // }
    }
}
