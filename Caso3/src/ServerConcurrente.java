import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;

public class ServerConcurrente extends Thread {

    private final int puerto;
    private ArrayList<Integer> listaClientes;
    private HashMap<Integer, EstadoPaquete> mapaPaquetes;
    private int totalClientes;

    public ServerConcurrente(int puerto, ArrayList<Integer> listaClientes, HashMap<Integer, EstadoPaquete> mapaPaquetes, int totalClientes) {
        this.puerto = puerto;
        this.listaClientes = listaClientes;
        this.mapaPaquetes = mapaPaquetes;
        this.totalClientes = totalClientes;

    }

    public void run() {
        ServerSocket servidorSocket = null;
        try {
            servidorSocket = new ServerSocket(puerto);
            System.out.println("Puerto Servidor:" + puerto);

            for (int contador = 0; contador < totalClientes; contador++) {
                Socket conexionCliente = servidorSocket.accept();
                ServerDelegado delegadoServidor = new ServerDelegado(listaClientes, mapaPaquetes, conexionCliente);
                System.out.println("Servidor concurrente " + (contador + 1));
                delegadoServidor.start();
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            if (servidorSocket != null) {
                try {
                    servidorSocket.close();
                } catch (IOException excepcionCierre) {
                    excepcionCierre.printStackTrace();
                }
            }
        }
    }
}
