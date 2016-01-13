import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.net.Socket;

import mz.util.ssl.SSLClientSocketManager;

public class SslClientTest {
	static final int STORE_INDEX = 0;
	static final int STORE_PASS_INDEX = 1;
	static final int XML_INDEX = 2;
	static final int MIN_ARGS = 3;
	private Socket socket;

	void run(String args[]) {
		try {
			if (args.length < MIN_ARGS) {
				throw new Exception("Argumentos insuficientes!");
			}

			String trustStore = args[STORE_INDEX];
			String trustStorePassword = args[STORE_PASS_INDEX];

			buildSocket(trustStore, trustStorePassword);

			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			DataInputStream in = new DataInputStream(socket.getInputStream());
			long start = System.currentTimeMillis();

			for (long stop = start; stop - start >= 0L; stop = System.currentTimeMillis()) {
				String outputString = args[XML_INDEX];
				out.writeUTF(outputString);
				String inputString = in.readUTF();
				System.out.println(inputString);
				Thread.sleep(10000L);
			}

			out.close();
			in.close();
			System.out.print("Terminando cliente");
			socket.close();
		} catch (Exception e) {
			System.out.print((new StringBuilder("Error:")).append(e.getMessage()).toString());
		}
	}

	public static void main(String args[]) {
		new SslClientTest().run(args);
	}

	void print(String msg) {
		System.out.println("SslClientTest::" + msg);
	}

	private void buildSocket(String trustStore, String trustStorePassword) throws Exception {
		print("trustStore=" + trustStore);
		print("trustStorePassword=" + trustStorePassword);

		assertStoreExistence(trustStore);

		this.socket = new SSLClientSocketManager(trustStore, trustStorePassword, trustStorePassword).createSocket("localhost", 5555);
	}

	private void assertStoreExistence(String trustStore) throws Exception {
		if (!new File(trustStore).exists()) {
			throw new Exception(trustStore + " no existe!");
		}
	}
}
