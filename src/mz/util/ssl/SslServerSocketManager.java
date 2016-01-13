package mz.util.ssl;

import java.io.FileInputStream;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * Manejador de sockets de Servidor ssl.
 * 
 * @author martin.zaragoza
 * 
 */
public class SslServerSocketManager {
	private String keystore = "testFiles/certs";
	private String keystorePwd = "serverkspw";
	private String keyPwd = "serverpw";
	private SSLServerSocketFactory sslServerSocketFactory = null;

	public void testRun() {
		try {
			int serverport = 443;
			SSLServerSocket s = createServerSocket(serverport);
			System.out.println("waiting for connection...");
			SSLSocket c = (SSLSocket) s.accept();

			System.out.println("server handshakes client");
			c.startHandshake();
			System.out.println("server handshake complete!");

			System.out.println("connection success!");

		} catch (Exception e) {
			e.printStackTrace();
		}
	}// run

	/**
	 * Crea una nueva fabrica de sockets de servidor tipo ssl.
	 * 
	 * @return nueva fabrica de sockets de servidor tipo ssl.
	 * @throws SSLSocketManagerException
	 */
	private SSLServerSocketFactory createServerSocketFactory() throws SSLSocketManagerException {
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(keystore), keystorePwd.toCharArray());

			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, keyPwd.toCharArray());

			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init(ks);

			SSLContext sc = SSLContext.getInstance("TLS");
			TrustManager[] trustManagers = tmf.getTrustManagers();
			sc.init(kmf.getKeyManagers(), trustManagers, null);

			SSLServerSocketFactory ssf = sc.getServerSocketFactory();

			this.sslServerSocketFactory = ssf;

			return sslServerSocketFactory;
		} catch (Exception e) {
			throw new SSLSocketManagerException(e);
		}
	}// createServerSocketFactory

	/**
	 * Crea un nuevo socket de servidor de ssl.
	 * 
	 * @param serverPort
	 *            - Puerto al cual el socket debe escuchar.
	 * @return Nuevo socket servidor ssl.
	 * @throws SSLSocketManagerException
	 */
	public SSLServerSocket createServerSocket(int serverPort) throws SSLSocketManagerException {
		try {
			SSLServerSocketFactory ssf = sslServerSocketFactory == null ? createServerSocketFactory() : sslServerSocketFactory;
			SSLServerSocket s = (SSLServerSocket) ssf.createServerSocket(serverPort);
			return s;
		} catch (Exception e) {
			throw new SSLSocketManagerException(e);
		}
	}// createServerSocket

	/**
	 * Crea una instancia nueva de un manejador de sockets de servidor de tipo
	 * SSL.
	 * 
	 * @param keystore
	 *            - Path al archivo de keystore donde se encuentran los
	 *            certificados a usar.
	 * @param keystorePwd
	 *            - Password del keystore a usar.
	 * @param keyPwd
	 *            - Password de certificado.
	 */
	public SslServerSocketManager(String keystore, String keystorePwd, String keyPwd) {
		super();
		this.keystore = keystore;
		this.keystorePwd = keystorePwd;
		this.keyPwd = keyPwd;
	}// cons

	public static void main(String[] args) {
		new SslServerSocketManager("testFiles/certs", "serverkspw", "serverpw").testRun();
	}// main
}// SSLServer
