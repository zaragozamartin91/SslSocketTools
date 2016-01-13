package mz.util.ssl;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * Manejador de sockets de cliente ssl.
 * 
 * @author martin.zaragoza
 * 
 */
public class SSLClientSocketManager {
	private String truststore = "testFiles/jssecacerts";
	private String truststorePwd = "12345678";
	private String keyPwd = "serverpw";
	private SSLSocketFactory sslSocketFactory = null;

	public void testRun() {
		try {
			String serverip = "localhost";
			int serverport = 443;
			SSLSocket sslSocket = (SSLSocket) createSocket(serverip, serverport);

			System.out.println("client handshakes with server");
			sslSocket.startHandshake();
			System.out.println("client handshake complete!");

			System.out.println("connection success!");

			printCertificates(sslSocket);

			sslSocket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}//testRun

	private SSLSocketFactory createSocketFactory() throws SSLSocketManagerException {
		try {
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new FileInputStream(truststore), truststorePwd.toCharArray());

			KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
			keyManagerFactory.init(keyStore, keyPwd.toCharArray());

			TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
			trustManagerFactory.init(keyStore);

			SSLContext sslContext = SSLContext.getInstance("TLS");
			TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
			sslContext.init(keyManagerFactory.getKeyManagers(), trustManagers, null);

			SSLSocketFactory ssf = sslContext.getSocketFactory();

			this.sslSocketFactory = ssf;

			return this.sslSocketFactory;
		} catch (Exception e) {
			throw new SSLSocketManagerException(e);
		}

	}// createSocketFactory

	/**
	 * Crea un socket para establecer una conexion https con un servidor.
	 * 
	 * @param serverip
	 *            - Ip o host de servidor remoto.
	 * @param serverport
	 *            - Puerto al cual conectarse.
	 * @return Nuevo socket de conexion.
	 * @throws SSLSocketManagerException
	 */
	public SSLSocket createSocket(String serverip, int serverport) throws SSLSocketManagerException {
		try {
			SSLSocketFactory ssf = sslSocketFactory == null ? createSocketFactory() : sslSocketFactory;
			SSLSocket sslSocket = (SSLSocket) ssf.createSocket(serverip, serverport);
			return sslSocket;
		} catch (Exception e) {
			throw new SSLSocketManagerException(e);
		}
	}// createSocket

	/**
	 * Imprime certificados de servidor remoto.
	 * 
	 * @param sslSocket
	 */
	public void printCertificates(SSLSocket sslSocket) {
		try {
			Certificate[] serverCerts = sslSocket.getSession().getPeerCertificates();
			System.out.println("Retreived Server's Certificate Chain");

			System.out.println(serverCerts.length + "Certifcates Found\n\n\n");
			for (int i = 0; i < serverCerts.length; i++) {
				Certificate myCert = serverCerts[i];
				System.out.println("====Certificate:" + (i + 1) + "====");
				System.out.println("-Public Key-\n" + myCert.getPublicKey());
				System.out.println("-Certificate Type-\n " + myCert.getType());

				System.out.println();
			}
		} catch (SSLPeerUnverifiedException e) {
			error("SSLClientSocketManager::error imprimiendo certificados de servidor : " + e.toString());
		}
	}// printCertificates

	private void error(String string) {
		System.err.println(string);
	}

	/**
	 * Crea una instancia de manejador de sockets ssl cliente.
	 * 
	 * @param truststore
	 *            - Path de archivo de truststore (keystore donde se encuentran
	 *            certificados de confianza. keystore de servidor puede
	 *            funcionar como truststore).
	 * @param truststorePwd
	 *            - Password de truststore.
	 * @param keyPwd
	 *            - Password de certificado.
	 */
	public SSLClientSocketManager(String truststore, String truststorePwd, String keyPwd) {
		super();
		this.truststore = truststore;
		this.truststorePwd = truststorePwd;
		this.keyPwd = keyPwd;
	}

	public static void main(String[] args) {
		new SSLClientSocketManager("testFiles/jssecacerts", "12345678", "serverpw").testRun();
	}
}// SSLClientSocketManager
