package com.eiv.sslcerts.ca;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.eiv.sslcerts.CryptoUtiles;


public class RootCA {

	public static final Logger LOG = LogManager.getLogger();
	public static final String CA_DN = "C=AR, ST=Santa-Fe, O=Pininitos, OU=Familia, CN=pininitos.net";
	
	public static final String KS_FILE = "target/pininitos-flia/pininitosCA.jks";
	public static final String KS_PWD = "asd123";
	
	private PrivateKey caPrivateKey = null;
	private X509Certificate caCertificate = null;
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException, KeyStoreException {
		
		RootCA rootCA = new RootCA();
		rootCA.run();
	}
	
	public void run() throws NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException, KeyStoreException {
		
		LOG.info("Generando claves para CA ...");
		KeyPair keyPair = genKeyPair();

		LOG.info("Private key generated!\n{}", 
				CryptoUtiles.toPEM("PRIVATE KEY", keyPair.getPrivate().getEncoded()));
		
		X509Certificate certificate = CryptoUtiles.genSelfSignedX509(
				CA_DN, 
				LocalDate.of(2018, 6, 1), 
				LocalDate.of(2022, 5, 31), 
				keyPair);
		
		LOG.info("Generando certificado CA ...");
		caCertificate = certificate;
		
		LOG.info("Certificate generated!\n{}", 
				CryptoUtiles.toPEM("CERTIFICATE", certificate.getEncoded()));
		
		KeyStore ks = CryptoUtiles.createKeyStore(KS_FILE, KS_PWD);
		ks.setKeyEntry("myRootCA", caPrivateKey, KS_PWD.toCharArray(), new Certificate[] { 
			caCertificate 
		});
		
		try(FileOutputStream fos = new FileOutputStream(KS_FILE)) {
			ks.store(fos, KS_PWD.toCharArray());
		}
		
		LOG.info("Listo!");
	}
	
	public KeyPair genKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
		
		KeyPair keyPair = CryptoUtiles.genKeyPair();		
		caPrivateKey = keyPair.getPrivate();
		
		return keyPair;
	}
}
