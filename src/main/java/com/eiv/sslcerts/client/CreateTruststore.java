package com.eiv.sslcerts.client;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.eiv.sslcerts.CryptoUtiles;

public class CreateTruststore {

	public static final Logger LOG = LogManager.getLogger();
	
	public static final String CERTIFICATE_FILE = "target/javadev/javadev.crt";
	public static final String CA_CERTIFICATE_FILE = "target/caCertificate.crt";
	
	public static final String KS_FILE = "target/javadev/javadev.jks";
	public static final String KS_PWD = "asd123";
	
	public static void main(String[] args) throws CertificateException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, IOException {
		CreateTruststore createTruststore = new CreateTruststore();
		createTruststore.create();
	}
	
	public void create() throws CertificateException, FileNotFoundException, IOException, KeyStoreException, NoSuchAlgorithmException {
		
		X509Certificate certificate = CryptoUtiles.loadCertificateFromPEMFormat(CERTIFICATE_FILE);
		X509Certificate caCertificate = CryptoUtiles.loadCertificateFromPEMFormat(CA_CERTIFICATE_FILE);
		
		KeyStore ks = CryptoUtiles.createKeyStore(KS_FILE, KS_PWD);
		ks.setCertificateEntry("javadev2", certificate);
		ks.setCertificateEntry("root", caCertificate);
		
		try(FileOutputStream fos = new FileOutputStream(KS_FILE)) {
			ks.store(fos, KS_PWD.toCharArray());
		}
		
		LOG.info("Listo!");
	}
}
