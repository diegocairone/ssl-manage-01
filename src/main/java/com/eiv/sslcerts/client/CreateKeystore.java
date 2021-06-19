package com.eiv.sslcerts.client;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.eiv.sslcerts.CryptoUtiles;

public class CreateKeystore {

	public static final Logger LOG = LogManager.getLogger();
	
	public static final String PKEY_FILE = "target/graylog.eivsoftware.net/key.pem";
	public static final String CERTIFICATE_FILE = "target/graylog.eivsoftware.net/graylog.crt";
	public static final String CA_CERTIFICATE_FILE = "target/caCertificate.crt";
    
	public static final String KS_FILE = "target/graylog.eivsoftware.net/graylog.jks";
	public static final String KS_PWD = "asd123";
	
	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException, InvalidKeySpecException {
		CreateKeystore createKeystore = new CreateKeystore();
		createKeystore.create();
	}
	
	public void create() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException, InvalidKeySpecException {

		PrivateKey privateKey = CryptoUtiles.loadPrivateKeyFromPEMFormat(PKEY_FILE);
		X509Certificate certificate = CryptoUtiles.loadCertificateFromPEMFormat(CERTIFICATE_FILE);
		X509Certificate caCertificate = CryptoUtiles.loadCertificateFromPEMFormat(CA_CERTIFICATE_FILE);
		
		KeyStore ks = CryptoUtiles.createKeyStore(KS_FILE, KS_PWD);
		ks.setKeyEntry("graylog", privateKey, KS_PWD.toCharArray(), new Certificate[] {
			certificate 
		});
		ks.setCertificateEntry("root", caCertificate);
		
		try(FileOutputStream fos = new FileOutputStream(KS_FILE)) {
			ks.store(fos, KS_PWD.toCharArray());
		}
		
		LOG.info("Listo!");
	}
}
