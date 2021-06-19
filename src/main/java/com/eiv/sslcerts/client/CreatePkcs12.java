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

public class CreatePkcs12 {

	public static final Logger LOG = LogManager.getLogger();
	
	public static final String HOST_NAME = "eq035";
	public static final String PKEY_FILE = "target/" + HOST_NAME + "/key.pem";
	public static final String CERTIFICATE_FILE = "target/" + HOST_NAME + "/" + HOST_NAME + ".crt";
	
	public static final String P12_FILE = "target/" + HOST_NAME + "/" + HOST_NAME + ".p12";
	public static final String P12_PWD = "asd123";
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException, CertificateException, KeyStoreException {
		
		CreatePkcs12 createPkcs12 = new CreatePkcs12();
		createPkcs12.create();
	}
	
	public void create() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException, CertificateException, KeyStoreException {
		
		PrivateKey privateKey = CryptoUtiles.loadPrivateKeyFromPEMFormat(PKEY_FILE);
		X509Certificate certificate = CryptoUtiles.loadCertificateFromPEMFormat(CERTIFICATE_FILE);
		
		KeyStore ks = CryptoUtiles.createPkcs12(P12_FILE, P12_PWD);
		ks.setKeyEntry(HOST_NAME, privateKey, P12_PWD.toCharArray(), new Certificate[] {
			certificate 
		});
		
		try(FileOutputStream fos = new FileOutputStream(P12_FILE)) {
			ks.store(fos, P12_PWD.toCharArray());
		}
		
		LOG.info("Listo!");
	}
}
