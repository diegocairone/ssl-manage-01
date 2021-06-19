package com.eiv.sslcerts.client;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.eiv.sslcerts.CryptoUtiles;

public class ClientCertificateRequest {

	public static final Logger LOG = LogManager.getLogger();
	public static final String CN = "wso2is.pininitos.net";
	public static final String CLIENT_DN = "C=AR, ST=Santa-Fe, O=Pininitos, OU=Familia, CN=" + CN;
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, IOException {
		
		ClientCertificateRequest clientCertificate = new ClientCertificateRequest();
		clientCertificate.run();
	}
	
	public void run() throws NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, IOException {
		
		LOG.info("Generando claves para certificado cliente de {} ...", CN);
		KeyPair keyPair = CryptoUtiles.genKeyPair();		
		
		PrivateKey privateKey = keyPair.getPrivate();
		String pkPemFormat = CryptoUtiles.toPEM("PRIVATE KEY", privateKey.getEncoded());
		
		LOG.info("Private key generated!\n{}", pkPemFormat);
		
		try(FileOutputStream fos = new FileOutputStream("target/" + CN +"/key.pem")) {
			fos.write(pkPemFormat.getBytes());
		}
		
		PKCS10CertificationRequest csr = CryptoUtiles.createCertificateSigningRequest(
			CLIENT_DN, 
			keyPair);
		
		String csrPemFormat = CryptoUtiles.toPEM("CERTIFICATE REQUEST", csr.getEncoded());
		LOG.info("Certificate generated!\n{}", csrPemFormat);
		
		try(FileOutputStream fos = new FileOutputStream("target/" + CN + "/csr.pem")) {
			fos.write(csrPemFormat.getBytes());
		}
	}
}
