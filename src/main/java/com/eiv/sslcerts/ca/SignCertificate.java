package com.eiv.sslcerts.ca;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.eiv.sslcerts.CryptoUtiles;


public class SignCertificate {

	public static final Logger LOG = LogManager.getLogger();
	public static final String CSR_FILE = "target/wso2is.pininitos.net/csr.pem";
	public static final String HOST_IP = "192.168.0.10";
    public static final String HOST_NAME = "wso2is.pininitos.net";
//    public static final String ALIAS_NAME = "microcks.eivsoftware.net";
//    public static final String ALIAS_NAME_ALT = "mongo.eivsoftware.net";
	
	public static final String CA_DN = "C=AR, ST=Santa-Fe, O=Pininitos, OU=Familia, CN=pininitos.net";
	public static final String KS_FILE = "target/wso2is.pininitos.net/pininitosCA.jks";
	public static final String KS_PWD = "asd123";
	
//	public static final ASN1Encodable[] ALTERNATIVE_NAMES = null;
	public static final ASN1Encodable[] ALTERNATIVE_NAMES = new ASN1Encodable[] {
	        new GeneralName(GeneralName.dNSName, HOST_NAME),
            new GeneralName(GeneralName.iPAddress, HOST_IP),
            new GeneralName(GeneralName.dNSName, "*." + HOST_NAME)
//            new GeneralName(GeneralName.dNSName, ALIAS_NAME),
//            new GeneralName(GeneralName.dNSName, ALIAS_NAME_ALT)
    };

	public static void main(String[] args) throws OperatorCreationException, CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, UnrecoverableKeyException {
		SignCertificate signCertificate = new SignCertificate();
		signCertificate.sign();
	}
	
	public void sign() throws OperatorCreationException, CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, UnrecoverableKeyException {
		
		PKCS10CertificationRequest csr = CryptoUtiles.loadCSRFromPEMFormat(CSR_FILE);
		KeyStore caKeyStore = CryptoUtiles.createKeyStore(KS_FILE, KS_PWD);
		
		PrivateKey caPrivateKey = (PrivateKey) caKeyStore.getKey("myRootCA", KS_PWD.toCharArray());
		PublicKey caPublicKey = caKeyStore.getCertificate("myRootCA").getPublicKey(); 
		
		KeyPair caKeyPair = new KeyPair(caPublicKey, caPrivateKey);
		
		X509Certificate certificate = CryptoUtiles.generateSignedCertificate(
				csr, 
				CA_DN, 
				LocalDate.of(2018, 6, 1), 
				LocalDate.of(2032, 6, 20), 
				HOST_IP,
				HOST_NAME,
				ALTERNATIVE_NAMES,
				caKeyPair);

		String signedCertificatePemFormat = CryptoUtiles.toPEM("CERTIFICATE", certificate.getEncoded());
		LOG.info("Signed Certificate generated!\n{}", signedCertificatePemFormat);
		
		try(FileOutputStream fos = new FileOutputStream("target/wso2is.pininitos.net/wso2is.crt")) {
			fos.write(signedCertificatePemFormat.getBytes());
		}

		LOG.info("Listo!");
	}
}
