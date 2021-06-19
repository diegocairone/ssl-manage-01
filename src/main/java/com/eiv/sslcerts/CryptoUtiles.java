package com.eiv.sslcerts;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class CryptoUtiles {

	public static final Logger LOG = LogManager.getLogger();
	public static final int KEY_LENGTH = 2048;
	public static final String CRYPTO_PROVIDER = "BC";
	public static final String ALG_KEYPAIR = "RSA";
	public static final String ALG_SIGNATURE = "SHA256WithRSA";
	public static final String KEYSTORE_TYPE_JKS = "JKS";
	public static final String KEYSTORE_TYPE_P12 = "pkcs12";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static KeyPair genKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {

		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(ALG_KEYPAIR, CRYPTO_PROVIDER);
		keyPairGen.initialize(KEY_LENGTH);

		KeyPair keyPair = keyPairGen.generateKeyPair();

		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();

		LOG.info("Private key generated! Alg: {} - Format: {}", privateKey.getAlgorithm(), privateKey.getFormat());
		LOG.info("Public key generated! Alg: {} - Format: {}", publicKey.getAlgorithm(), publicKey.getFormat());

		return keyPair;
	}
	
	public static PKCS10CertificationRequest createCertificateSigningRequest(String name, KeyPair keyPair) throws OperatorCreationException {
		
		X500Name subject = new X500Name(name);
		PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
		
		PKCS10CertificationRequest certificationRequest = requestBuilder
	            .build(new JcaContentSignerBuilder(ALG_SIGNATURE)
	            		.setProvider(CRYPTO_PROVIDER)
	            		.build(keyPair.getPrivate())
        		);
		
		return certificationRequest;
	}

	public static X509Certificate genSelfSignedX509(String dn, LocalDate validFrom, LocalDate validTo, KeyPair keyPair) throws CertificateException {
		try {

			AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(ALG_SIGNATURE);
			AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
			
			AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory
					.createKey(keyPair.getPrivate().getEncoded());
			
			SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
			ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);
			
			Date from = convertFromLocalDate(validFrom);
			Date to = convertFromLocalDate(validTo);
			BigInteger sn = new BigInteger(64, new SecureRandom());
			
			X500Name name = new X500Name(dn);
			
			X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(name, sn, from, to, name, subPubKeyInfo);
			v3CertGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
			
			X509CertificateHolder certificateHolder = v3CertGen.build(sigGen);
						
			return new JcaX509CertificateConverter()
					.setProvider(CRYPTO_PROVIDER)
					.getCertificate(certificateHolder);
			
		} catch (CertificateException ce) {
			throw ce;
		} catch (Exception e) {
			throw new CertificateException(e);
		}
	}
	
	public static X509Certificate generateSignedCertificate(PKCS10CertificationRequest csr, String issuerDN, LocalDate validFrom, LocalDate validTo, KeyPair caKeyPair) throws OperatorCreationException, IOException, CertificateException, NoSuchAlgorithmException {
		return generateSignedCertificate(csr, issuerDN, validFrom, validTo, null, null, caKeyPair);
	}
	
	public static X509Certificate generateSignedCertificate(PKCS10CertificationRequest csr, String issuerDN, LocalDate validFrom, LocalDate validTo, String hostIP, String hostname, KeyPair caKeyPair) throws OperatorCreationException, IOException, CertificateException, NoSuchAlgorithmException {
	    return generateSignedCertificate(csr, issuerDN, validFrom, validTo, hostIP, hostname, null, caKeyPair);
	}
	
	public static X509Certificate generateSignedCertificate(PKCS10CertificationRequest csr, String issuerDN, LocalDate validFrom, LocalDate validTo, String hostIP, String hostname, ASN1Encodable[] alternativeNames, KeyPair caKeyPair) throws OperatorCreationException, IOException, CertificateException, NoSuchAlgorithmException {
		
		Date from = convertFromLocalDate(validFrom);
		Date to = convertFromLocalDate(validTo);
		BigInteger sn = new BigInteger(64, new SecureRandom());
		
		X500Name issuer = new X500Name(issuerDN); 
		X500Name subject = csr.getSubject();
		
		X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
				issuer, 
				sn, 
				from, 
				to, 
				subject, 
				csr.getSubjectPublicKeyInfo());
		

		PrivateKey caPrivateKey = caKeyPair.getPrivate();
		PublicKey caPublicKey = caKeyPair.getPublic();
		
		builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
		builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
		builder.addExtension(Extension.authorityKeyIdentifier, false,
			new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey)
		);
		builder.addExtension(Extension.subjectKeyIdentifier, false,
			new JcaX509ExtensionUtils().createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo())
		);
		
		if(alternativeNames == null) {
		    if(hostname != null && !hostname.isEmpty()) {
	            GeneralNames subjectAltName = new GeneralNames(new GeneralName[] { 
	                    new GeneralName(GeneralName.dNSName, hostname),
	                    new GeneralName(GeneralName.iPAddress, hostIP)
	                });
	            builder.addExtension(Extension.subjectAlternativeName, false, subjectAltName);
	        }
		} else {
		    DERSequence subjectAlternativeNames = new DERSequence(alternativeNames);
		    builder.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeNames);
		}
		
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(ALG_SIGNATURE);
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		
		AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(caPrivateKey.getEncoded());
		ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);
		
		X509CertificateHolder certificateHolder = builder.build(signer);
		X509Certificate certificate = new JcaX509CertificateConverter().setProvider(CRYPTO_PROVIDER).getCertificate(certificateHolder);
		
		return certificate;
	}

	public static String toPEM(String header, byte[] encoded) throws IOException {

		PemObject pemObject = new PemObject(header, encoded);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(baos))) {
			pemWriter.writeObject(pemObject);
		}

		return baos.toString();
	}
	
	public static PKCS10CertificationRequest loadCSRFromDERFormat(String filename) throws IOException {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		PKCS10CertificationRequest csr = new PKCS10CertificationRequest(keyBytes);
		return csr;
	}
	
	public static PKCS10CertificationRequest loadCSRFromPEMFormat(String filename) throws IOException {
		
		try(FileInputStream fis = new FileInputStream(filename)) {
			InputStreamReader reader = new InputStreamReader(fis);
			try(PEMParser pemParser = new PEMParser(reader)) {
				PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pemParser.readObject();
				return csr;
			}
		}
	}
	
	public static PrivateKey loadPrivateKeyFromPEMFormat(String filename) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		
		try(FileInputStream fis = new FileInputStream(filename)) {
			InputStreamReader reader = new InputStreamReader(fis);
			try(PEMParser pemParser = new PEMParser(reader)) {
				PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) pemParser.readObject();
			    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
			    KeyFactory kf = KeyFactory.getInstance(ALG_KEYPAIR, CRYPTO_PROVIDER);
			    PrivateKey key = kf.generatePrivate(keySpec);
			    return key;
			}
		}
	}
	
	public static X509Certificate loadCertificateFromPEMFormat(String filename) throws CertificateException, FileNotFoundException, IOException {
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		try (FileInputStream is = new FileInputStream(filename)) {
			X509Certificate certificate = (X509Certificate) fact.generateCertificate(is);
			return certificate;
		}
	}
	
	public static KeyStore createPkcs12(String keystoreFile, String password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException {

		KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE_P12, CRYPTO_PROVIDER);
		File file = new File(keystoreFile);
		
		if(file.exists()) {
	        try(FileInputStream in = new FileInputStream(file)) {        
	            keyStore.load(in, password.toCharArray());
	        }
		} else {
			keyStore.load(null, password.toCharArray());
		}
        
        return keyStore;
	}
	
	public static KeyStore createKeyStore(String keystoreFile, String password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		
		KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE_JKS);
		File file = new File(keystoreFile);
		
		if(file.exists()) {
	        try(FileInputStream in = new FileInputStream(file)) {        
	            keyStore.load(in, password.toCharArray());
	        }
		} else {
			keyStore.load(null, password.toCharArray());
		}
        
        return keyStore;
	}
	
	public static Date convertFromLocalDate(LocalDate localDate) {
		Date date = Date.from(localDate.atStartOfDay(ZoneId.systemDefault()).toInstant());
		return date;
	}
}
