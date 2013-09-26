package org.bouncycastle.openpgp.examples;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.BufferedInputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.SocketException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.UserAttributeSubpacket;
import org.bouncycastle.bcpg.UserIDPacket;
import org.bouncycastle.bcpg.attr.ImageAttribute;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVectorGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;

public class BCPGUtils {
	static public enum Keytype {MASTER, SIGNING, ENCRYPTION, REVOKED};
    static public enum Op {ADD, REMOVE};

    public static final int ITER64     = 0x10; // s2kcount
    public static final int ITER128    = 0x20;
    public static final int ITER256    = 0x30;
    public static final int ITER512    = 0x40;
    public static final int ITER1K     = 0x50;
    public static final int ITER2K     = 0x60;
    public static final int ITER130K   = 0xc0; // BC 148 default

    public static final long EXPIRED   = 0;
    public static final long SECOND    = 1;
    public static final long MINUTE    = SECOND*60;
    public static final long HOUR      = MINUTE*MINUTE;
    public static final long DAY       = HOUR*24;
    public static final long WEEK      = DAY*7;
    public static final long YEAR      = WEEK*52;
    public static final long MONTH	   = YEAR/12;

    public static final int BIT1       = 1;
    public static final int BIT2       = BIT1+BIT1;
    public static final int BIT64      = BIT2*32;
    public static final int BIT128     = BIT64*BIT2;
    public static final int BIT256     = BIT128*BIT2;
    public static final int BIT512     = BIT256*BIT2;
    public static final int BIT1024    = BIT512*BIT2;
    public static final int BIT2048    = BIT1024*BIT2;
    public static final int BIT4096    = BIT2048*BIT2;

    public static final int CERTAINTITY6     = 6;
    public static final int CERTAINTITY8     = 8;
    public static final int CERTAINTITY10    = 10;
    public static final int CERTAINTITY12    = 12; // 0.9998 certainty vs highest execution time
    
    public static final String seperator = System.getProperty("file.separator");
    public final static String SKEY_RING = ".skr";
	public final static String PKEY_RING = ".pkr";

    public static String getAlgAsString(int algId)
    {
        switch (algId)
        {
            case PublicKeyAlgorithmTags.RSA_GENERAL:
                return "RSA_GENERAL";
            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
                return "RSA_ENCRYPT";
            case PublicKeyAlgorithmTags.RSA_SIGN:
                return "RSA_SIGN";
            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
                return "ELGAMAL_ENCRYPT";
            case PublicKeyAlgorithmTags.DSA:
                return "DSA";
            case PublicKeyAlgorithmTags.EC:
                return "EC";
            case PublicKeyAlgorithmTags.ECDSA:
                return "ECDSA";
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
                return "ELGAMAL_GENERAL";
            case PublicKeyAlgorithmTags.DIFFIE_HELLMAN:
                return "DIFFIE_HELLMAN";
        }

        return "Unknown encryption algorithm";
    }

    public static String getHashAlgAsString(int algId) {

        switch (algId) {
            case PGPUtil.DOUBLE_SHA:
                return "Double SHA";
            case PGPUtil.MD2:
                return "MD2";
            case PGPUtil.HAVAL_5_160:
                return "HAVAL 5 160";
            case PGPUtil.MD5:
                return "MD5";
            case PGPUtil.RIPEMD160:
                return "RIPEMD160";
            case PGPUtil.SHA1:
                return "SHA1";
            case PGPUtil.SHA224:
                return "SHA224";
            case PGPUtil.SHA256:
                return "SHA256";
            case PGPUtil.SHA384:
                return "SHA384";
            case PGPUtil.SHA512:
                return "SHA512";
            case PGPUtil.TIGER_192:
                return "TIGER 192";
        }
        return "Unknown Hash Algorithm";
    }
    
    public static String getSymmAlgAsString(int algId) {
    	switch (algId) {
    		case SymmetricKeyAlgorithmTags.AES_128:
    			return "AES_128";
    		case SymmetricKeyAlgorithmTags.AES_192:
    			return "AES_192";
    		case SymmetricKeyAlgorithmTags.AES_256:
    			return "AES_256";
    		case SymmetricKeyAlgorithmTags.BLOWFISH:
    			return "BLOWFISH";
    		case SymmetricKeyAlgorithmTags.CAST5:
    			return "CAST5";
    		case SymmetricKeyAlgorithmTags.DES:
    			return "DES";
    		case SymmetricKeyAlgorithmTags.IDEA:
    			return "IDEA";
    		case SymmetricKeyAlgorithmTags.NULL:
    			return "NULL";
    		case SymmetricKeyAlgorithmTags.SAFER:
    			return "SAFER";
    		case SymmetricKeyAlgorithmTags.TRIPLE_DES:
    			return "TRIPLE_DES";
    		case SymmetricKeyAlgorithmTags.TWOFISH:
    			return "TWOFISH";
    	}
    	return "UNKNOWN";
    }
    
    public static int getSymmAlgAsInt(String algStr) {
    	if (algStr.equals("AES_128")) 		return SymmetricKeyAlgorithmTags.AES_128;
    	if (algStr.equals("AES_192")) 		return SymmetricKeyAlgorithmTags.AES_192;
    	if (algStr.equals("AES_256"))		return SymmetricKeyAlgorithmTags.AES_256;
    	if (algStr.equals("BLOWFISH"))		return SymmetricKeyAlgorithmTags.BLOWFISH;
    	if (algStr.equals("CAST5"))			return SymmetricKeyAlgorithmTags.CAST5;
    	if (algStr.equals("DES"))			return SymmetricKeyAlgorithmTags.DES;
    	if (algStr.equals("IDEA"))			return SymmetricKeyAlgorithmTags.IDEA;
    	if (algStr.equals("NULL"))			return SymmetricKeyAlgorithmTags.NULL;
    	if (algStr.equals("SAFER"))			return SymmetricKeyAlgorithmTags.SAFER;
    	if (algStr.equals("TRIPLE_DES"))	return SymmetricKeyAlgorithmTags.TRIPLE_DES;
    	if (algStr.equals("TWOFISH"))		return SymmetricKeyAlgorithmTags.TWOFISH;
    	return -1;
    }

    static byte[] compressFile(String fileName, int algorithm) throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
        PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));
        comData.close();
        return bOut.toByteArray();
    }

    /**
     * Search a secret key ring collection for a secret key corresponding to keyID if it
     * exists.
     *
     * @param pgpSec a secret key ring collection.
     * @param keyID keyID we want.
     * @param pass passphrase to decrypt secret key with.
     * @return the private key.
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
            throws PGPException, NoSuchProviderException
    {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null)
        {
            return null;
        }

        return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
    }

    static public PGPSecretKeyRing findSecretKeyRing(PGPSecretKeyRingCollection psrc, long keyId) throws PGPException {
        PGPSecretKeyRing pskr = psrc.getSecretKeyRing(keyId);

        if(pskr == null) {
            return null;
        }

        return pskr;
    }

    static private PGPPublicKey findPublicKey(PGPPublicKeyRingCollection pkrc, long keyId) throws PGPException {


        PGPPublicKey pgpk = null;

        if (pkrc.contains(keyId))
            pgpk = pkrc.getPublicKey(keyId);

        return pgpk;
    }

    static public PGPPublicKeyRing findPublicKeyRing(PGPPublicKeyRingCollection pkrc, long keyId) throws PGPException {

        PGPPublicKeyRing ppkr = null;
        if (pkrc.contains(keyId))
            ppkr = pkrc.getPublicKeyRing(keyId);

        return ppkr;
    }

    // ************************************************************************************************
    // Public key
    // ************************************************************************************************
    // filename only
    static PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException
    {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPPublicKey pubKey = readPublicKey(keyIn);
        keyIn.close();
        return pubKey;
    }

    // filename and userId
    public static PGPPublicKey readPublicKey(String fileName, String userId) throws IOException, PGPException
    {
//        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        InputStream keyIn = PGPUtil.getDecoderStream(new FileInputStream(fileName));
        PGPPublicKey pubKey = readPublicKey(keyIn, userId);
        keyIn.close();
        return pubKey;
    }

    // filename, userId, keytype
    static PGPPublicKey readPublicKey(String fileName, String userId, Keytype keytype) throws Exception {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPPublicKey pubKey = readPublicKey(keyIn, userId, keytype, false);
        keyIn.close();
        return pubKey;
    }

    // InputStream, userId, keytype
    static public PGPPublicKey readPublicKey(InputStream in, String userId, Keytype keytype, boolean expiredOK) throws Exception {

        PGPPublicKeyRingCollection pgpPub = readPublicKeyRingCollection(in, userId, expiredOK);

        Iterator keyRingIter = pgpPub.getKeyRings(userId);
        while (keyRingIter.hasNext())
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext())
            {
                PGPPublicKey key = (PGPPublicKey)keyIter.next();
                Keytype kType = keytype;
                switch (kType) {
                    case MASTER:
                        if (key.isMasterKey()) {
                            return key;
                        }
                    case ENCRYPTION:
                        if (key.isEncryptionKey()) {
                            return key;
                        }
                    case REVOKED:
                        if (key.isRevoked()) {
                            return key;
                        }
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption, master or revoked key in key ring.");
    }
    
    // InputStream, userId, fingerprint
    static public PGPPublicKey readPublicKey(InputStream in, String userId, String fingerPrint, boolean expiredOK) throws Exception {

        PGPPublicKeyRingCollection pgpPub = readPublicKeyRingCollection(in, userId, expiredOK);

        Iterator keyRingIter = pgpPub.getKeyRings(userId);
        
        PGPPublicKey key = null;
        
        while (keyRingIter.hasNext())
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();

            while (keyIter.hasNext())
            {
                key = (PGPPublicKey)keyIter.next();
                
                String fpTemp = new String(Hex.encode(key.getFingerprint()));
                
                if (key.isEncryptionKey() && fpTemp.equalsIgnoreCase(fingerPrint)) {
                	return key;
                } else if (key.isMasterKey() && fpTemp.equalsIgnoreCase(fingerPrint) && !hasEncKeys(keyRing)) {
                    return key;
                } else {
                	key = null;
                }
            }
        }

        return key;
    }
    
 // InputStream, userId, KeyType, fingerprint
    static public PGPPublicKey readPublicKey(InputStream in, String userId, Keytype keytype, String fingerPrint) throws Exception {

        PGPPublicKeyRingCollection pgpPub = readPublicKeyRingCollection(in, userId, false);

        Iterator keyRingIter = pgpPub.getKeyRings(userId);
        
        PGPPublicKey key = null;
        
        while (keyRingIter.hasNext())
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();

            while (keyIter.hasNext())
            {
                key = (PGPPublicKey)keyIter.next();
                
                String fpTemp = new String(Hex.encode(key.getFingerprint()));
                
                Keytype kType = keytype;
                switch (kType) {
                    case MASTER:
                        if (key.isMasterKey() && fpTemp.equalsIgnoreCase(fingerPrint)) {
                            return key;
                        }
                    case ENCRYPTION:
                        if (key.isEncryptionKey() && fpTemp.equalsIgnoreCase(fingerPrint)) {
                            return key;
                        }
                    case REVOKED:
                        if (key.isRevoked() && fpTemp.equalsIgnoreCase(fingerPrint)) {
                            return key;
                        }
                }
            }
        }

        return key;
    }

    static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException
    {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input));

        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext())
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext())
            {
                PGPPublicKey key = (PGPPublicKey)keyIter.next();

                if (key.isEncryptionKey())
                {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find public key in key ring.");
    }

    // InputStream, Keytype
    static PGPPublicKey readPublicKey(InputStream input, Keytype keytype) throws IOException, PGPException
    {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input));

        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext())
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext())
            {
                PGPPublicKey key = (PGPPublicKey)keyIter.next();
                Keytype kType = keytype;
                switch (kType) {
                    case MASTER:
                        if (key.isMasterKey()) {
                            return key;
                        }
                    case ENCRYPTION:
                        if (key.isEncryptionKey()) {
                            return key;
                        }
                    case REVOKED:
                        if (key.isRevoked()) {
                            return key;
                        }
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption, master or revoked key in key ring.");
    }

    /**
     * A method that opens a key ring file and loads the first available key
     * suitable for encryption. Not recommended.
     *
     * @param input data stream containing the public key data
     * @return the first public key found.
     * @throws IOException
     * @throws PGPException
     */
    // InputStream and userId
    public static PGPPublicKey readPublicKey(InputStream input, String userId) throws IOException, PGPException
    {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input));

        Iterator keyRingIter = pgpPub.getKeyRings(userId);
        while (keyRingIter.hasNext())
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();
            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext())
            {
                PGPPublicKey key = (PGPPublicKey)keyIter.next();

                if (key.isEncryptionKey())
                {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }


    // InputSream, User Id, Keytype, PGPSignature add remove certification such as revoking an expired key.
    static public PGPPublicKey readPublicKey(InputStream input, String userId, Keytype keytype, PGPSignature pSig, Op certOp) throws IOException, PGPException
    {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input));

        Iterator keyRingIter = pgpPub.getKeyRings(userId);
        while (keyRingIter.hasNext())
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            Op cOp;
            if(certOp!=null)
                cOp = certOp;
            else
                cOp = Op.ADD;
            while (keyIter.hasNext())
            {
                PGPPublicKey key = (PGPPublicKey)keyIter.next();

                switch (keytype) {
                    case MASTER:
                        if (key.isMasterKey()) {
                            return getCertOpKey(key, userId, pSig, cOp);
                        }
                    case ENCRYPTION:
                        if (key.isEncryptionKey()) {
                            return getCertOpKey(key, userId, pSig, cOp);
                        }
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption or master key in key ring.");
    }


    // add or remove a cert to a public key and return a new key
    static public PGPPublicKey readPublicKey(PGPPublicKeyRingCollection pkrc, String userId, Keytype keytype, PGPSignature pSig, Op certOp) throws IOException, PGPException
    {

        Iterator keyRingIter = pkrc.getKeyRings(userId);
        while (keyRingIter.hasNext())
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            Op cOp;
            if(certOp!=null)
                cOp = certOp;
            else
                cOp = Op.ADD;
            while (keyIter.hasNext())
            {
                PGPPublicKey key = (PGPPublicKey)keyIter.next();

                switch (keytype) {
                    case MASTER:
                        if (key.isMasterKey()) {
                            return getCertOpKey(key, userId, pSig, cOp);
                        }
                    case ENCRYPTION:
                        if (key.isEncryptionKey()) {
                            return getCertOpKey(key, userId, pSig, cOp);
                        }
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption or master key in key ring.");
    }

    // Just return the key ring collection
    static public PGPPublicKeyRingCollection readPublicKeyRingCollection(InputStream in) throws Exception {

    	PGPPublicKeyRingCollection pkrc = null;
		try {
			pkrc = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in));
		} catch (IOException e) {
			System.out.println("PgpUtilities.listKeys() unable to open ");
            e.printStackTrace();
        } catch (PGPException e) {
        	System.out.println("PgpUtilities.listKeys() PGP exception found: PGPPublic key expected: PGPPublicKeyRing");
            e.printStackTrace();
        }
    	
        return pkrc;
    }

    // return a key ring collection for a particular user and no expired keys
    static public PGPPublicKeyRingCollection readPublicKeyRingCollection(InputStream in, String userId, boolean expiredOK) throws Exception {

        PGPPublicKeyRingCollection pkrc = readPublicKeyRingCollection(in);

        HashMap pkrHM = new HashMap<PGPPublicKey, PGPPublicKeyRing>();

        Collection pkrColl = new ArrayList();

        Iterator it = pkrc.getKeyRings(userId);

        while (it.hasNext())
        {
            PGPPublicKeyRing  pgpPub = (PGPPublicKeyRing)it.next();

            try {
                pgpPub.getPublicKey();
            } catch (Exception e) {
                e.printStackTrace();
                continue;
            }

            Iterator kit = pgpPub.getPublicKeys();

            while (kit.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) kit.next();

                if(key.isMasterKey() && expiredOK) {
                    pkrHM.put(key, pgpPub);
                    pkrColl.add(pgpPub);
                } else if(key.isMasterKey() && !isKeyExpired(key)) {
                    pkrHM.put(key, pgpPub);
                    pkrColl.add(pgpPub);
                } else if (key.isEncryptionKey() && expiredOK) {
                	pkrHM.put(key, pgpPub);
                    pkrColl.add(pgpPub);
                } else if (key.isEncryptionKey() && !isKeyExpired(key)) {
                	pkrHM.put(key, pgpPub);
                    pkrColl.add(pgpPub);
                } else if (key.isRevoked() && expiredOK) {
                	pkrHM.put(key, pgpPub);
                    pkrColl.add(pgpPub);
                } else if (key.isRevoked() && !isKeyExpired(key)) {
                	pkrHM.put(key, pgpPub);
                    pkrColl.add(pgpPub);
                }
            }
        }

        PGPPublicKeyRingCollection newPkrc = new PGPPublicKeyRingCollection(pkrColl);

        return newPkrc;
    }


    // Return a new public key ring collection with all the expired keys removed.
    /*static public PGPPublicKeyRingCollection readPublicKeyRingCollection(InputStream in, OutputStream out, String userId) throws Exception {

        PGPPublicKeyRingCollection pkrc = readPublicKeyRingCollection(in);

        HashMap pkrHM = new HashMap<PGPPublicKey, PGPPublicKeyRing>(); // TODO use this to keep key IDs to remove a key using the while() loop

        Collection pkrColl = new ArrayList();

        Iterator it = pkrc.getKeyRings(userId);

        while (it.hasNext())
        {
            PGPPublicKeyRing  pgpPub = (PGPPublicKeyRing)it.next();

            try {
                pgpPub.getPublicKey();
            } catch (Exception e) {
                e.printStackTrace();
                continue;
            }

            Iterator kit = pgpPub.getPublicKeys();

            while (kit.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) kit.next();

                if(key.isMasterKey() && !isKeyExpired(key)) {
                    pkrHM.put(key, pgpPub);

                    pkrColl.add(pgpPub);
                }
            }
        }

        PGPPublicKeyRingCollection newPkrc = new PGPPublicKeyRingCollection(pkrColl);

        writePublicKeyRingCollection(out, newPkrc, false);

        return newPkrc;
    }*/
    
    static public PGPPublicKeyRingCollection readPublicKeyRingCollection(InputStream in, String userId) throws Exception {

        PGPPublicKeyRingCollection pkrc = readPublicKeyRingCollection(in);

        HashMap pkrHM = new HashMap<PGPPublicKey, PGPPublicKeyRing>();

        Collection pkrColl = new ArrayList();

        Iterator it = pkrc.getKeyRings(userId);

        while (it.hasNext())
        {
            PGPPublicKeyRing  pgpPub = (PGPPublicKeyRing)it.next();

            try {
                pgpPub.getPublicKey();
            } catch (Exception e) {
                e.printStackTrace();
                continue;
            }

            Iterator kit = pgpPub.getPublicKeys();

            while (kit.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) kit.next();

                if(key.isMasterKey() && !isKeyExpired(key)) {
                    pkrHM.put(key, pgpPub);

                    pkrColl.add(pgpPub);
                }
            }
        }

        PGPPublicKeyRingCollection newPkrc = new PGPPublicKeyRingCollection(pkrColl);

        return newPkrc;
    }

    // Read a public keyring and add a public key to the ring and return the new key ring collection
    static public PGPPublicKeyRingCollection readPublicKeyRingCollection(InputStream in,
		                                                                String userId, char[]
		                                                                pass,
		                                                                PGPPublicKey key,
		                                                                Op op,
		                                                                int pubHashAlgTag,
		                                                                int secHashAlgTag) throws Exception {

        PGPPublicKeyRingCollection pkrc = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in));
        PGPPublicKeyRingCollection newPkrc = null;
        PGPKeyRingGenerator pkrg = null;

        if (getAlgAsString(key.getAlgorithm()).startsWith("RSA")) {
            pkrg = genRSAKeyRingGenerator(userId, pass, ITER130K, key.getBitStrength(), CERTAINTITY12, key.getValidSeconds(), pubHashAlgTag, secHashAlgTag);
        } else if (getAlgAsString(key.getAlgorithm()).startsWith("DSA")) {
            pkrg = genDSAElgamalKeyRingGenerator(key.getBitStrength(), key.getValidSeconds(), userId, pass, pubHashAlgTag);
        }

        PGPPublicKeyRing pkr = null;
        if (pkrg != null) {
            pkr = pkrg.generatePublicKeyRing();
        }
        if(op.equals(Op.ADD)) {
            newPkrc = PGPPublicKeyRingCollection.addPublicKeyRing(pkrc, pkr);
        } else if (op.equals(Op.REMOVE)) {
            pkr = findPublicKeyRing(pkrc, key.getKeyID());
            newPkrc = PGPPublicKeyRingCollection.removePublicKeyRing(pkrc, pkr);
        }
        return newPkrc;
    }

    // add a public key ring using the passed in public key
    static public PGPPublicKeyRingCollection readPublicKeyRingCollection(InputStream in,
                                                                         String userId, char[]
                                                                         pass,
                                                                         PGPPublicKey key,
                                                                         int pubHashAlgTag,
                                                                         int secHashAlgTag) throws Exception {

        PGPPublicKeyRingCollection pkrc = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in));
        PGPPublicKeyRingCollection newPkrc = null;
        PGPKeyRingGenerator pkrg = null;

        if (getAlgAsString(key.getAlgorithm()).startsWith("RSA")) {
            pkrg = genRSAKeyRingGenerator(userId, pass, ITER130K, key.getBitStrength(), CERTAINTITY12, key.getValidSeconds(), pubHashAlgTag, secHashAlgTag);
        } else if (getAlgAsString(key.getAlgorithm()).startsWith("DSA")) {
            pkrg = genDSAElgamalKeyRingGenerator(key.getBitStrength(), key.getValidSeconds(), userId, pass, pubHashAlgTag);
        }

        PGPPublicKeyRing pkr = null;
        if (pkrg != null) {
            pkr = pkrg.generatePublicKeyRing();
        }

        newPkrc = PGPPublicKeyRingCollection.addPublicKeyRing(pkrc, pkr);
        return newPkrc;
    }

    // remove method does not work
    static public PGPPublicKeyRingCollection readPublicKeyRingCollection(String fileName,
                                                                            String userId, 
                                                                            char[] pass,
                                                                            PGPPublicKey key,
                                                                            Op op,
                                                                            int pubHashAlgTag,
                                                                            int secHashAlgTag) throws Exception {

        FileInputStream in = new FileInputStream(fileName);

        PGPPublicKeyRingCollection pkrc = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in));
        PGPPublicKeyRingCollection newPkrc = null;
        PGPKeyRingGenerator pkrg = null;

        if (getAlgAsString(key.getAlgorithm()).startsWith("RSA")) {
            pkrg = genRSAKeyRingGenerator(userId, pass, ITER130K, key.getBitStrength(), CERTAINTITY12, key.getValidSeconds(), pubHashAlgTag, secHashAlgTag);
        } else if (getAlgAsString(key.getAlgorithm()).startsWith("DSA")) {
            pkrg = genDSAElgamalKeyRingGenerator(key.getBitStrength(), key.getValidSeconds(), userId, pass, pubHashAlgTag);
        }

        PGPPublicKeyRing pkr = null;
        if (pkrg != null) {
            pkr = pkrg.generatePublicKeyRing();
        }
        if(op.equals(Op.ADD) && !pkrc.contains(key.getKeyID())) {
            newPkrc = PGPPublicKeyRingCollection.addPublicKeyRing(pkrc, pkr);
        } else if (op.equals(Op.REMOVE) && pkrc.contains(key.getKeyID())) {
            newPkrc = PGPPublicKeyRingCollection.removePublicKeyRing(pkrc, pkr);
        }
        in.close();
        return newPkrc;
    }
    
    // remove a public key
    static public PGPPublicKeyRingCollection readPublicKeyRingCollection(InputStream in, String userId, String fingerPrint) throws Exception {

        PGPPublicKeyRingCollection pkrc = readPublicKeyRingCollection(in);
        PGPPublicKeyRingCollection newPkrc = null;

        Collection pkrColl = new CopyOnWriteArrayList();

        Iterator it = pkrc.getKeyRings(userId);
        
        PGPPublicKeyRing  pgpPub = null;
        
        while (it.hasNext()) {
        	pgpPub = (PGPPublicKeyRing)it.next();
        	pkrColl.add(pgpPub);
        }
        
        boolean hasSubKeys = false;

        Iterator cit = pkrColl.iterator();
        
        while (cit.hasNext() && !hasSubKeys) {
        	pgpPub = (PGPPublicKeyRing)cit.next();
        	
        	Iterator kit = pgpPub.getPublicKeys();

        	while (kit.hasNext()) {
        		PGPPublicKey key = (PGPPublicKey)kit.next();
        		String fpTemp = new String(Hex.encode(key.getFingerprint()));
        		
        		if(fpTemp.equalsIgnoreCase(fingerPrint) && key.isMasterKey() && !hasEncKeys(pgpPub)) {
        			if(!pkrColl.remove(pgpPub))
        				throw new Exception("Unable to remove the public key ring from the Collection");
        		} else if(fpTemp.equalsIgnoreCase(fingerPrint) && key.isEncryptionKey()) {
                	pgpPub = pgpPub.removePublicKey(pgpPub, key);
                    pkrColl.add(pgpPub);
                }
        	}
        }

//        if(!pkrColl.isEmpty())
        	newPkrc = new PGPPublicKeyRingCollection(pkrColl);

        return newPkrc;
    }
    
    private static boolean hasKeys(PGPPublicKeyRing pkr) {
    	Iterator it = pkr.getPublicKeys();
    	boolean hasKeys = false;
    	while(it.hasNext()) {
    		hasKeys = true;
    	}
    	return hasKeys;
    }
    
    private static boolean hasEncKeys(PGPPublicKeyRing pkr) {
    	Iterator it = pkr.getPublicKeys();
    	
    	boolean hasKeys = false;
    	while(it.hasNext()) {
    		PGPPublicKey key = (PGPPublicKey)it.next();
    		if(key.isEncryptionKey()) {
    			hasKeys = true;
    			break;
    		}
    	}
    	return hasKeys;
    }
    
    public static String getKeyType(PGPSecretKey sk) {
    	String keyType = null;
    	
    	if (sk.isMasterKey()) {
    		keyType = new String("MASTER");
    	} else if (sk.isSigningKey()) {
    		keyType = new String("SIGNING");
    	}
    	
    	return keyType;
    }

    //
    private static PGPPublicKey getCertOpKey(PGPPublicKey pKey, String uId, PGPSignature pSig, Op certOp) throws PGPException {
        PGPPublicKey lKey = null;
        if (certOp.equals(Op.ADD)) {
            new PGPPublicKey(pKey.getPublicKeyPacket(), new BcKeyFingerprintCalculator());
            lKey = PGPPublicKey.addCertification(pKey, uId, pSig);
        } else if (certOp.equals(Op.REMOVE)) {
            new PGPPublicKey(pKey.getPublicKeyPacket(), new BcKeyFingerprintCalculator());
            lKey = PGPPublicKey.removeCertification(pKey, uId, pSig);
        }
        return lKey;
    }

    // *****************************************************************************************************
    // Secret key
    // *****************************************************************************************************
    // filename only not recommended
    public static PGPSecretKey readSecretKey(String fileName) throws IOException, PGPException
    {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPSecretKey secKey = readSecretKey(keyIn);
        keyIn.close();
        return secKey;
    }

    // filename and userId
    public static PGPSecretKey readSecretKey(String fileName, String userId) throws IOException, PGPException
    {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPSecretKey secKey = readSecretKey(keyIn, userId);
        keyIn.close();
        return secKey;
    }

    // filename, userId, Keytype
    public static PGPSecretKey readSecretKey(String fileName, String userId, Keytype keyType) throws IOException, PGPException
    {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPSecretKey secKey = readSecretKey(keyIn, userId, keyType);
        keyIn.close();
        return secKey;
    }

    // filename, userId, partial match
    public static PGPSecretKey readSecretKey(String fileName, String userId, boolean partMatch) throws IOException, PGPException
    {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPSecretKey secKey = readSecretKey(keyIn, userId, partMatch);
        keyIn.close();
        return secKey;
    }

    // filename, userId, partial match and keytype
    public static PGPSecretKey readSecretKey(String fileName, String userId, boolean partMatch, Keytype keytype) throws IOException, PGPException
    {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPSecretKey secKey = readSecretKey(keyIn, userId, partMatch, keytype);
        keyIn.close();
        return secKey;
    }

    // InputStream, userId, partial match, ignore case
    public static PGPSecretKey readSecretKey(String fileName, String userId, boolean partMatch, boolean ignoreCase) throws IOException, PGPException
    {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPSecretKey secKey = readSecretKey(keyIn, userId, partMatch, ignoreCase);
        keyIn.close();
        return secKey;
    }

    // InputStream, userId, partial match, ignore case, keytype
    public static PGPSecretKey readSecretKey(String fileName, String userId, boolean partMatch, boolean ignoreCase, Keytype keytype) throws IOException, PGPException
    {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPSecretKey secKey = readSecretKey(keyIn, userId, partMatch, ignoreCase, keytype);
        keyIn.close();
        return secKey;
    }

    // filename only not recommended
    public static PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException
    {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input));

        Iterator keyRingIter = pgpSec.getKeyRings();

        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();
            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                return  (PGPSecretKey)keyIter.next();
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }

    /**
     * A routine that opens a key ring file and loads the first available key
     * suitable for signature generation.
     *
     * @param input stream to read the secret key ring collection from.
     * @return a secret key.
     * @throws IOException on a problem with using the input stream.
     * @throws PGPException if there is an issue parsing the input stream.
     */
    // InputStream and userId not recommended
    public static PGPSecretKey readSecretKey(InputStream input, String userId) throws IOException, PGPException
    {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input));

        Iterator keyRingIter = pgpSec.getKeyRings(userId);

        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();
            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                return  (PGPSecretKey)keyIter.next();
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }

    // InputStream, userId and Keytype
    public static PGPSecretKey readSecretKey(InputStream input, String userId, Keytype keytype) throws IOException, PGPException
    {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input));

        Iterator keyRingIter = pgpSec.getKeyRings(userId);

        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();
            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = (PGPSecretKey)keyIter.next();
                Keytype kType = keytype;
                switch (kType) {
                    case MASTER:
                        if (key.isMasterKey()) {
                            return key;
                        }
                    case SIGNING:
                        if (key.isSigningKey()) {
                            return key;
                        }
                }
            }
        }

        throw new IllegalArgumentException("Can't find master or signing key in key ring.");
    }

    // InputStream, userId, partial match first available
    public static PGPSecretKey readSecretKey(InputStream input, String userId, boolean partMatch) throws IOException, PGPException
    {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input));

        Iterator keyRingIter = pgpSec.getKeyRings(userId, partMatch);

        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();
            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                return  (PGPSecretKey)keyIter.next();
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }

    // InputStream, userId, partial match and Keytype
    public static PGPSecretKey readSecretKey(InputStream input, String userId, boolean partMatch, Keytype keytype) throws IOException, PGPException
    {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input));

        Iterator keyRingIter = pgpSec.getKeyRings(userId, partMatch);

        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();
            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = (PGPSecretKey)keyIter.next();
                Keytype kType = keytype;
                switch (kType) {
                    case MASTER:
                        if (key.isMasterKey()) {
                            return key;
                        }
                    case SIGNING:
                        if (key.isSigningKey()) {
                            return key;
                        }
                }
            }
        }

        throw new IllegalArgumentException("Can't find signing or master key in key ring.");
    }

    // InputStream, userId, partial match and ignore case
    public static PGPSecretKey readSecretKey(InputStream input, String userId, boolean partMatch, boolean ignoreCase) throws IOException, PGPException
    {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input));

        Iterator keyRingIter = pgpSec.getKeyRings(userId, partMatch, ignoreCase);

        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();
            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                return  (PGPSecretKey)keyIter.next();
            }
        }

        throw new IllegalArgumentException("Can't find secret key in key ring based on partial match: " + partMatch + " or based on ignore case: " + ignoreCase);
    }

    // InputStream, userId, partial match, ignore case and keytype
    public static PGPSecretKey readSecretKey(InputStream input, String userId, boolean partMatch, boolean ignoreCase, Keytype keytype) throws IOException, PGPException
    {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input));

        Iterator keyRingIter = pgpSec.getKeyRings(userId, partMatch, ignoreCase);

        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();
            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = (PGPSecretKey)keyIter.next();
                Keytype kType = keytype;
                switch (kType) {
                    case MASTER:
                        if (key.isMasterKey()) {
                            return key;
                        }
                    case SIGNING:
                        if (key.isSigningKey()) {
                            return key;
                        }
                }
            }
        }

        throw new IllegalArgumentException("Can't find master or signing key in key ring.");
    }

    // Read a secret key ring and add or remove a secret key to the ring (deprecated use the overloaded method that just adds a secret key)
    static public PGPSecretKeyRingCollection readSecretKeyRingCollection(InputStream in,
                                                                String userId,
                                                                char[] pass,
                                                                PGPSecretKey key,
                                                                Op op,
                                                                int pubHashAlgTag,
                                                                int secHashAlgTag) throws Exception {
        PGPSecretKeyRingCollection pskrc = new PGPSecretKeyRingCollection(in);
        PGPSecretKeyRingCollection newPskrc = null;

        PGPKeyRingGenerator pkrg = null;
        PGPPublicKey pubKey = key.getPublicKey();
        if (getAlgAsString(pubKey.getAlgorithm()).startsWith("RSA")) {
            pkrg = genRSAKeyRingGenerator(userId, pass, ITER130K, pubKey.getBitStrength(), CERTAINTITY12, pubKey.getValidSeconds(), pubHashAlgTag, secHashAlgTag);
        } else if (getAlgAsString(pubKey.getAlgorithm()).startsWith("DSA")) {
            pkrg = genDSAElgamalKeyRingGenerator(pubKey.getBitStrength(), pubKey.getValidSeconds(), userId, pass, pubHashAlgTag);
        }

        PGPSecretKeyRing skr = null;
        if (pkrg!=null) {
            skr = pkrg.generateSecretKeyRing();
        }

        if(op.equals(Op.ADD) && pskrc.contains(key.getKeyID())) {
            newPskrc = PGPSecretKeyRingCollection.addSecretKeyRing(pskrc, skr);
        } else if (op.equals(Op.REMOVE)) { // cannot find the target key to remove
            newPskrc = PGPSecretKeyRingCollection.removeSecretKeyRing(pskrc, skr); // does not work do not use
        }

        return newPskrc;
    }

    // Read a secret key ring and add a secret key to the ring
    static public PGPSecretKeyRingCollection readSecretKeyRingCollection(InputStream in,
                                                                  String userId,
                                                                  char[] pass,
                                                                  PGPSecretKey key,
                                                                  int pubHashAlgTag,
                                                                  int secHashAlgTag) throws Exception {

        PGPSecretKeyRingCollection pskrc = readSecretKeyRingCollection(in);

        PGPSecretKeyRingCollection newPskrc = null;

        PGPKeyRingGenerator pkrg = null;
        PGPPublicKey pubKey = key.getPublicKey();
        if (getAlgAsString(pubKey.getAlgorithm()).startsWith("RSA")) {
            pkrg = genRSAKeyRingGenerator(userId, pass, ITER130K, pubKey.getBitStrength(), CERTAINTITY12, pubKey.getValidSeconds(), pubHashAlgTag, secHashAlgTag);
        } else if (getAlgAsString(pubKey.getAlgorithm()).startsWith("DSA")) {
            pkrg = genDSAElgamalKeyRingGenerator(pubKey.getBitStrength(), pubKey.getValidSeconds(), userId, pass, pubHashAlgTag);
        }

        PGPSecretKeyRing skr = null;

        if (pkrg!=null) {
            skr = pkrg.generateSecretKeyRing();
        }

        newPskrc = PGPSecretKeyRingCollection.addSecretKeyRing(pskrc, skr);

        return newPskrc;
    }

    static public PGPSecretKeyRingCollection readSecretKeyRingCollection(InputStream in) throws IOException, PGPException {
        return new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(in));
    }
    
    static public PGPSecretKeyRingCollection readSecretKeyRingCollection(InputStream in, String userId, long keyId) throws IOException, PGPException {

        PGPSecretKeyRingCollection skrc = readSecretKeyRingCollection(in);

        HashMap skrHM = new HashMap<PGPSecretKey, PGPSecretKeyRing>();

        Collection skrColl = new ArrayList();

        Iterator it = skrc.getKeyRings(userId);

        while (it.hasNext()) {

        	boolean masterSkipped = true;
        	
            PGPSecretKeyRing pgpSec = (PGPSecretKeyRing) it.next();

            try {
                pgpSec.getSecretKey();
            } catch (Exception e) {
                e.printStackTrace();
                continue;
            }

            Iterator kit = pgpSec.getSecretKeys();

            while (kit.hasNext()) {
            	
                PGPSecretKey sKey = (PGPSecretKey) kit.next();

                long lKeyId = sKey.getKeyID();

                if(sKey.isMasterKey() && lKeyId!=keyId) {
                	masterSkipped = false;
                    skrHM.put(sKey, pgpSec);
                    skrColl.add(pgpSec);
                } else if (!masterSkipped && !sKey.isMasterKey()) { // get the sub-key
                	skrHM.put(sKey, pgpSec);
                    skrColl.add(pgpSec);
                }
            }
        }

        PGPSecretKeyRingCollection newSkrc = new PGPSecretKeyRingCollection(skrColl);

        return newSkrc;
    }

    static public PGPSecretKeyRingCollection readSecretKeyRingCollection(InputStream in, String userId, PGPSecretKey sk) throws IOException, PGPException {

        PGPSecretKeyRingCollection skrc = readSecretKeyRingCollection(in);
        
        PGPSecretKeyRing skr = null;
        
        PGPSecretKeyRing pgpSec = null;

        Iterator it = skrc.getKeyRings(userId);
        
        Collection skrColl = new ArrayList();
        
        boolean masterFound = false;

        while (it.hasNext()) {

            pgpSec = (PGPSecretKeyRing) it.next();

            try {
                pgpSec.getSecretKey();
            } catch (Exception e) {
                e.printStackTrace();
                continue;
            }

            Iterator kit = pgpSec.getSecretKeys();

            while (kit.hasNext()) {

                PGPSecretKey key = (PGPSecretKey) kit.next();
                
                long sKeyId = sk.getKeyID();

                if(key.getKeyID() == sKeyId && sk.isMasterKey()) {
                	skr = pgpSec.removeSecretKey(pgpSec, sk);
                	skrColl.add(skr);
                } else if (!key.isMasterKey()){
                	skr = pgpSec.removeSecretKey(pgpSec, key);
                }
            }
        }

        PGPSecretKeyRingCollection newSkrc = null;
        
        if (!skrColl.isEmpty())
        	newSkrc = new PGPSecretKeyRingCollection(skrColl);
        else {
        	skrColl.add(pgpSec);
        	newSkrc = new PGPSecretKeyRingCollection(skrColl);
        }

        return newSkrc;
    }

    static public PGPSecretKeyRingCollection readSecretKeyRingCollection(InputStream in, String userId) {

        PGPSecretKeyRingCollection skrc = null;
		try {
			skrc = readSecretKeyRingCollection(in);
		} catch (IOException e2) {
			System.out.println("BCPGUtils.readSecretKeyRingCollection() IOException for user: " + userId);
			e2.printStackTrace();
		} catch (PGPException e2) {
			System.out.println("BCPGUtils.readSecretKeyRingCollection() PGPException for user: " + userId);
			e2.printStackTrace();
		}

        Collection skrColl = new ArrayList();

        Iterator it = null;
		try {
			it = skrc.getKeyRings(userId);
		} catch (PGPException e1) {
			System.out.println("BCPGUtils.readSecretKeyRingCollection() Iterator PGPException for user: " + userId);
			e1.printStackTrace();
		}

        while (it.hasNext()) {

            PGPSecretKeyRing pgpSec = (PGPSecretKeyRing) it.next();

            try {
                pgpSec.getSecretKey();
            } catch (Exception e) {
                e.printStackTrace();
                continue;
            }

            Iterator kit = pgpSec.getSecretKeys();

            while (kit.hasNext()) {

                PGPSecretKey key = (PGPSecretKey) kit.next();

                if(key.isMasterKey()) { 

                    skrColl.add(pgpSec);
                }
            }
        }

        PGPSecretKeyRingCollection newSkrc = null;
		try {
			newSkrc = new PGPSecretKeyRingCollection(skrColl);
		} catch (IOException e) {
			System.out.println("BCPGUtils.readSecretKeyRingCollection IOException for user: " + userId);
			e.printStackTrace();
		} catch (PGPException e) {
			System.out.println("BCPGUtils.readSecretKeyRingCollection PGPException for user: " + userId);
			e.printStackTrace();
		}

        return newSkrc;
    }


    static public PGPKeyRingGenerator genRSAKeyRingGenerator(String id,             // user id
                                                             char[] pass,           // passphrase
                                                             int s2kcount,          // string to key specifier count
                                                             int bits,              // strength of key
                                                             int certainty,         // modulus prime certainty
                                                             long seconds,          // expiration of key
                                                             int pubHashAlgTag,     // public key signing
                                                             int secHashAlgTag)		// secret key signing 
                                                             throws PGPException, SignatureException
    {
    	
    	byte[] passPhrase = charToBytesASCII(pass);

        RSAKeyPairGenerator kpg = new RSAKeyPairGenerator(); // generate key pairs

        if(certainty!=CERTAINTITY12) {
            certainty=CERTAINTITY12; // default
        }

        kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), bits, certainty));
        AsymmetricCipherKeyPair akp = kpg.generateKeyPair();
        PGPKeyPair rsakp_sign = null;
        
		try {
			rsakp_sign = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, akp, new Date());
		} 
		catch (PGPException e) { // master key
			System.out.println("BCPGUtils.genRSAKeyRingGenerator() PGPException for master key " + e.getMessage());
			e.printStackTrace();
		}
		catch (NoSuchMethodError nme)
		{
			System.out.println("BCPGUtils.genRSAKeyRingGenerator() PGPException for master key " + nme.getMessage());
			nme.printStackTrace();
		}
		catch (Throwable th)
		{
			System.out.println("BCPGUtils.genRSAKeyRingGenerator() PGPException for master key " + th.getMessage());
			th.printStackTrace();
		}
		
        PGPKeyPair rsakp_enc = null;

		try {
			rsakp_enc = new BcPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, akp, new Date());
		} catch (PGPException e) {
			System.out.println("BCPGUtils.genRSAKeyRingGenerator() PGPException for encryption key");
			e.printStackTrace();
		} // encryption key

        PGPSignatureSubpacketGenerator signhashgen = new PGPSignatureSubpacketGenerator(); // self signed

        signhashgen.setKeyFlags(false, KeyFlags.SIGN_DATA|KeyFlags.CERTIFY_OTHER); // signed meta data

        signhashgen.setPreferredSymmetricAlgorithms (false, new int[] { // key message prefs
                        SymmetricKeyAlgorithmTags.CAST5,  // according to DH AES_256 may cause issues.
                        SymmetricKeyAlgorithmTags.AES_256,
                        SymmetricKeyAlgorithmTags.AES_192,
                        SymmetricKeyAlgorithmTags.AES_128
        });

        signhashgen.setPreferredHashAlgorithms(false, new int[] { // hash algorithm prefs
                        HashAlgorithmTags.SHA256,
                        HashAlgorithmTags.SHA1,
                        HashAlgorithmTags.SHA384,
                        HashAlgorithmTags.SHA512,
                        HashAlgorithmTags.SHA224,
        });

        signhashgen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION); // additional checksums to verify unsigned messages.

        signhashgen.setKeyExpirationTime(true, seconds);

        signhashgen.setRevocable(true, true);

        PGPSignatureSubpacketGenerator enchashgen = new PGPSignatureSubpacketGenerator(); // subkey signature

        enchashgen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS|KeyFlags.ENCRYPT_STORAGE); // purpose metadata

        enchashgen.setKeyExpirationTime(true, seconds);

        PGPDigestCalculator loBitCalc = null;
		try {
			loBitCalc = new BcPGPDigestCalculatorProvider().get(pubHashAlgTag);
		} catch (PGPException e) {
			System.out.println("BCPGUtils.genRSAKeyRingGenerator() PGPException for digest calculator");
			e.printStackTrace();
		}

        PGPDigestCalculator hiBitCalc = null;
		try {
			hiBitCalc = new BcPGPDigestCalculatorProvider().get(secHashAlgTag);
		} catch (PGPException e) {
			System.out.println("BCPGUtils.genRSAKeyRingGenerator() PGPException for master signing key");
			e.printStackTrace();
		} // encrypt secret key

        PBESecretKeyEncryptor pske = (new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, hiBitCalc, s2kcount)).build(pass); // s2kcount since BC148, use CAST5 instead of AES_256
        
        rsakp_sign = addCertData(passPhrase, rsakp_sign);
        
        PGPKeyRingGenerator keyRingGen = null;
        
		try {
			keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,   // metadata purpose
                                                rsakp_sign,                             // master key
                                                id,                                     // user id
                                                loBitCalc,                              // checksum calculator
                                                signhashgen.generate(),                 // meta data, expiration, etc.(hashed)
                                                null,                                   // unhashed metadata
                                                new BcPGPContentSignerBuilder(rsakp_sign.getPublicKey().getAlgorithm(),HashAlgorithmTags.SHA1), // key signer builder
                                                pske);
		} catch (PGPException e) {
			System.out.println("BCPGUtils.genRSAKeyRingGenerator() PGPException for key ring generator");
			e.printStackTrace();
		} // key encryptor

        try {
			keyRingGen.addSubKey(rsakp_enc, enchashgen.generate(), null);
		} catch (PGPException e) {
			System.out.println("BCPGUtils.genRSAKeyRingGenerator() PGPException adding subkey");
			e.printStackTrace();
		} // add subkey with signature

        return keyRingGen;
    }
    
    
    static private PGPKeyPair addCertData(byte[] passPhrase, PGPKeyPair kPair) throws PGPException, SignatureException {
    	
    	PGPUserAttributeSubpacketVectorGenerator asvGen = new PGPUserAttributeSubpacketVectorGenerator();
        
        asvGen.setImageAttribute(ImageAttribute.JPEG, passPhrase); // the UserAttributeSubpacket class is not visible (protected) so forced to use the image byte data array
        
        PGPUserAttributeSubpacketVector uVec = asvGen.generate();
        
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(kPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1));
        
        PGPPrivateKey sPrivKey = kPair.getPrivateKey();
        
        sGen.init(PGPSignature.POSITIVE_CERTIFICATION, sPrivKey);
        
        PGPSignature sSig = sGen.generateCertification(uVec, kPair.getPublicKey());
        
        PGPPublicKey sNKey = PGPPublicKey.addCertification(kPair.getPublicKey(), uVec, sSig);
        
        logPassPhraseData(sNKey, passPhrase);
        
        return new PGPKeyPair(sNKey, sPrivKey);
    }
    
    static private void logPassPhraseData(PGPPublicKey pk, byte[] passPhrase) {
    	Iterator it = pk.getUserAttributes();
        
        while (it.hasNext()) {
        	PGPUserAttributeSubpacketVector attributes = (PGPUserAttributeSubpacketVector)it.next();
            byte[] passTmp = attributes.getImageAttribute().getImageData();
            if(passTmp!=null) {
            	boolean blnResult = Arrays.areEqual(passPhrase, passTmp);
            	String password = bytesToString(passTmp);
            	System.out.println("BCPGUtils.genRSAKeyRingGenerator phrases are equal: " + blnResult + " " + password);
            } else {
            	System.out.println("BCPGUtils.genRSAKeyRingGenerator phrases not equal or phrase is null.");
            }
        }
    	
    }
    
    static public String getPublicKeyPassPhrase(PGPPublicKey pk) {
    	Iterator it = pk.getUserAttributes();

        while (it.hasNext()) {
        	PGPUserAttributeSubpacketVector attributes = (PGPUserAttributeSubpacketVector)it.next();
            byte[] passTmp = attributes.getImageAttribute().getImageData();
            if(passTmp!=null)
            	return bytesToString(passTmp);
        }
        
        return null;
    }

    static public PGPKeyRingGenerator genDSAElgamalKeyRingGenerator(
            int             bits,               // key strength
            long            seconds,            // key expiration in seconds
            String          identity,			// user id
            char[]          passPhrase,
            int             hashAlgTag)			// Hash Algorithm Tag
            throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        KeyPairGenerator    dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");

        dsaKpg.initialize(bits);

        // generate DSA key params before generation of the ring
        KeyPair             dsaKp = dsaKpg.generateKeyPair();

        KeyPairGenerator    elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        BigInteger g = null;
        BigInteger p = null;
        
        byte gKey[]=null; 
        byte pKey[]=null;
        
        try {
			gKey = PGPUtil.makeRandomKey(hashAlgTag, new SecureRandom());
			pKey = PGPUtil.makeRandomKey(hashAlgTag, new SecureRandom());

			g = new BigInteger(gKey).nextProbablePrime().abs();
            p = new BigInteger(pKey).nextProbablePrime().abs();
        	
		} catch (ArithmeticException ae) {
			if(g==null)
				g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
			if(p==null)
				p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);
        	System.out.println("BCPGUtils.genDSAElgamalKeyRingGenerator() Arithmetic Exception negative exponent " + ae.getMessage());
            ae.printStackTrace();
        }

        ElGamalParameterSpec elParams = new ElGamalParameterSpec(p, g);

        elgKpg.initialize(elParams);
        SecureRandom random = new SecureRandom();
        elgKpg.initialize(bits, random);

        KeyPair                    elgKp = elgKpg.generateKeyPair();

        PGPKeyPair        dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());
        PGPKeyPair        elgKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date());
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(hashAlgTag);

        PGPSignatureSubpacketGenerator ssgHashed = new PGPSignatureSubpacketGenerator();
        PGPSignatureSubpacketGenerator subKeyHashed = new PGPSignatureSubpacketGenerator();

        subKeyHashed.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE); // hashed meta data

        ssgHashed.setKeyFlags(false, KeyFlags.SIGN_DATA|KeyFlags.CERTIFY_OTHER);

        ssgHashed.setPreferredSymmetricAlgorithms(false, new int[] {
                SymmetricKeyAlgorithmTags.CAST5, // avoids potential issues w/ AES_256
                SymmetricKeyAlgorithmTags.AES_128,
                SymmetricKeyAlgorithmTags.AES_192,
                SymmetricKeyAlgorithmTags.AES_256,
                SymmetricKeyAlgorithmTags.BLOWFISH,
                SymmetricKeyAlgorithmTags.DES,
                SymmetricKeyAlgorithmTags.IDEA,
                SymmetricKeyAlgorithmTags.SAFER,
                SymmetricKeyAlgorithmTags.TRIPLE_DES,
                SymmetricKeyAlgorithmTags.TWOFISH
        });

        ssgHashed.setPreferredHashAlgorithms(false, new int[] {
                HashAlgorithmTags.SHA512,
                HashAlgorithmTags.TIGER_192,
                HashAlgorithmTags.SHA384,
                HashAlgorithmTags.DOUBLE_SHA,
                HashAlgorithmTags.HAVAL_5_160,
                HashAlgorithmTags.MD2,
                HashAlgorithmTags.MD5,
                HashAlgorithmTags.RIPEMD160,
                HashAlgorithmTags.SHA1,
                HashAlgorithmTags.SHA384,
                HashAlgorithmTags.SHA224
        });

        ssgHashed.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

        ssgHashed.setKeyExpirationTime(true, seconds);

        ssgHashed.setRevocable(true, true);

        PGPSignatureSubpacketVector ssv = ssgHashed.generate();

        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,   // cert level
                                                                dsaKeyPair,                             // master PGPKeyPair
                                                                identity,                               // user id
                                                                sha1Calc,                               // signing hash
                                                                ssv,                                    // subpacket vector
                                                                null,                                   // subpacket vector
                                                                new BcPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(),HashAlgorithmTags.SHA1),
                                                                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase)); // was AES_256 which has problems

        PGPSignatureSubpacketGenerator ssvEnc = new PGPSignatureSubpacketGenerator(); // subkey signature

        ssvEnc.setKeyExpirationTime(true, seconds); // key expiration in seconds

        ssvEnc.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS|KeyFlags.ENCRYPT_STORAGE); // purpose metadata

        keyRingGen.addSubKey(elgKeyPair, ssvEnc.generate(), null); // add subkey with signature

        return keyRingGen;
    }

    // returns if the key is expired or not
    static public boolean isKeyExpired(PGPPublicKey key) {

        boolean isExpired = false;

        Date now = new Date(); // Mon Jun 24 14:13:57 CDT 2013 "EEE MMM dd HH:mm:ss z yyyy"

        Calendar calexpired = Calendar.getInstance();

        Calendar calnow = Calendar.getInstance();

        calnow.setTime(now);

        calexpired.setTime(key.getCreationTime());

        calexpired.add(Calendar.SECOND, Integer.parseInt(Long.toString(key.getValidSeconds())));

        Date expired = calexpired.getTime();

        if(expired.compareTo(now)<0)
            isExpired = true;

        return isExpired;
    }
    
    // key expiration date.
    static public Date keyExpiration(PGPPublicKey key) {

        boolean isExpired = false;

        Date now = new Date(); // Mon Jun 24 14:13:57 CDT 2013 "EEE MMM dd HH:mm:ss z yyyy"

        Calendar calexpired = Calendar.getInstance();

        Calendar calnow = Calendar.getInstance();

        calnow.setTime(now);

        calexpired.setTime(key.getCreationTime());

        calexpired.add(Calendar.SECOND, Integer.parseInt(Long.toString(key.getValidSeconds())));

        Date expired = calexpired.getTime();

        return expired;
    }

    // returns if the key is revoked
    static boolean isKeyRevoked(PGPPublicKey key) {
        boolean revoked = false;
        if (key.isRevoked()) {
            revoked = true;
        }

        return revoked;
    }

    static public void writePublicKeyRingCollection(OutputStream pubOut, PGPPublicKeyRingCollection pkrc, boolean armor) throws PGPException, IOException {

        if (armor) {
            pubOut = new ArmoredOutputStream(pubOut);
        }

        pkrc.encode(pubOut);
    }

    static public void writeSecretKeyRingCollection(OutputStream secOut, PGPSecretKeyRingCollection skrc, boolean armor) throws IOException {

        if (armor) {
            secOut = new ArmoredOutputStream(secOut);
        }

        skrc.encode(secOut);
    }
    
    public static void exportRSAKeyPair(
            OutputStream    secretOut,
            OutputStream    publicOut,
            String          identity,
            char[]          passPhrase,
            boolean         armor,
            int             s2kcount,
            int             bits,
            int             certainty,
            long            expiration,
            int             pubHashAlgTag,
            int             secHashAlgTag)
            throws Exception {
        if (armor)
        {
            secretOut = new ArmoredOutputStream(secretOut);
        }

        PGPKeyRingGenerator pkrg = genRSAKeyRingGenerator(identity,
                                                        passPhrase,
                                                        s2kcount,
                                                        bits,
                                                        certainty,
                                                        expiration,
                                                        pubHashAlgTag,
                                                        secHashAlgTag);

        pkrg.generateSecretKeyRing().encode(secretOut);

        secretOut.close();

        if (armor)
        {
            publicOut = new ArmoredOutputStream(publicOut);
        }

        pkrg.generatePublicKeyRing().encode(publicOut);

        publicOut.close();
    }
    
    public static void exportDSAKeyPair(
        OutputStream    secretOut,
        OutputStream    publicOut,
        String          identity,
        char[]          passPhrase,
        long            expiration,
        boolean         armor,
        int             hashAlgTag,
        int             bits)
            throws Exception {
        if (armor)
        {
            secretOut = new ArmoredOutputStream(secretOut);
        }

        PGPKeyRingGenerator keyRingGen = genDSAElgamalKeyRingGenerator(bits, expiration, identity, passPhrase, hashAlgTag);

        keyRingGen.generateSecretKeyRing().encode(secretOut);
        
        secretOut.close();
        
        if (armor)
        {
            publicOut = new ArmoredOutputStream(publicOut);
        }
        
        keyRingGen.generatePublicKeyRing().encode(publicOut);
        
        publicOut.close();
    }
    
    /**********************************************************************************************/
    /**************************** File encryption/decryption **************************************/
    /**********************************************************************************************/
    
    public static void decryptFile(
        String inputFileName,
        String keyFileName,
        char[] passwd,
        String defaultFileName)
        throws IOException, NoSuchProviderException
    {
        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
        decryptFile(in, keyIn, passwd, defaultFileName);
        keyIn.close();
        in.close();
    }
        
        /**
         * decrypt the passed in message stream
         */
        public static void decryptFile(
            InputStream in,
            InputStream keyIn,
            char[]      passwd,
            String      defaultFileName)
        {    
            
            try
            {
            	in = PGPUtil.getDecoderStream(in);
                PGPObjectFactory        pgpF = new PGPObjectFactory(in);
                PGPEncryptedDataList    enc;

                Object                  o = pgpF.nextObject();
                //
                // the first object might be a PGP marker packet.
                //
                if (o instanceof PGPEncryptedDataList)
                {
                    enc = (PGPEncryptedDataList)o;
                }
                else
                {
                    enc = (PGPEncryptedDataList)pgpF.nextObject();
                }
                
                //
                // find the secret key
                //
                Iterator                    it = enc.getEncryptedDataObjects();
                PGPPrivateKey               sKey = null;
                PGPPublicKeyEncryptedData   pbe = null;
                PGPSecretKeyRingCollection  pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn));
                
                while (sKey == null && it.hasNext())
                {
                    pbe = (PGPPublicKeyEncryptedData)it.next();

                    sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd);
                }
                
                if (sKey == null)
                {
                    throw new IllegalArgumentException("secret key for message not found.");
                }
                
                InputStream         clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
                
                PGPObjectFactory    plainFact = new PGPObjectFactory(clear);
                
                PGPCompressedData   cData = (PGPCompressedData)plainFact.nextObject();
        
                InputStream         compressedStream = new BufferedInputStream(cData.getDataStream());
                PGPObjectFactory    pgpFact = new PGPObjectFactory(compressedStream);
                
                Object              message = pgpFact.nextObject();
                
                if (message instanceof PGPLiteralData)
                {
                    PGPLiteralData ld = (PGPLiteralData)message;

                    String outFileName = ld.getFileName();
                    if (outFileName.length() == 0 || outFileName.length() < defaultFileName.length())
                    {
                        outFileName = defaultFileName;
                    }

                    InputStream unc = ld.getInputStream();
                    OutputStream fOut =  new BufferedOutputStream(new FileOutputStream(outFileName));

                    Streams.pipeAll(unc, fOut);

                    fOut.close();
                }
                else if (message instanceof PGPOnePassSignatureList)
                {
                    throw new PGPException("encrypted message contains a signed message - not literal data.");
                }
                else
                {
                    throw new PGPException("message is not a simple encrypted file - type unknown.");
                }

                if (pbe.isIntegrityProtected())
                {
                    if (!pbe.verify())
                    {
                        System.out.println("BCPGUtils.decryptFile(): message failed integrity check.");
                    }
                    else
                    {
                    	System.out.println("BCPGUtils.decryptFile(): message integrity check passed");
                    }
                }
                else
                {
                	System.out.println("BCPGUtils.decrypteFile() no message integrity check");
                }
            }
            catch (PGPException e)
            {
                if (e.getUnderlyingException() != null)
                {
                    System.out.println("BCPGUtils.decryptFile(): " + e.getUnderlyingException().getMessage());
                }
            } catch (IOException e) {
				System.out.println("BCPGUtils.decryptFile() IO Exception: " + e.getMessage());
			} catch (NoSuchProviderException e) {
				System.out.println("BCPGUtils.decryptFile() No Such Provider: " + e.getMessage());
			}
        }

        private static void encryptFile(
            String          outputFileName,
            String          inputFileName,
            String          encKeyFileName,
            String          userId,
            Keytype 		keytype,
            boolean         armor,
            boolean         withIntegrityCheck)
                throws Exception {
            OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));
            PGPPublicKey encKey = readPublicKey(encKeyFileName, userId, keytype);
            encryptFile(out, inputFileName, encKey, armor, withIntegrityCheck);
            out.close();
        }

        private static void encryptFile(
            String          outputFileName,
            String          inputFileName,
            String          encKeyFileName,
            boolean         armor,
            boolean         withIntegrityCheck,
            boolean			compression)
            throws IOException, NoSuchProviderException, PGPException
        {
            OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));
            PGPPublicKey encKey = readPublicKey(encKeyFileName);
            encryptFile(out, inputFileName, encKey, armor, withIntegrityCheck);
            out.close();
        }

        public static void encryptFile(
            OutputStream    out,
            String          fileName,
            PGPPublicKey    encKey,
            boolean         armor,
            boolean         withIntegrityCheck)
        {    
            if (armor)
            {
                out = new ArmoredOutputStream(out);
            }
            
            try
            {    
                PGPEncryptedDataGenerator   cPk = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));
                    
                cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
                
                OutputStream                cOut = cPk.open(out, new byte[1 << 16]);
                
                PGPCompressedDataGenerator  comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
                                                                        
                PGPUtil.writeFileToLiteralData(comData.open(cOut), PGPLiteralData.BINARY, new File(fileName), new byte[1 << 16]);
                
                comData.close();
                
                cOut.close();

                if (armor)
                {
                    out.close();
                }
            }
            catch (PGPException e)
            {
                if (e.getUnderlyingException() != null)
                {
                    System.out.println("BCPGUtils.encryptFile() PGPException: " + e.getUnderlyingException().getMessage());
                }
            } catch (IOException e) {
				System.out.println("BCPGUtils.encryptFile() IO Exception: " + e.getMessage());
			}
        }
        
        public static boolean isFileEncrypted (String inputFileName)
        {
            InputStream in = null;
            boolean encrypted = false;
			try {
				in = new BufferedInputStream(new FileInputStream(inputFileName));
			} catch (FileNotFoundException e) {
				System.out.println("BCPGUtils.isFileEncrypted() " + e.getMessage());
			}
            encrypted = isFileEncrypted (in);
            try {
				in.close();
			} catch (IOException e) {
				System.out.println("BCPGUtils.isFileEncrypted() " + e.getMessage());
			}
            
            return encrypted;
        }
        
        public static boolean isFileEncrypted (InputStream in)
        {    
    		boolean encrypted = false;
            try {
				in = PGPUtil.getDecoderStream(in);
			} catch (IOException e) {
				System.out.println("BCPGUtils.isFileEncrypted(): IO Exception " + e.getMessage());
			}
            
            PGPObjectFactory        pgpF = new PGPObjectFactory(in);

			Object o = null;
			try {
				o = pgpF.nextObject();
			} catch (IOException e) {
				System.out.println("BCPGUtils.isFileEncrypted(): IO Exception. " + e.getMessage());
			}
			
			if(o!=null) { // PGP object?
				encrypted = true;
			}
            
            return encrypted;
        }
    
    /**********************************************************************************************/

    private static String getAlgorithm(int algId)
    {
        switch (algId)
        {
            case PublicKeyAlgorithmTags.RSA_GENERAL:
                return "RSA_GENERAL";
            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
                return "RSA_ENCRYPT";
            case PublicKeyAlgorithmTags.RSA_SIGN:
                return "RSA_SIGN";
            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
                return "ELGAMAL_ENCRYPT";
            case PublicKeyAlgorithmTags.DSA:
                return "DSA";
            case PublicKeyAlgorithmTags.EC:
                return "EC";
            case PublicKeyAlgorithmTags.ECDSA:
                return "ECDSA";
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
                return "ELGAMAL_GENERAL";
            case PublicKeyAlgorithmTags.DIFFIE_HELLMAN:
                return "DIFFIE_HELLMAN";
        }

        return "unknown";
    }
    
    public static Keytype getAlgAsKeyType(String type) {
    	Keytype keyType = null;
    	
    	if(type.equals("RSA_GENERAL") || type.equals("RSA_ENCRYPT") || type.equals("DSA") || type.equals("ELGAMAL_GENERAL")) return Keytype.MASTER;
    	if(type.equals("RSA_SIGN")) return Keytype.SIGNING;
    	if(type.equals("ELGAMAL_ENCRYPT")) return Keytype.ENCRYPTION;
    	
    	return keyType;
    }
    
    
    public static int getAlgorithmAsInt(String algStr)
    {
    	if(algStr.equals("RSA_GENERAL")) 			return PublicKeyAlgorithmTags.RSA_GENERAL;
    	else if(algStr.equals("RSA_ENCRYPT")) 		return PublicKeyAlgorithmTags.RSA_ENCRYPT;
    	else if(algStr.equals("RSA_SIGN")) 			return PublicKeyAlgorithmTags.RSA_SIGN;
    	else if(algStr.equals("ELGAMAL_ENCRYPT")) 	return PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT;
    	else if(algStr.equals("DSA")) 				return PublicKeyAlgorithmTags.DSA;
    	else if(algStr.equals("EC"))				return PublicKeyAlgorithmTags.EC;
    	else if(algStr.equals("ECDSA"))				return PublicKeyAlgorithmTags.ECDSA;
    	else if(algStr.equals("ELGAMAL_GENERAL"))	return PublicKeyAlgorithmTags.ELGAMAL_GENERAL;
    	else if(algStr.equals("DIFFIE_HELLMAN"))	return PublicKeyAlgorithmTags.DIFFIE_HELLMAN;
    	else if(algStr.equals("AES_128"))			return SymmetricKeyAlgorithmTags.AES_128;
    	else if(algStr.equals("AES_192"))			return SymmetricKeyAlgorithmTags.AES_192;
    	else if(algStr.equals("AES_256"))			return SymmetricKeyAlgorithmTags.AES_256;
    	else if(algStr.equals("BLOWFISH"))			return SymmetricKeyAlgorithmTags.BLOWFISH;
    	else if(algStr.equals("CAST5"))				return SymmetricKeyAlgorithmTags.CAST5;
    	else if(algStr.equals("DES"))				return SymmetricKeyAlgorithmTags.DES;
    	else if(algStr.equals("IDEA"))				return SymmetricKeyAlgorithmTags.IDEA;
    	else if(algStr.equals("NULL"))				return SymmetricKeyAlgorithmTags.NULL;
    	else if(algStr.equals("SAFER"))				return SymmetricKeyAlgorithmTags.SAFER;
    	else if(algStr.equals("TRIPLE_DES"))		return SymmetricKeyAlgorithmTags.TRIPLE_DES;
    	else if(algStr.equals("TWOFISH"))			return SymmetricKeyAlgorithmTags.TWOFISH;
    		
        return -1;
    }
    
    public static boolean validAlg(String algStr) {
    	boolean isValid = false;
    	if (getAlgorithmAsInt(algStr) != -1)
    		isValid = true;
    	
    	return isValid;
    }
    
    private static byte[] charToBytesASCII(char[] arry) {
    	byte[] b = new byte[arry.length];
    	for (int i = 0; i < b.length; i++) {
    		b[i] = (byte) arry[i];
    	}
    	return b;
	}
    
    public static String bytesToString(byte[] bytes) {
		char[] buffer = new char[bytes.length];
		for(int i = 0; i < buffer.length; i++) {
			char c = (char)bytes[i];
			buffer[i] = c;
		}
		return new String(buffer);
	}
}
