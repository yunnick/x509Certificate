package demo;


import java.io.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.*;
import java.util.Date;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import sun.misc.BASE64Encoder;

import static com.sun.xml.internal.ws.policy.privateutil.PolicyUtils.Text.NEW_LINE;
import static demo.KeyStoreType.BKS;
import static demo.KeyStoreType.JKS;


public class X509CertDaoImpl implements X509Dao {

    public static final KeyStoreType Default_keyType = JKS;
    public static final String Default_KeyPairGenerator = "RSA";
    public static final String Default_Signature = "SHA256withRSA";
    public static final String cert_type = "X.509";
    public static final Integer Default_KeySize = 2048;

    /**
     * 在将java生成的证书导出到文件的时候，需要将下面两行信息对应的添加到证书内容的头部后尾部
     */
    private static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERTIFICATE = "-----END CERTIFICATE-----";

    /**
     * 在将java生成的私钥导出到文件的时候，需要将下面两行信息对应的添加到私钥内容的头部后尾部
     */
    private static final String BEGIN_RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String END_RSA_PRIVATE_KEY = "-----END RSA PRIVATE KEY-----";

    static {
        // 系统添加BC加密算法 以后系统中调用的算法都是BC的算法
        Security.addProvider(new BouncyCastleProvider());
    }


    public void createKeystore(String issuer, Date notBefore, Date notAfter, String certDestPath,
                          BigInteger serial, String keyPassword, String alias, KeyStoreType type) throws Exception {
        //产生公私钥对
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(Default_KeyPairGenerator);
        kpg.initialize(Default_KeySize);
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        // 组装证书 颁发者及拥有者
        X500Name issueDn = new X500Name(issuer);
        X500Name subjectDn = new X500Name(issuer);
        //组装公钥信息
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo
                .getInstance(new ASN1InputStream(publicKey.getEncoded()).readObject());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                issueDn, serial, notBefore, notAfter, subjectDn, subjectPublicKeyInfo);
        //证书的签名数据
        ContentSigner sigGen = new JcaContentSignerBuilder(Default_Signature).build(privateKey);

        /*
         * 以上是证书的基本信息 如果要添加用户扩展信息 则比较麻烦 首先要确定version必须是v3否则不行 然后按照以下步骤
         *
         */
        Extension extension = new Extension(Extension.subjectKeyIdentifier, false, new DEROctetString(new SubjectKeyIdentifier(getDigest(publicKey))));

        X509CertificateHolder holder = builder.addExtension(extension).build(sigGen);
        byte[] certBuf = holder.getEncoded();
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance(cert_type).
                generateCertificate(new ByteArrayInputStream(certBuf));

        // 创建KeyStore,存储证书
        KeyStore store = KeyStore.getInstance(type.getValue());

        store.load(null, null);

        store.setKeyEntry(alias, keyPair.getPrivate(), keyPassword.toCharArray(), new Certificate[]{certificate});
//        store.setCertificateEntry(alias+"cert", certificate);
        FileOutputStream fout = new FileOutputStream(certDestPath);
        store.store(fout, keyPassword.toCharArray());
        fout.close();
    }

    public void createJks(String issuer, Date notBefore, Date notAfter, String certDestPath,
                          BigInteger serial, String keyPassword, String alias) throws Exception {

        createKeystore(issuer, notBefore, notAfter, certDestPath,
                serial, keyPassword, alias, KeyStoreType.JKS);
    }

    public void createBks(String issuer, Date notBefore, Date notAfter, String certDestPath,
                          BigInteger serial, String keyPassword, String alias) throws Exception {

        createKeystore(issuer, notBefore, notAfter, certDestPath,
                serial, keyPassword, alias, BKS);
    }

    private static byte[] getDigest(PublicKey publicKey)
    {
        Digest digest = new SHA1Digest();
        byte[]  resBuf = new byte[digest.getDigestSize()];

        byte[] bytes = publicKey.getEncoded();
        digest.update(bytes, 0, bytes.length);
        digest.doFinal(resBuf, 0);
        return resBuf;
    }

    public static X509Certificate getCertficate(File crtFile) {
        CertificateFactory cf;
        X509Certificate cert = null;
        FileInputStream crtIn = null;
        try {
            cf = CertificateFactory.getInstance(cert_type);
            crtIn = new FileInputStream(crtFile);
            cert = (X509Certificate) cf.generateCertificate(crtIn);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } finally {
            if(crtIn != null){
                try {
                    crtIn.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return cert;
    }

    public Certificate getCertificate(String alias, String certPath, String keyPassword) throws Exception {
        char[] charArray = keyPassword.toCharArray();
        KeyStore ks = KeyStore.getInstance(Default_keyType.getValue());
        FileInputStream fis = new FileInputStream(certPath);
        ks.load(fis, charArray);
        fis.close();
        Enumeration enumas = ks.aliases();
        String keyAlias = null;
        if (enumas.hasMoreElements()) {
            keyAlias = (String) enumas.nextElement();
            if (alias.equals(keyAlias)){
                return ks.getCertificate(keyAlias);
            }
        }
        return null;
    }

    public void importCertToKeystore(Certificate certificate, String certAlias, KeyStore store, String ksPath, String keyPassword)throws Exception{
        store.setCertificateEntry(certAlias, certificate);
        FileOutputStream fout = new FileOutputStream(ksPath);
        store.store(fout, keyPassword.toCharArray());
        fout.close();
    }

    @Override
    public void createCert(String issuer, Date notBefore, Date notAfter, String certDestPath,
                           BigInteger serial, String keyPassword, String alias) throws Exception {
        //产生公私钥对
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(Default_KeyPairGenerator);
        kpg.initialize(Default_KeySize);
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        // 组装证书
        X500Name issueDn = new X500Name(issuer);
        X500Name subjectDn = new X500Name(issuer);
        //组装公钥信息
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo
                .getInstance(new ASN1InputStream(publicKey.getEncoded()).readObject());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                issueDn, serial, notBefore, notAfter, subjectDn, subjectPublicKeyInfo);
        //证书的签名数据
        ContentSigner sigGen = new JcaContentSignerBuilder(Default_Signature).build(privateKey);
        X509CertificateHolder holder = builder.build(sigGen);
        byte[] certBuf = holder.getEncoded();
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance(cert_type).
                generateCertificate(new ByteArrayInputStream(certBuf));

        createCerFile(certificate, "/Users/liulu/IdeaProjects/x509/src/main/resources/test.cer");
        exportCrtPem(certificate, "/Users/liulu/IdeaProjects/x509/src/main/resources/test.pub.pem");
        // 创建KeyStore,存储证书
        KeyStore store = KeyStore.getInstance(Default_keyType.getValue());

        store.load(null, null);

        store.setKeyEntry(alias, keyPair.getPrivate(), keyPassword.toCharArray(), new Certificate[]{certificate});
//        store.setCertificateEntry(alias+"cert", certificate);
        FileOutputStream fout = new FileOutputStream(certDestPath);
        store.store(fout, keyPassword.toCharArray());
        fout.close();
    }


    @Override
    public void printCert(String certPath, String keyPassword) throws Exception {
        char[] charArray = keyPassword.toCharArray();
        KeyStore ks = KeyStore.getInstance(Default_keyType.getValue());
        FileInputStream fis = new FileInputStream(certPath);
        ks.load(fis, charArray);
        fis.close();
        System.out.println("keystore type=" + ks.getType());
        Enumeration enumas = ks.aliases();
        String keyAlias = null;
        if (enumas.hasMoreElements()) {
            keyAlias = (String) enumas.nextElement();
            System.out.println("alias=[" + keyAlias + "]");
        }
        System.out.println("is key entry=" + ks.isKeyEntry(keyAlias));
        PrivateKey prikey = (PrivateKey) ks.getKey(keyAlias, charArray);
        Certificate cert = ks.getCertificate(keyAlias);
        PublicKey pubkey = cert.getPublicKey();
        System.out.println("cert class = " + cert.getClass().getName());
        System.out.println("cert = " + cert);
        System.out.println("public key = " + pubkey);
        System.out.println("private key = " + prikey);
    }

    @Override
    public PublicKey getPublicKey(String certPath, String keyPassword) throws Exception {
        char[] charArray = keyPassword.toCharArray();
        KeyStore ks = KeyStore.getInstance(Default_keyType.getValue());
        FileInputStream fis = new FileInputStream(certPath);
        ks.load(fis, charArray);
        fis.close();
        Enumeration enumas = ks.aliases();
        String keyAlias = null;
        if (enumas.hasMoreElements()) {
            keyAlias = (String) enumas.nextElement();
            Certificate certificate = ks.getCertificate(keyAlias);

            return ks.getCertificate(keyAlias).getPublicKey();
        }
        return null;
    }

    @Override
    public PrivateKey getPrivateKey(String certPath, String keyPassword, String alias) throws Exception {
        char[] charArray = keyPassword.toCharArray();
        KeyStore ks = KeyStore.getInstance(Default_keyType.getValue());
        FileInputStream fis = new FileInputStream(certPath);
        ks.load(fis, charArray);
        fis.close();
        Enumeration enumas = ks.aliases();
        String keyAlias = null;
        if (enumas.hasMoreElements()) {
            keyAlias = (String) enumas.nextElement();
            if (alias.equals(keyAlias)){
                return (PrivateKey) ks.getKey(keyAlias, charArray);
            }

        }
        return null;
    }

    /**
     * 生成原格式 cer证书
     * @return
     */
    public boolean createCerFile(Certificate cert, String certPath) {
        try {
            String cerString = new BASE64Encoder().encode(cert.getEncoded());
            System.out.println(cerString);

            //生成cer证书文件
            FileOutputStream fos = new FileOutputStream(certPath);
            fos.write(cert.getEncoded()); //证书可以二进制形式存入库表，存储字段类型为BLOB
            fos.close();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("createPublicKey error：" + e.getMessage());
            return false;
        }
    }

    /**
     * 将JAVA创建的证书内容导出到文件， 基于BASE64转码了。
     *
     * @param devCrt  设备证书对象
     * @param crtPath 设备证书存储路径
     */
    public static void exportCrtPem(Certificate devCrt, String crtPath) {
        try {
            export(BEGIN_CERTIFICATE + NEW_LINE, END_CERTIFICATE, devCrt.getEncoded(), crtPath);
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }

    }

    /**
     * 导出私钥内容到文件中，以base64编码。
     * 注意，java生成的私钥文件默认是PKCS#8的格式，加载的时候，要注意对应关系。
     *
     * @param key
     * @param keyPath
     */
    public static void exportKey(PrivateKey key, String keyPath) {
        export(BEGIN_RSA_PRIVATE_KEY + NEW_LINE, END_RSA_PRIVATE_KEY, key.getEncoded(), keyPath);
    }

    public static void exportCertAndKeyWithPem(Certificate devCrt, PrivateKey key, String pemPath) {
        BASE64Encoder base64Crt = new BASE64Encoder();
        FileOutputStream fosKey = null;
        try {
            fosKey = new FileOutputStream(new File(pemPath));
            fosKey.write((BEGIN_RSA_PRIVATE_KEY + NEW_LINE).getBytes());
            base64Crt.encodeBuffer(key.getEncoded(), fosKey);
            fosKey.write((END_RSA_PRIVATE_KEY + NEW_LINE).getBytes());
            fosKey.write((BEGIN_CERTIFICATE + NEW_LINE).getBytes());
            base64Crt.encodeBuffer(devCrt.getEncoded(), fosKey);
            fosKey.write((END_CERTIFICATE + NEW_LINE).getBytes());

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        } finally {
            if (fosKey != null) {
                try {
                    fosKey.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private static void export(String begin, String end, byte[] conent, String path){
        BASE64Encoder base64Crt = new BASE64Encoder();
        FileOutputStream fosKey = null;
        try {
            fosKey = new FileOutputStream(new File(path));
            fosKey.write(begin.getBytes());
            base64Crt.encodeBuffer(conent, fosKey);
            fosKey.write(end.getBytes());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fosKey != null) {
                try {
                    fosKey.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    @Override
    public void certDelayTo(Date endTime, String certPath, String password) throws Exception {

    }

    @Override
    public void changePassword(String certPath, String oldPwd, String newPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance(Default_keyType.getValue());
        FileInputStream fis = new FileInputStream(certPath);
        ks.load(fis, oldPwd.toCharArray());
        fis.close();
        FileOutputStream output = new FileOutputStream(certPath);
        ks.store(output, newPwd.toCharArray());
        output.close();
    }

    @Override
    public void deleteAlias(String certPath, String password, String alias, String entry) throws Exception {
        char[] charArray = password.toCharArray();
        KeyStore ks = KeyStore.getInstance(Default_keyType.getValue());
        FileInputStream fis = new FileInputStream(certPath);
        ks.load(fis, charArray);
        fis.close();
        if (ks.containsAlias(alias)) {
            ks.deleteEntry(entry);
            FileOutputStream output = new FileOutputStream(certPath);
            ks.store(output, password.toCharArray());
            output.close();
        } else {
            throw new Exception("该证书未包含别名--->" + alias);
        }
    }

    static void createServerCertificate(String serverDomain, String serverAlias, String fileName, String keyPassword, String path) throws Exception {
        X509CertDaoImpl impl = new X509CertDaoImpl();
        String issuer = getIssuer(serverDomain);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        /**
         * create server certificate
         */
        String serverCertPath = path + "/"+fileName+"." + Default_keyType.getFileSuffix();
        impl.createJks(issuer, new Date(), new Date("2020/09/27"), serverCertPath, serial, keyPassword, serverAlias);
        Certificate serverCertificate = impl.getCertificate(serverAlias, serverCertPath, keyPassword);
        impl.createCerFile(serverCertificate, path + "/"+fileName+ ".cer");
        exportCrtPem(serverCertificate, path + "/"+fileName+ ".pub.pem");

    }

    static String getIssuer(String domain){
//        return "CN="+domain+", OU=siot, O=siot, L=BJ, ST=BJ, C=CN";
        return "C=US, ST=CA, L=SF, O=siot, OU=siot, CN="+domain;
    }

    static void createClientCertificate(String serverKsPath, String serverCertPath, String serverDomain, String serverAlias, String keyPassword, String clientName, String path) throws Exception{
        X509CertDaoImpl impl = new X509CertDaoImpl();

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis()/1000);

        Certificate serverCertificate = impl.getCertificate(serverAlias, serverKsPath, keyPassword);
        Certificate serverCertificate2 = impl.getCertficate(new File(serverCertPath));

        String clientIssuer = getIssuer(serverDomain);
        String clientIssuerbak = ((X509Certificate)serverCertificate).getIssuerX500Principal().toString();
        /**
         * create client certificate
         */
        String clientJksPath = path + "/"+clientName+"." + Default_keyType.getFileSuffix();
        String clientAlias = clientName;
        impl.createJks(clientIssuer, new Date(), new Date("2020/09/27"), clientJksPath, serial, keyPassword, clientAlias);

        Certificate  clientCertificate = impl.getCertificate(clientAlias, clientJksPath, keyPassword);
        PrivateKey privateKey = impl.getPrivateKey(clientJksPath, keyPassword, clientAlias);
        impl.createCerFile(clientCertificate, path +"/"+clientName+".cer");
        exportCertAndKeyWithPem(clientCertificate, privateKey,path+"/"+clientName+".nopass.pem");



        KeyStore jksStore = KeyStore.getInstance(Default_keyType.getValue());
        jksStore.load(new FileInputStream(clientJksPath), keyPassword.toCharArray());
        impl.importCertToKeystore(serverCertificate, serverAlias, jksStore, clientJksPath, keyPassword);

        String clientBksPath = path + "/"+clientName+"." + BKS.getFileSuffix();
        impl.createBks(clientIssuer, new Date(), new Date("2020/09/27"), clientBksPath, serial, keyPassword, clientAlias);
        KeyStore bksStore = KeyStore.getInstance(BKS.getValue());
        bksStore.load(new FileInputStream(clientBksPath), keyPassword.toCharArray());
        impl.importCertToKeystore(serverCertificate, serverAlias, bksStore, clientBksPath, keyPassword);

    }

    public static void main(String[] args) throws Exception {
        X509CertDaoImpl impl = new X509CertDaoImpl();
        String issuer = "C=CN,ST=BJ,L=BJ,O=siot,OU=siot,CN=server.jks";
        String certDestPath = "/Users/liulu/IdeaProjects/x509/src/main/resources/test." + Default_keyType.getFileSuffix();
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        String alias = "test";
//        impl.createCert(issuer, new Date(), new Date("2017/09/27"), certDestPath, serial, keyPassword, alias);
        //impl.changePassword(certDestPath, "123", "123");
        //impl.createCert(issuer, new Date(), new Date("2017/09/27"), certDestPath, serial, keyPassword, alias);
        //未实现
//        impl.certDelayTo(new Date("2017/09/28"), certDestPath, keyPassword);
//        impl.printCert(certDestPath, keyPassword);

//        String serverDomain = "api.binancemock.com";
//        String path = "/Users/liulu/IdeaProjects/x509/src/main/resources/1";
//        String serverAlias = "server";
//        String clientName = "client";
//        String serverFileName = "server";

        String serverDomain = "testmqtt2.stc-seedland.com.cn";
        String serverAlias = "serveralias";
        String clientName = "mqttclient";
        String path = "/Users/liulu/IdeaProjects/x509/src/main/resources/2";
        String serverFileName = "mqttserver_ori";

//        String keyPassword = "123";
        String keyPassword = "@lmggTy6XNZmJwu7";

        String serverKsPath = path+"/"+ serverFileName+"."+Default_keyType.getFileSuffix();
        String serverCertPath = path+"/"+ serverFileName+".cer";

//        createServerCertificate(serverDomain, serverAlias, serverFileName, keyPassword, path);
        createClientCertificate(serverKsPath, serverCertPath, serverDomain, serverAlias, keyPassword, clientName, path);
    }

}

