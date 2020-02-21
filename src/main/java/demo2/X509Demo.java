package demo2;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.*;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


public class X509Demo {


    private static final String NEW_LINE = System.getProperty("line.separator");

    /**
     * 证书摘要及签名算法组
     */
    public static final String MSG_DIGEST_SIGN_ALGO = "SHA256withRSA";

    /**
     * 在将java生成的证书导出到文件的时候，需要将下面两行信息对应的添加到证书内容的头部后尾部
     */
    private static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERTIFICATE = "-----END CERTIFICATE-----";

    /**
     * 在将java生成的私钥导出到文件的时候，需要将下面两行信息对应的添加到私钥内容的头部后尾部
     */
    private static final String BEGIN_RSA_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    private static final String END_RSA_PRIVATE_KEY = "-----END PRIVATE KEY-----";

    private static final String X509 = "x509";
    private static final String RSA_ALGORITHM = "RSA";
    private static final String CERTIFICATE = "crt";
    private static final String PRIVATE_KEY = "key";
    private static final String PUBLIC_KEY = "pubkey";

    public static void main(String[] args) {

    }

    /**
     * 创建私钥和公钥的数据，以一个map的形式返回。
     *
     * @param keySize 私钥的长度
     * @param keyAlgo 创建私钥的算法，例如RSA，DSA等
     * @return map 私钥和公钥对信息
     */
    public static Map<String, String> createKeys(int keySize, String keyAlgo){
        BASE64Encoder base64Encoder = new BASE64Encoder();
        //为RSA算法创建一个KeyPairGenerator对象
        KeyPairGenerator kpg;
        try{
            kpg = KeyPairGenerator.getInstance(keyAlgo);
        }catch(NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("No such algorithm-->[" + keyAlgo + "]");
        }

        //初始化KeyPairGenerator对象,密钥长度
        kpg.initialize(keySize);
        //生成密匙对
        KeyPair keyPair = kpg.generateKeyPair();
        //得到公钥
        Key publicKey = keyPair.getPublic();
        String publicKeyStr = base64Encoder.encode(publicKey.getEncoded());
        //得到私钥
        Key privateKey = keyPair.getPrivate();
        String privateKeyStr = base64Encoder.encode(privateKey.getEncoded());
        Map<String, String> keyPairMap = new HashMap<String, String>();
        keyPairMap.put(PUBLIC_KEY, publicKeyStr);
        keyPairMap.put(PRIVATE_KEY, privateKeyStr);
        return keyPairMap;
    }

    /**
     * 创建根证书， 并保存根证书到指定路径的文件中， crt和key分开存储文件。
     * 创建SSL根证书的逻辑，很重要，此函数调用频次不高，创建根证书，也就是自签名证书。
     *
     * @param algorithm      私钥安全算法，e.g. RSA
     * @param keySize        私钥长度，越长越安全，RSA要求不能小于512， e.g. 2048
     * @param digestSignAlgo 信息摘要以及签名算法 e.g. SHA256withRSA
     * @param subj           证书所有者信息描述，e.g. CN=iotp,OU=tkcloud,O=taikang,L=wuhan,S=hubei,C=CN
     * @param validDays      证书有效期天数，e.g. 3650即10年
     * @param rootCACrtPath  根证书所要存入的全路径，e.g. /opt/certs/iot/rootCA.crt
     * @param rootCAKeyPath  根证书对应秘钥key所要存入的全路径，e.g. /opt/certs/iot/rootCA.key
     * @return 私钥和证书对的map对象
     * @throws IOException
     */
    public static HashMap<String, Object> createRootCA(String algorithm, int keySize, String digestSignAlgo,
                                                                    String subj, long validDays, String rootCACrtPath, String rootCAKeyPath) {

        //参数分别为 公钥算法 签名算法 providerName（因为不知道确切的 只好使用null 既使用默认的provider）
        CertAndKeyGen cak = null;
        try {
            cak = new CertAndKeyGen(algorithm, digestSignAlgo, null);
            //生成一对key 参数为key的长度 对于rsa不能小于512
            cak.generate(keySize);
            cak.setRandom(new SecureRandom());

            //证书拥有者subject的描述name
            X500Name subject = new X500Name(subj);

            //给证书配置扩展信息
            PublicKey publicKey = cak.getPublicKey();
            PrivateKey privateKey = cak.getPrivateKey();
            CertificateExtensions certExts = new CertificateExtensions();
            certExts.set("SubjectKeyIdentifier", new SubjectKeyIdentifierExtension((new KeyIdentifier(publicKey)).getIdentifier()));
            certExts.set("AuthorityKeyIdentifier", new AuthorityKeyIdentifierExtension(new KeyIdentifier(publicKey), null, null));
            certExts.set("BasicConstraints", new BasicConstraintsExtension(false, true, 0));

            //配置证书的有效期,并生成根证书（自签名证书）
            X509Certificate certificate = cak.getSelfCertificate(subject, new Date(), validDays * 24L * 60L * 60L, certExts);

            HashMap<String, Object> rootCA = new HashMap<>();
            rootCA.put(PRIVATE_KEY, privateKey);
            rootCA.put(CERTIFICATE, certificate);
            
            exportCrt(certificate, rootCACrtPath);
            exportKey(privateKey, rootCAKeyPath);

//            String rootPath = "E:\\2018\\IOT\\MQTT\\javassl\\jsseRoot.keystore";
//            String rootPfxPath = "E:\\2018\\IOT\\MQTT\\javassl\\jsseRoot.pfx";
//            /**
//             * 通过下面的指令，可以将keystore里面的内容转为DER格式的证书jsseRoot.cer
//             * keytool -export -alias rootCA -storepass abcdef -file jsseRoot.cer -keystore jsseRoot.keystore
//             *
//             * 通过下面的指令，可以将DER格式的证书转化为OPENSSL默认支持的PEM证书：
//             * openssl x509 -inform der -in jsseRoot.cer -out jsseRoot.pem
//             */
//            saveJks("rootCA", privateKey, "abcdef", new Certificate[]{certificate}, rootPath);
//
//            /**
//             * 通过下面的指令，可以获取证书的私钥
//             * openssl pkcs12 -in jsseRoot.pfx -nocerts -nodes -out jsseRoot.key
//             */
//            savePfx("rootCA", privateKey, "abcdef", new Certificate[]{certificate}, rootPfxPath);
            return rootCA;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 将JAVA创建的证书内容导出到文件， 基于BASE64转码了。
     *
     * @param devCrt  设备证书对象
     * @param crtPath 设备证书存储路径
     */
    public static void exportCrt(Certificate devCrt, String crtPath) {
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

    /**
     * 创建X509的证书， 由ca证书完成签名。
     * <p>
     * subject,issuer都遵循X500Principle规范，
     * 即： X500Principal由可分辨名称表示，例如“CN = Duke，OU = JavaSoft，O = Sun Microsystems，C = US”。
     *
     * @param ca        根证书对象
     * @param caKey     CA证书对应的私钥对象
     * @param publicKey 待签发证书的公钥对象
     * @param subj      证书拥有者的主题信息，签发者和主题拥有者名称都转写X500Principle规范，格式：CN=country,ST=state,L=Locality,OU=OrganizationUnit,O=Organization
     * @param validDays 证书有效期天数
     * @param sginAlgo  证书签名算法， e.g. SHA256withRSA
     * @return cert 新创建得到的X509证书
     */
    public static X509Certificate createUserCert(X509Certificate ca, PrivateKey caKey, PublicKey publicKey, String subj, long validDays, String sginAlgo) {

        //获取ca证书
        X509Certificate caCert = ca;

        X509CertInfo x509CertInfo = new X509CertInfo();

        try {
            //设置证书的版本号
            x509CertInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));

            //设置证书的序列号，基于当前时间计算
            x509CertInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber((int) (System.currentTimeMillis() / 1000L)));

            /**
             * 下面这个设置算法ID的代码，是错误的，会导致证书验证失败，但是报错不是很明确。 若将生成的证书存为keystore，让后keytool转换
             * 会出现异常。
             * AlgorithmId algorithmId = new AlgorithmId(AlgorithmId.SHA256_oid);
             */
            AlgorithmId algorithmId = AlgorithmId.get(sginAlgo);
            x509CertInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algorithmId));

            //设置证书的签发者信息
            X500Name issuer = new X500Name(caCert.getIssuerX500Principal().toString());
            x509CertInfo.set(X509CertInfo.ISSUER, issuer);

            //设置证书的拥有者信息
            X500Name subject = new X500Name(subj);
            x509CertInfo.set(X509CertInfo.SUBJECT, subject);

            //设置证书的公钥
            x509CertInfo.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));

            //设置证书有效期
            Date beginDate = new Date();
            Date endDate = new Date(beginDate.getTime() + validDays * 24 * 60 * 60 * 1000L);
            CertificateValidity cv = new CertificateValidity(beginDate, endDate);
            x509CertInfo.set(X509CertInfo.VALIDITY, cv);

            CertificateExtensions exts = new CertificateExtensions();

            /*
             * 以上是证书的基本信息 如果要添加用户扩展信息 则比较麻烦 首先要确定version必须是v3否则不行 然后按照以下步骤
             *
             */
            exts.set(SubjectKeyIdentifierExtension.NAME, new SubjectKeyIdentifierExtension((new KeyIdentifier(publicKey)).getIdentifier()));
            exts.set(AuthorityKeyIdentifierExtension.NAME, new AuthorityKeyIdentifierExtension(new KeyIdentifier(ca.getPublicKey()), null, null));
            exts.set(BasicConstraintsExtension.NAME, new BasicConstraintsExtension(false,false,-1));
            x509CertInfo.set(CertificateExtensions.NAME, exts);

        } catch (CertificateException cee) {
            cee.printStackTrace();
        } catch (IOException eio) {
            eio.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        // 获取CA私钥
        PrivateKey caPrivateKey = caKey;
        //用CA的私钥给当前证书进行签名，获取最终的下游证书（证书链的下一节点）
        X509CertImpl cert = new X509CertImpl(x509CertInfo);
        try {
            cert.sign(caPrivateKey, sginAlgo);
        } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e3) {
            e3.printStackTrace();
        }
        return cert;
    }

    public static PublicKey getPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        BASE64Decoder base64 = new BASE64Decoder();

        //通过PKCS#8编码的Key指令获得私钥对象
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(base64.decodeBuffer(publicKey));
        PublicKey key = keyFactory.generatePublic(pkcs8KeySpec);
        return key;
    }


    /**
     * 得到私钥, 记得这个文件是类似PEM格式的问题，需要将文件头部的----BEGIN和尾部的----END信息去掉
     *
     * @param privateKey 密钥字符串（经过base64编码）
     * @throws Exception
     */
    public static RSAPrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        BASE64Decoder base64 = new BASE64Decoder();

        //通过PKCS#8编码的Key指令获得私钥对象
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        if(privateKey.startsWith(BEGIN_RSA_PRIVATE_KEY)) {
            int bidx = BEGIN_RSA_PRIVATE_KEY.length();
            privateKey = privateKey.substring(bidx);
        }
        if (privateKey.endsWith(END_RSA_PRIVATE_KEY)) {
            int eidx = privateKey.indexOf(END_RSA_PRIVATE_KEY);
            privateKey = privateKey.substring(0, eidx);
        }
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(base64.decodeBuffer(privateKey));
        RSAPrivateKey key = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
        return key;
    }

    /**
     * 利用开源的工具类BC解析私钥，例如openssl私钥文件格式为pem，需要去除页眉页脚后才能被java读取
     *
     * @param file 私钥文件
     * @return 私钥对象
     */
    public static PrivateKey getPrivateKey(File file) {
        if (file == null) {
            return null;
        }
        PrivateKey privKey = null;
        PemReader pemReader = null;
        try {
            pemReader = new PemReader(new FileReader(file));
            PemObject pemObject = pemReader.readPemObject();
            byte[] pemContent = pemObject.getContent();
            //支持从PKCS#1或PKCS#8 格式的私钥文件中提取私钥, PKCS#1的私钥，主要是openssl默认生成的编码格式
            if (pemObject.getType().endsWith("RSA PRIVATE KEY")) {
                /*
                 * 取得私钥  for PKCS#1
                 * openssl genrsa 默认生成的私钥就是PKCS1的编码
                 */
                org.bouncycastle.asn1.pkcs.RSAPrivateKey asn1PrivateKey = org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(pemContent);
                RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(asn1PrivateKey.getModulus(), asn1PrivateKey.getPrivateExponent());
                KeyFactory keyFactory= KeyFactory.getInstance(RSA_ALGORITHM);
                privKey= keyFactory.generatePrivate(rsaPrivateKeySpec);
            } else if (pemObject.getType().endsWith("PRIVATE KEY")) {
                /*
                 * java创建的私钥，默认是PKCS#8格式
                 *
                 * 通过openssl pkcs8 -topk8转换为pkcs8，例如（-nocrypt不做额外加密操作）：
                 * openssl pkcs8 -topk8 -in pri.key -out pri8.key -nocrypt
                 *
                 * 取得私钥 for PKCS#8
                 */
                PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(pemContent);
                KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM);
                privKey = kf.generatePrivate(privKeySpec);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }  finally {
            try {
                if (pemReader != null) {
                    pemReader.close();
                }
            } catch (IOException e) {
            }
        }
        return privKey;
    }


    /**
     * 从经过base64转化后的证书文件中构建证书对象,是一个标准的X509证书，
     *
     * 且非常重要的是，文件头部含有-----BEGIN CERTIFICATE-----
     * 文件的尾部含有 -----END CERTIFICATE-----
     * 若没有上述头和尾部，证书验证的时候会报certificate_unknown。
     *
     * @param crtFile 经过base64处理的证书文件
     * @return X509的证书
     */
    public static X509Certificate getCertficate(File crtFile) {
        //这个客户端证书，是用来发送给服务端的，准备做双向验证用的。
        CertificateFactory cf;
        X509Certificate cert = null;
        FileInputStream crtIn = null;
        try {
            cf = CertificateFactory.getInstance(X509);
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

    private static void demoGenFull(String basePath, String devName, String emqHost) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        String subjCA = "CN=IOTPlatform,OU=TanKang,O=TKCloud,L=Wuhan,S=Hubei,C=CN";
        String rootCACrtPath = basePath + "sccCA0.crt";
        String rootCAKeyPath = basePath + "sccCA0.key";

        String subjDev = "OU=TanKang,O=TKCloud,L=Wuhan,ST=Hubei,C=CN,CN=IOTDevice" + devName;
        String devCrtPath = basePath + "sccDev" + devName + ".crt";
        String devKeyPath = basePath + "sccDev" + devName + ".key";

        String subjEmq = "OU=TanKang,O=TKCloud,L=Wuhan,ST=Hubei,C=CN,CN=" + emqHost;
        String emqCommName = emqHost.replace(".", "-");
        String emqCrtPath = basePath + "sccEmq" + emqCommName + ".crt";
        String emqKeyPath = basePath + "sccEmq" + emqCommName + ".key";

        /**
         * 创建根证书，即自签名证书
         */
        HashMap<String, Object> rootCA = createRootCA("RSA",2048, MSG_DIGEST_SIGN_ALGO,  subjCA, 3650, "", "");
        X509Certificate caCrt = (X509Certificate) rootCA.get(CERTIFICATE);
        PrivateKey caKey = (PrivateKey)rootCA.get(PRIVATE_KEY);
        exportCrt(caCrt, rootCACrtPath);
        exportKey(caKey, rootCAKeyPath);

        /**
         * 创建公钥和私钥对，然后基于自签名证书签发设备证书，即客户端证书
         */
        Map<String, String> keyDev = createKeys(2048, RSA_ALGORITHM);
        PublicKey devPubKey = getPublicKey(keyDev.get(PUBLIC_KEY));
        PrivateKey devPriKey = getPrivateKey(keyDev.get(PRIVATE_KEY));
        X509Certificate devCrt = createUserCert(caCrt, caKey, devPubKey, subjDev, 3650, MSG_DIGEST_SIGN_ALGO);
        exportCrt(devCrt, devCrtPath);
        exportKey(devPriKey, devKeyPath);

        /**
         * 创建公钥和私钥对，然后基于自签名证书签发EMQ证书,即服务端证书。
         */
        Map<String, String> keyEmq = createKeys(2048, RSA_ALGORITHM);
        PublicKey emqPubKey = getPublicKey(keyEmq.get(PUBLIC_KEY));
        PrivateKey emqPriKey = getPrivateKey(keyEmq.get(PRIVATE_KEY));
        X509Certificate emqCrt = createUserCert(caCrt, caKey, emqPubKey, subjEmq, 3650, MSG_DIGEST_SIGN_ALGO);
        exportCrt(emqCrt, emqCrtPath);
        exportKey(emqPriKey, emqKeyPath);
    }

    private static void demoGenUserCertWithExistedCA(String basePath, String devName, String emqHost) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        String rootCACrtPath = basePath + "sccCA0.crt";
        String rootCAKeyPath = basePath + "sccCA0.key";

        String subjDev = "OU=TanKang,O=TKCloud,L=Wuhan,ST=Hubei,C=CN,CN=IOTDevice" + devName;
        String devCrtPath = basePath + "sccDev" + devName + ".crt";
        String devKeyPath = basePath + "sccDev" + devName + ".key";

        String subjEmq = "OU=TanKang,O=TKCloud,L=Wuhan,ST=Hubei,C=CN,CN=" + emqHost;
        String emqCommName = emqHost.replace(".", "-");
        String emqCrtPath = basePath + "sccEmq" + emqCommName + ".crt";
        String emqKeyPath = basePath + "sccEmq" + emqCommName + ".key";

        /**
         * 从指定的文件加载构建根证书以及对应的私钥
         */
        X509Certificate caCrt = getCertficate(new File(rootCACrtPath));
        PrivateKey caKey = getPrivateKey(new File(rootCAKeyPath));

        /**
         * 创建公钥和私钥对，然后基于自签名证书签发设备证书，即客户端证书
         */
        Map<String, String> keyDev = createKeys(2048, RSA_ALGORITHM);
        PublicKey devPubKey = getPublicKey(keyDev.get(PUBLIC_KEY));
        PrivateKey devPriKey = getPrivateKey(keyDev.get(PRIVATE_KEY));
        X509Certificate devCrt = createUserCert(caCrt, caKey, devPubKey, subjDev, 3650, MSG_DIGEST_SIGN_ALGO);
        exportCrt(devCrt, devCrtPath);
        exportKey(devPriKey, devKeyPath);

        /**
         * 创建公钥和私钥对，然后基于自签名证书签发EMQ证书,即服务端证书。
         */
        Map<String, String> keyEmq = createKeys(2048, RSA_ALGORITHM);
        PublicKey emqPubKey = getPublicKey(keyEmq.get(PUBLIC_KEY));
        PrivateKey emqPriKey = getPrivateKey(keyEmq.get(PRIVATE_KEY));
        X509Certificate emqCrt = createUserCert(caCrt, caKey, emqPubKey, subjEmq, 3650, MSG_DIGEST_SIGN_ALGO);
        exportCrt(emqCrt, emqCrtPath);
        exportKey(emqPriKey, emqKeyPath);
    }
}
