package demo;


import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

public interface X509Dao {

    /**
     * @param issuer 发布者  C=CN,ST=BJ,L=BJ,O=组织,OU=单位,CN=CCERT
     * @param notBefore 使用日期
     * @param notAfter 到期
     * @param certDestPath 生成证书地址
     * @param serial 证书序列号
     * @param alias 证书别名
     * @throws Exception
     */
    void createCert(String issuer, Date notBefore, Date notAfter, String certDestPath, BigInteger serial,
                    String keyPassword, String alias) throws Exception;

    /** 输出证书信息
     * @param certPath 证书地址
     * @param keyPassword 证书密码
     */
    void printCert(String certPath, String keyPassword) throws Exception;

    /** 返回公钥
     * @param certPath 证书路径
     * @param keyPassword 证书密码
     * @return
     * @throws Exception
     */
    PublicKey getPublicKey(String certPath, String keyPassword) throws Exception;

    /** 返回私钥
     * @param certPath
     * @param keyPassword
     * @return
     * @throws Exception
     */
    PrivateKey getPrivateKey(String certPath, String keyPassword, String alias) throws Exception;

    /**
     * @param endTime 延期时间
     * @param certPath 证书地址
     * @param password 密码
     * @throws Exception 目前未实现，
     */
    void certDelayTo(Date endTime, String certPath, String password) throws Exception;

    /**修改密码
     * @param certPath 证书地址 密码
     * @param oldPwd 原始密码
     * @param newPwd 新密码
     * @throws Exception
     */
    void changePassword(String certPath, String oldPwd, String newPwd) throws Exception;

    /** 删除证书
     * @param certPath 证书地址
     * @param password 密码
     * @param alias 别名
     * @param entry 条目
     * @throws Exception
     */
    void deleteAlias(String certPath, String password, String alias, String entry) throws Exception;

}