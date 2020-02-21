package demo;

public enum  KeyStoreType {
    PKCS12("PKCS12", "p12"), JKS("JKS", "jks"), BKS("BKS", "bks");
    private String value;
    private String fileSuffix;

    public String getValue() {
        return value;
    }

    public String getFileSuffix() {
        return fileSuffix;
    }

    KeyStoreType(String type, String fileSuffix) {
        this.value = type;
        this.fileSuffix = fileSuffix;
    }
}
