import java.util.Base64;
public class Sample {
    private static byte [] getPrivateKey1() {
        final byte [] pkey = Base64.getMimeDecoder().decode(
            "MIIBOgIBAAJBAL1/hJjtuMbjbVXo6wYT1SxiROOvwgffVSvOAk5aN2d4wYTC25k3"+
            "sklfpdwxvkjh4iGB6/qC+0RbmiLwaXaQT0ECAwEAAQJAeAlQyza6t3HVDnhud/kU"+
            "LftJvBjXhfkYkJj8qPlI40dn/Tnwe6mywfly6hOvAn4TRBsnB/Eln6hJLmCrDvZv"+
            "yQIhAPf7Uma4/Aqgoz3SfPyz9TaQXyD5JSC3ej7cOH7b3hgTAiEAw6AYhc/UKh8i"+
            "IAPYGK15ImVmXAlxmhFD6xCWx9bcTdsCIQDiqOayWZaWKCnNEh2H5PzW+LLasp9K"+
            "/ilQV32UBmdD3QIgbafQFzHoO7Q37Lo655pVzHIKbozcoQAMkjc6TcqiswECIBvX"+
            "LFj5jkNs4iSqphZo8eISUdol/9Zo/dkrHC41kbYJ");
        return pkey;
    }
    private static byte [] getPrivateKey8() {
        final String text =
            "MIIBvTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIT0gWHcAV1rACAggA\n"+
            "MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBaZ0qE6fJsz9rDPoa2esruBIIB\n"+
            "YF9QvKgDLA15MgXR8P73DRdrDJzEEoYe7bDtk+vnTzy6DNVwSfkgQLNLpKfnjPO3\n"+
            "b1szG5md06Fai6Tuuc9kKDhaCWfGgw/xAeb4OEjWupyCUvmyWYBNqCC+DDQZb7cc\n"+
            "ka4cuIRV7Ty0I/3AdGCZ/g4mDBozjtfLkLOvWzRuKXQYvGlPYd0HUWupKn2Sgduy\n"+
            "rwKt43zq0j+t9UXMMFVYv7RZOzZruVcUkBKHoYDkgOl9OQ5tGE+atfhLZUVUKj4Q\n"+
            "7F+o6mlTy0JHxv94oUadDXJCyzivdes2RxabPDJ+1gEfNW8ZRZtselC+Pdy+KBIt\n"+
            "Ln3f3FEWXpWbNPRzhElOUUaNgRNOQrmxoE09QxWLt8L3soArRfWe732Nw7N9izpU\n"+
            "uKmL72bzbpetDQu/sn49CEnWcFGCZQ9inSiEogF0e2ncxnKfthRKzpT3K5JGiqcM\n"+
            "mbcMoz5WjLks//PgWcZ/l2o=\n";
        final byte [] pkey = Base64.getMimeDecoder().decode(text);
        return pkey;
    }
    public static byte[] get(boolean encryption){
        if (encryption) {
            return Sample.getPrivateKey8();
        } else {
            return Sample.getPrivateKey1();
        }
    }
}
/* javac Sample.java && javap -c -l -p -v -s Sample.class */
