package CoffeCrypt;

public class Main {
    public static void main(String[] args) {
        Hash hash = new Sha1();
        String dup = hash.encrypt("Hello, World");
        System.out.println(dup);
    }
}
