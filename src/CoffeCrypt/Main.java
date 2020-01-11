package CoffeCrypt;

public class Main {
    public static void main(String[] args) {
        Hash hash = new Sha1();
        String dup = hash.encrypt("dupa blada siki swietej weroniki huhu hihi haha klocek kupa gowno dupa");
        System.out.println(dup);
    }
}
