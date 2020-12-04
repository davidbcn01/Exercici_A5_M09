import javax.crypto.SecretKey;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        // EXERCICI 1
        KeyPair keys = a5.randomGenerate(1024);
        System.out.println("Privada: "+keys.getPrivate());
        System.out.println("Pública: "+keys.getPublic());

        System.out.println("Introdueix el missatge a xifrar: ");
    String msg = sc.nextLine();
    byte [] msgBytes = msg.getBytes();
        byte[] mensXifrat = a5.encryptData(msgBytes, keys.getPublic());
        System.out.println("Missatge Xifrat");

        byte [] mensDex = a5.decryptData(mensXifrat, keys.getPrivate());
        System.out.println("Missatge Desxifrat");
        String missatgeDesxifrat = new String(mensDex);
        System.out.println("Missatge: "+missatgeDesxifrat);


        System.out.println(" ");


        KeyStore ks = null;

        // EXERCICI 2
        try {
           ks =  a5.loadKeyStore("/home/dam2a/Escriptori/Programación/keystore123.ks","932@agU11");
            System.out.println("Tipus de la KeyStore: "+ ks.getType());
            System.out.println("Mida: "+ ks.size());
            System.out.println("Alies de les claus: "+ks.aliases().nextElement());
            System.out.println("Certificat d'una clau: "+ks.getCertificate("mykey"));
            System.out.println(ks.getCertificate("mykey").getPublicKey().getAlgorithm());

        } catch (Exception e) {
            e.printStackTrace();
        }
       // 2.2
        String contra = "contraseña";
        SecretKey sk = a5.passwordKeyGeneration(contra,128);
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(sk);
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection("password".toCharArray());

        try {
            ks.setEntry("mykeyNEW",secretKeyEntry,protectionParameter);
            FileOutputStream fos = new FileOutputStream("/home/dam2a/Escriptori/Programación/keystore123.ks");
                ks.store(fos, "932@agU11".toCharArray());
        } catch (KeyStoreException | FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println(" ");
        System.out.println("EXERCICI 3");
        System.out.println(" ");

        System.out.println(" ");
        System.out.println("EXERCICI 4");
        System.out.println(" ");


        System.out.println(" ");
        System.out.println("EXERCICI 5");
        System.out.println(" ");
        System.out.println("Introduce un mensaje");
        String algo = sc.nextLine();
        byte [] argo = algo.getBytes();
        byte [] signature = a5.signData(argo, keys.getPrivate());
        String  sign = new String(signature);
        System.out.println(sign);


        System.out.println(" ");
        System.out.println("EXERCICI 6");
        System.out.println(" ");

boolean ValidSign = a5.validateSignature(argo,signature, keys.getPublic());
        System.out.println("És valid?: "+ValidSign);



    }



}
