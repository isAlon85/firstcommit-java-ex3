package com.company;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Main {

    private static ArrayList<User> users;

    public static void main(String[] args) {
        users = new ArrayList<>();
        try {
            System.out.println("User is registered?: " + register("usuario1@firstcommit.com", "Hola1234"));
            System.out.println("User is registered?: " + register("usuario2@firstcommit.com", "Hola1234"));
            System.out.println("User is registered?: " + register("usuario3@firstcommit.com", "Hola1234"));
            System.out.println("User is registered?: " + register("mailnovalido", "Hola1234"));
            System.out.println("User is registered?: " + register("usuario3@firstcommit.com", "Hola1234"));
        } catch (Exception e) {
            System.out.println("A problem occurs: "+ e.getMessage());
        }

        for (User user : users) {
            System.out.println(user);
        }

        try {
            System.out.println("User is logged?: " + login("usuario1@firstcommit.com", "Hola1234"));
            System.out.println("User is logged?: " + login("usuario1@firstcommit.com", "Hola1267"));
            System.out.println("User is logged?: " + login("usuario8@firstcommit.com", "Hola1234"));
        } catch (Exception e) {
            System.out.println("A problem occurs: "+ e.getMessage());
        }
    }

    public static boolean register(String email, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //Revisamos si el mail es válido
        if (!validateMail(email)) return false;

        //Hasheamos mail
        Argon2 argon2 = Argon2Factory.create(Argon2Types.ARGON2id);
        char[] passChar = password.toCharArray();
        String hashedPassword = argon2.hash(4, 1024 * 1024, 8, passChar);

        User user = new User (email, hashedPassword);

        //Recorremos mails ya utilizados
        for (User value : users) {
            if (user.getEmail().equals(value.getEmail())) {
                return false;
            }
        }

        //Añadimos user si es correcto
        users.add(user);
        return true;
    }

    public static int login (String email, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Argon2 argon2 = Argon2Factory.create(Argon2Types.ARGON2id);
        char[] passChar = password.toCharArray();
        //Recorremos el array para hacer match con el mail
        for (User value : users) {
            if (email.equals(value.getEmail())) {
                //Comprobamos si la pass es correcta
                if (argon2.verify(value.getPassword(),passChar)) {
                    return 1;
                } else return -2;
            }
        }
        return -1;
    }

    public static boolean validateMail(String email) {
        Pattern pattern = Pattern
                .compile("^[_A-Za-z0-9-+]+(\\.[_A-Za-z0-9-]+)*@"
                        + "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$");

        Matcher mather = pattern.matcher(email);
        return mather.find();
    }
}
