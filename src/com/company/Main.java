package com.company;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
        if (!validateMail(email)) return false;

        String hashedPassword = generateStrongPasswordHash(password);

        User user = new User (email, hashedPassword);

        for (User value : users) {
            if (user.getEmail().equals(value.getEmail())) {
                return false;
            }
        }

        users.add(user);
        return true;
    }

    public static int login (String email, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        for (User value : users) {
            if (email.equals(value.getEmail())) {
                if (validatePassword(password,value.getPassword())) {
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

    public static String generateStrongPasswordHash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        int iterations = 1000;
        char[] chars = password.toCharArray();
        byte[] salt = getSalt();

        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64 * 8);

        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return iterations + ":" + toHex(salt) + ":" + toHex(hash);
    }


    private static byte[] getSalt() throws NoSuchAlgorithmException
    {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }


    private static String toHex(byte[] array)
    {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if(paddingLength > 0)
        {
            return String.format("%0"  +paddingLength + "d", 0) + hex;
        }else{
            return hex;
        }
    }

    public static boolean validatePassword(String originalPassword, String storedPassword) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        try {
            String[] parts = storedPassword.split(":");
            int iterations = Integer.parseInt(parts[0]);
            byte[] salt = fromHex(parts[1]);
            byte[] hash = fromHex(parts[2]);

            PBEKeySpec spec = new PBEKeySpec(originalPassword.toCharArray(), salt, iterations, hash.length * 8);

            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

            byte[] testHash = skf.generateSecret(spec).getEncoded();

            int diff = hash.length ^ testHash.length;
            for(int i = 0; i < hash.length && i < testHash.length; i++) {
                diff |= hash[i] ^ testHash[i];
            }

            return diff == 0;

        } catch (NumberFormatException e) {
            System.err.println("NumberFormatException");
            return false;
        }
    }

    private static byte[] fromHex(String hex) {

        byte[] bytes = new byte[hex.length() / 2];
        for(int i = 0; i<bytes.length ;i++) {
            bytes[i] = (byte)Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }

        return bytes;
    }
}
