package com.lagou;

public class TestMain {

    public static void main(String[] args) {

        try {
            int i = 9;

            int result = i / 0;

            System.out.println(result);
        } catch (Exception e) {
            e.printStackTrace();

            System.out.println("......");
            System.out.println("\n");

            System.out.println(e.getMessage());
        }


    }
}
