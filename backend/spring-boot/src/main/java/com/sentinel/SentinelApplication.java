package com.sentinel;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SentinelApplication {
    public static void main(String[] args) {
        SpringApplication.run(SentinelApplication.class, args);
        System.out.println("===============================================================");
        System.out.println(" SENTINEL — Universal Authentication Security Platform Started ");
        System.out.println(" Endpoints: POST /api/v1/auth-events | GET /api/v1/alerts      ");
        System.out.println("===============================================================");
    }
}
