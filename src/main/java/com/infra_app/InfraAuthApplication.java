package com.infra_app;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
public class InfraAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(InfraAuthApplication.class, args);
	}

}
