package com.nfky.datacenter.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Created by lyr on 2017/6/8.
 */
@SpringBootApplication
public class DataCenterApiApp {

    public final static String API_VERSION = "/api/v1.0";

    public static void main(String[] args) {
        SpringApplication.run(DataCenterApiApp.class, args);
    }
}
