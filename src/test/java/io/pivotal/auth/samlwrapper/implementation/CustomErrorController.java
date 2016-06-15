package io.pivotal.auth.samlwrapper.implementation;

import org.springframework.boot.autoconfigure.web.ErrorController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CustomErrorController implements ErrorController {

    private static final String PATH = "/error";

    @RequestMapping(value = PATH)
    public String error() {
        return (
                "<!DOCTYPE html>" +
                        "<html>" +
                        "<head><title>" + "Error Page" + "</title></head>" +
                        "<body>" +
                        "<h1>" + "Error Page" + "</h1>" +
                        "<p class='error-page'></p>" +
                        "</body>" +
                        "</html>"
        );
    }

    @Override
    public String getErrorPath() {
        return PATH;
    }
}