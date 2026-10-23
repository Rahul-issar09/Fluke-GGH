package demo;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.sql.*;
import java.util.*;
import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api")
public class Controller {
    private final JdbcTemplate jdbc;
    private final Connection conn;
    private final RestTemplate rest = new RestTemplate();

    Controller(JdbcTemplate jdbc, Connection conn) { this.jdbc = jdbc; this.conn = conn; }

    @GetMapping("/ping")
    public void ping(@RequestParam String host) throws IOException {
        Runtime.getRuntime().exec("ping -c 1 " + host);  // ruleid: java-command-injection
    }

    @PostMapping("/convert")
    public void convert(@RequestBody String file) throws IOException {
        String cmd = "convert " + file + " out.png";
        new ProcessBuilder("sh", "-c", cmd).start();  // ruleid: java-command-injection
    }
}
