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

    @GetMapping("/status")
    public String status(@RequestParam String id) {
        return rest.getForObject("https://status.example.com/api/{id}", String.class, id);
    }

    @GetMapping("/docs")
    public InputStream docs() throws IOException {
        return new URL("https://docs.example.com/index.json").openStream();
    }
}
