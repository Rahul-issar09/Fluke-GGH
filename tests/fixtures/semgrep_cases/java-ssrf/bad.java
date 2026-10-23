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

    @GetMapping("/preview")
    public String preview(@RequestParam String url) {
        return rest.getForObject(url, String.class);  // ruleid: java-ssrf
    }

    @GetMapping("/image")
    public InputStream image(@RequestParam("src") String src) throws IOException {
        return new URL(src).openStream();  // ruleid: java-ssrf
    }
}
