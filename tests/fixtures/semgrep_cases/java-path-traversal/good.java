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

    @GetMapping("/download")
    public byte[] download(@RequestParam String name) throws IOException {
        return Files.readAllBytes(Paths.get("/srv/files").resolve(Paths.get(name).getFileName()));
    }

    @GetMapping("/readme")
    public byte[] readme() throws IOException {
        return Files.readAllBytes(Paths.get("/srv/README.md"));
    }
}
