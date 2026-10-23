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

    @GetMapping("/users")
    public List<Map<String, Object>> users(@RequestParam String name) {
        return jdbc.queryForList("SELECT * FROM users WHERE name = ?", name);
    }

    @GetMapping("/orders/{id}")
    public String order(@PathVariable("id") String id) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM orders WHERE id = ?");
        ps.setString(1, id);
        ResultSet rs = ps.executeQuery();
        return rs.next() ? rs.getString(1) : "";
    }

    @GetMapping("/count")
    public Integer count() {
        return jdbc.queryForObject("SELECT COUNT(*) FROM users", Integer.class);
    }
}
