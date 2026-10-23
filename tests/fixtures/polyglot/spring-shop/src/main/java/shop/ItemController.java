package shop;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

// A small Spring controller with planted weaknesses (test fixture, never deploy).
@RestController
@RequestMapping("/api")
public class ItemController {
    private final JdbcTemplate jdbc;

    ItemController(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @GetMapping("/items")
    public List<Map<String, Object>> items(@RequestParam String q) {
        return jdbc.queryForList("SELECT * FROM items WHERE title LIKE '%" + q + "%'");
    }

    @PostMapping("/reports/{name}")
    public void report(@PathVariable String name) throws IOException {
        Runtime.getRuntime().exec("generate-report " + name);
    }
}
