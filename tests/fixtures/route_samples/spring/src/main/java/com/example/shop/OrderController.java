package com.example.shop;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private final OrderRepository orders;

    public OrderController(OrderRepository orders) {
        this.orders = orders;
    }

    @GetMapping("/{id}")
    public Order getOrder(@PathVariable Long id) {
        return orders.findById(id).orElseThrow(); // no owner check
    }

    @PostMapping
    public Order create(@RequestBody Order order) {
        return orders.save(order);
    }

    @RequestMapping(value = "/{id}/cancel", method = {RequestMethod.POST, RequestMethod.PUT})
    public void cancel(@PathVariable Long id) {
        orders.cancel(id);
    }

    @DeleteMapping(path = "/{id}")
    public void delete(@PathVariable Long id) {
        orders.deleteById(id);
    }
}
