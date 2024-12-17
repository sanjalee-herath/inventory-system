package com.swift.inventory_system.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("product")
public class ProductController {
    @GetMapping
    @PreAuthorize("hasRole('ROLE_admin')")
    public String ListAllProducts() {
        return "Products";
    }
}
