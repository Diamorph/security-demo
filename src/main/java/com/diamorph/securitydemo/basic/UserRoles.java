package com.diamorph.securitydemo.basic;

public enum UserRoles {
    USER("USER"),
    ADMIN("ADMIN");

    private String roleName;

    UserRoles(String roleName) {
        this.roleName = roleName;
    }
}
