package com.diamorph.securitydemo.resources;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@RestController
public class TodoResource {

    private Logger logger = LoggerFactory.getLogger(getClass());

    private static final List<Todo> TODO_LIST = List.of(
            new Todo("diamorph", "Learn AWS"),
            new Todo("diamorph", "Get AWS Certified")
    );;

    @GetMapping("/todos")
    public List<Todo> retrieveAllTodos() {
        return TODO_LIST;
    }

    @GetMapping("/users/{username}/todos")
    // PreAuthorize and PostAuthorize prefered way to use, before need to add @EnableMethodSecurity to BasicAuthSecurityConfiguration
//    @PreAuthorize("hasRole('USER') and #username == authentication.name")
//    @PostAuthorize("returnObject.username == 'diamorph'")
//    @RolesAllowed({"ADMIN", "USER"}) // before need to add @EnableMethodSecurity(jsr250Enabled = true) to BasicAuthSecurityConfiguration
//    @Secured({"ROLE_ADMIN", "ROLE_USER"}) // // before need to add @EnableMethodSecurity(securedEnabled = true) to BasicAuthSecurityConfiguration
    public Todo retrieveTodosForSpecificUser(@PathVariable String username) {
        return TODO_LIST.get(0);
    }

    @PostMapping("/users/{username}/todos")
    public void createTodoForSpecificUser(@PathVariable String username, @RequestBody Todo todo) {
        logger.info("Create {} for {}", todo, username);
    }
}

record Todo (String username, String description) {}