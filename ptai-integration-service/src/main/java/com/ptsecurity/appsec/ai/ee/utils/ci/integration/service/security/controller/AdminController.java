package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.controller;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain.Role;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain.User;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.service.AdminService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @Autowired
    private AdminService adminService;

    /**
     *
     * user signup
     * @param user
     * @return
     */
    @RequestMapping(value = "/signup", method = RequestMethod.POST)
    public ResponseEntity<User> signup(@RequestBody User user) {
        User res = adminService.addUser(user, new String[] {"USER"});
        return new ResponseEntity<User>(res, HttpStatus.CREATED);
    }

    @GetMapping("/encode")
    public ResponseEntity<String> encode(@RequestParam(name = "password") String password) {
        return new ResponseEntity<String>(adminService.encodePassword(password), HttpStatus.OK);
    }

    @GetMapping("/random")
    public ResponseEntity<String> random() {
        return new ResponseEntity<String>(adminService.generateRandomString(), HttpStatus.OK);
    }
}