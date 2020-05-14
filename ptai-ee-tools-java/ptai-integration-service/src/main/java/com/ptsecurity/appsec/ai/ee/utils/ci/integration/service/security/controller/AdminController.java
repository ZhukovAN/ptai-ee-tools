package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.controller;

import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.User;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.Role;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.UserData;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain.UserRole;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.service.AdminService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @Autowired
    private AdminService adminService;

    protected User convert(com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain.User user) {
        User res = new User();
        res.setId(user.getId());
        res.setName(user.getUsername());
        res.setRoles(new ArrayList<>());
        for (UserRole userRole : user.getRoles()) {
            Role role = new Role();
            role.setId(userRole.getRole().getId());
            role.setName(userRole.getRole().getName());
            res.getRoles().add(role);
        }
        return res;
    }

    /**
     *
     * user signup
     * @param userData
     * @return
     */
    @RequestMapping(value = "/users", method = RequestMethod.POST)
    public ResponseEntity<User> signup(@RequestBody UserData userData) {
        if (null == userData.getRoles() || userData.getRoles().isEmpty())
            userData.setRoles(Arrays.asList("USER"));
        User res = convert(adminService.addUser(userData));
        return new ResponseEntity<User>(res, HttpStatus.CREATED);
    }

    @GetMapping("/users")
    public ResponseEntity<List<User>> users() {
        List<com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain.User> users = adminService.allUsers();
        List<User> res = new ArrayList<>();
        users.forEach(u -> res.add(convert(u)));
        return new ResponseEntity<List<User>>(res, HttpStatus.OK);
    }

    @DeleteMapping("/users")
    public ResponseEntity delete(
            @RequestParam(name = "id", required = false) Long id,
            @RequestParam(name = "name", required = false) String name) {
        if (StringUtils.isNotEmpty(name))
            adminService.deleteUser(name);
        else if (null != id)
            adminService.deleteUser(id);
        else
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("At least name or id must be not empty");
        return ResponseEntity.status(HttpStatus.OK).build();
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