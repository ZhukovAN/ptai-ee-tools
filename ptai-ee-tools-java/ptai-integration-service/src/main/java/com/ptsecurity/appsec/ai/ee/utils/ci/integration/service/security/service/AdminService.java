package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.service;

import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.UserData;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.exceptions.ConflictException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.exceptions.EntityExistsException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.exceptions.EntityNotFoundException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain.Role;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain.User;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain.UserRole;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.repository.RoleRepository;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.repository.UserRepository;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.passay.PasswordGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.PostConstruct;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Service
@Transactional
@Slf4j
public class AdminService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Value("${ptai-authorization-server.admin-name}")
    private String adminName;

    // Set up a default admin with two roles USER and ADMIN and randomly generated password
    @PostConstruct
    public void setupDefaultUser() {
        User admin = userRepository.findByUsername(adminName);
        if (null != admin) return;

        String password = generateRandomString();
        log.info("Inital {} password is: {}", adminName, password);
        try {
            FileUtils.write(new File("admin"), password, StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.error("Failed to save initial admin password to file", e);
        }
        password = passwordEncoder.encode(password);

        Role adminRole = roleRepository.findByName("ADMIN");
        Role userRole = roleRepository.findByName("USER");
        admin = new User(
                adminName, password,
                Arrays.asList(adminRole, userRole));
        userRepository.save(admin);
    }

    public User addUser(UserData userData) {
        if (null != userRepository.findByUsername(userData.getName()))
            throw new EntityExistsException("User " + userData.getName() + " already exists");
        User user = User.builder()
                .username(userData.getName())
                .password(userData.getPassword()).build();
        List<UserRole> userRoles = new ArrayList<>();

        for (String role : userData.getRoles())
            userRoles.add(new UserRole(user, roleRepository.findByName(role)));
        user.setRoles(userRoles);
        user.setPassword(passwordEncoder.encode(userData.getPassword()));
        return userRepository.save(user);
    }

    public List<User> allUsers() {
        List<User> res = new ArrayList<>();
        userRepository.findAll().forEach(res::add);
        return res;
    }

    public void deleteUser(@NonNull Long id) {
        Optional<User> user = userRepository.findById(id);
        if (user.isPresent()) {
            log.debug("User #{} will be deleted", id);

            // Check if this is a last admin user
            Role adminRole = roleRepository.findByName("ADMIN");
            // Get this user roles
            boolean isAdmin =  user.get().getRoles().stream()
                    .anyMatch(r -> adminRole.getId() == r.getRole().getId());
            if (isAdmin) {
                log.debug("User is administrator, need to check if he isn't the last one");
                if (1 >= adminRole.getUsers().size())
                    throw new ConflictException("Last administrative account couldn't be deleted");
            }
            userRepository.deleteById(id);
        } else
            throw new EntityNotFoundException("User " + id.toString() + " not found");
    }

    public void deleteUser(@NonNull String name) {
        User user = userRepository.findByUsername(name);
        if (null != user)
            this.deleteUser(user.getId());
        else
            throw new EntityNotFoundException("User " + name + " not found");
    }

    public static String generateRandomString() {
        return new PasswordGenerator()
                .generatePassword(
                        32,
                        new CharacterRule(EnglishCharacterData.Alphabetical, 24),
                        new CharacterRule(EnglishCharacterData.Digit, 32 - 24));
    }

    public String encodePassword(String password) {
        return passwordEncoder.encode(null == password ? "" : password);
    }
}