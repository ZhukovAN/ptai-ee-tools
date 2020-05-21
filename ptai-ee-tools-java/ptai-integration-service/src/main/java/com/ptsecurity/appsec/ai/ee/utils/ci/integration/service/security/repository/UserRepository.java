package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.repository;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain.Role;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain.User;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

public interface UserRepository extends CrudRepository<User, Long> {
    User findByUsername(String username);
}
