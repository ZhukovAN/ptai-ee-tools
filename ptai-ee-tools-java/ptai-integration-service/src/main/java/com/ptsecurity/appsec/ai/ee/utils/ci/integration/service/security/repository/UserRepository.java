package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.repository;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain.User;
import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<User, Long> {
    User findByUsername(String username);
}
