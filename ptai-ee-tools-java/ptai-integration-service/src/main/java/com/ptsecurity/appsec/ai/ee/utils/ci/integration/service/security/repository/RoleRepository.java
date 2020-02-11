package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.repository;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain.Role;
import org.springframework.data.repository.CrudRepository;

public interface RoleRepository extends CrudRepository<Role, Long> {
    Role findByName(String name);
}
