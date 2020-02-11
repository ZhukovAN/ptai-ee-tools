package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.List;

@Entity
@Table(name="role")
@Data
@NoArgsConstructor
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    @OneToMany(mappedBy = "role", fetch = FetchType.LAZY, cascade=CascadeType.ALL)
    private List<UserRole> users;

    public Role(String name) {
        this.name = name;
    }
}
