package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain;

import lombok.*;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@Table(name = "user_role")
@Getter @Setter
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserRole implements Serializable {
    @Id
    @ManyToOne
    @JoinColumn(name = "user")
    private User user;

    @Id
    @ManyToOne
    @JoinColumn(name = "role")
    private Role role;
}
