package com.mevizcode.springsecurity_backend_with_jwt.models;

import lombok.*;
import javax.persistence.*;


@Entity
@Table(name = "roles")
@NoArgsConstructor
@Getter
@Setter
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private UserRole name;

}
