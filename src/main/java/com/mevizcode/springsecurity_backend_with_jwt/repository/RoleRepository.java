package com.mevizcode.springsecurity_backend_with_jwt.repository;

import com.mevizcode.springsecurity_backend_with_jwt.models.Role;
import com.mevizcode.springsecurity_backend_with_jwt.models.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(UserRole name);
}
