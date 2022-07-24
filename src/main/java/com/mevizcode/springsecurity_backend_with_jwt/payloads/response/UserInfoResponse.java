package com.mevizcode.springsecurity_backend_with_jwt.payloads.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@AllArgsConstructor
@Getter
@Setter
public class UserInfoResponse {
    private Integer id;
    private String username;
    private String email;
    private List<String> roles;


}
