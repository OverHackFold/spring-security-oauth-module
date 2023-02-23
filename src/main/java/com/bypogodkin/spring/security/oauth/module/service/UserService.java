package com.bypogodkin.spring.security.oauth.module.service;


import com.bypogodkin.spring.security.oauth.module.domain.User;
import com.bypogodkin.spring.security.oauth.module.domain.enums.Provider;
import com.bypogodkin.spring.security.oauth.module.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepository repo;

    public void processOAuthPostLogin(String username) {
        User existUser = repo.getUserByUsername(username);

        if (existUser == null) {
            User newUser = new User();
            newUser.setUsername(username);
            newUser.setProvider(Provider.GOOGLE);
            newUser.setEnabled(true);

            repo.save(newUser);
        }

    }
}
