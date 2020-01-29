package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.service;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.domain.User;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class PtaiUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(userName);
        if(user == null)
            throw new UsernameNotFoundException("UserName " + userName + " not found");
        return new PtaiUserDetails(user);
    }
}
