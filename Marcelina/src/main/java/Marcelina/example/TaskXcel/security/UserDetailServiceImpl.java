package Marcelina.example.TaskXcel.security;

import Marcelina.example.TaskXcel.model.Users;
import Marcelina.example.TaskXcel.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class UserDetailServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;

//    @Autowired
//    Duhet vetem kur ke me shume se nje konstruktor
    public UserDetailServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users user = userRepository.findByUsername(username)
                .orElseThrow();
        return new UserDetailImpl(user);
    }
}
