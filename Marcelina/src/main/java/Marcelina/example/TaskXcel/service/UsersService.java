package Marcelina.example.TaskXcel.service;

import Marcelina.example.TaskXcel.dto.RequestUserDto;
import Marcelina.example.TaskXcel.dto.ResponseTaskDto;
import Marcelina.example.TaskXcel.dto.ResponseUserDto;
import Marcelina.example.TaskXcel.mapper.UserMapper;
import Marcelina.example.TaskXcel.model.Task;
import Marcelina.example.TaskXcel.model.Users;
import Marcelina.example.TaskXcel.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;


@Service
public class UsersService  {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserMapper userMapper;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public void createUser(RequestUserDto requestUserDto) {
        Users user = userMapper.mapToEntity(requestUserDto);
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);
        userRepository.save(user);
    }

    public void deleteUser(Long id){
        userRepository.deleteById(id);
    }

    public List<ResponseUserDto> getAllUsers() {
        List<Users> lista = userRepository.findAll();
        return lista.stream().map(userMapper::mapToResponse).toList();
    }


    public ResponseUserDto findByUsernameAndPasswordAndRole(String username, String password) {
        Users user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("This user does not exist!"));
        if (passwordEncoder.matches(password, user.getPassword())) {
            return ResponseUserDto.builder()
                    .id(user.getId())
                    .username(user.getUsername())
                    .role(user.getRole())
                    .build();
        }
        throw new RuntimeException("Invalid password!");
    }


    public Optional<Users> findByUsername(String username) {
        return  userRepository.findByUsername(username);
    }

    public Optional<Users> findById(Long id) {
        return  userRepository.findById(id);
    }

    public String getUserEmailById(Long userId) {
        return userRepository.findById(userId)
                .map(Users::getEmail)
                .orElse(null);
    }

    public ResponseUserDto findByUsernameAndEmailAndRole(String username, String email, String role) {
        Users user = userRepository.findByUsernameAndEmailAndRole(username, email, role);
        return userMapper.mapToResponse(user);
    }

    public void updateEmail(String username, String newEmail) {
        Users user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.setEmail(newEmail);
        userRepository.save(user);
    }

    public void updateUserPassword(Long userId, String newPassword) {
        Users user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        if (user != null) {
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);
        }
    }



}
