package Marcelina.example.TaskXcel.repository;


import Marcelina.example.TaskXcel.model.Users;
import Marcelina.example.TaskXcel.model.Task;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<Users, Long> {
    Optional<Users> findByUsernameAndPasswordAndRole(String username, String password, String role);

    Optional<Users>findByUsernameAndRole(String username, String role);

    Optional<Users> findByUsername (String username);

    Users findByUsernameAndEmailAndRole(String username, String email, String role);


}
