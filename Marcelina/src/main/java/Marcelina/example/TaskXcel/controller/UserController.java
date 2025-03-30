package Marcelina.example.TaskXcel.controller;

import Marcelina.example.TaskXcel.dto.RequestUserDto;
import Marcelina.example.TaskXcel.dto.ResponseUserDto;
import Marcelina.example.TaskXcel.service.UsersService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;

@Controller
@RequestMapping("/users")
public class UserController {

    @Autowired
    private   UsersService usersService;

//    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping
    public String listUsers(Model model) {
        List<ResponseUserDto> users = usersService.getAllUsers();
        model.addAttribute("users", users);
        return "user-list";
    }


    @GetMapping("/create")
    public String showRegistrationForm(Model model) {
        if (!model.containsAttribute("user")) {
            model.addAttribute("user", new RequestUserDto());
        }
        return "user-registration";
    }


    @PostMapping("/create")
    public String createUser(@Valid @ModelAttribute("user") RequestUserDto user, BindingResult result,Model model) {
        if (result.hasErrors()) {
            model.addAttribute("user", user);
            return "user-registration";
        }
        usersService.createUser(user);
        return "redirect:/logIn";
    }


    @PostMapping("/delete/{id}")
    public String deleteUser(@PathVariable Long id) {
        usersService.deleteUser(id);
        return "redirect:/users";
    }

    @GetMapping("/check")
    @ResponseBody
    public ResponseEntity<?> checkUserExists(@RequestParam String username) {
        boolean exists = usersService.findByUsername(username).isPresent();
        return ResponseEntity.ok(Collections.singletonMap("exists", exists));
    }


}
