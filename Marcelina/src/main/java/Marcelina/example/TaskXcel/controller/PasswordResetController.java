package Marcelina.example.TaskXcel.controller;


import Marcelina.example.TaskXcel.dto.RequestUserDto;
import Marcelina.example.TaskXcel.dto.ResponseUserDto;
import Marcelina.example.TaskXcel.service.UsersService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;


@Controller
@RequestMapping("/forgot-password")
public class PasswordResetController {

    @Autowired
    private UsersService usersService;

    @GetMapping
    public String showForgotPasswordForm(Model model) {
        model.addAttribute("user", new RequestUserDto());
        return "forgot-password";
    }

    @PostMapping
    public String processForgotPassword(@ModelAttribute("user") RequestUserDto user,
                                        @RequestParam("confirmPassword") String confirmPassword,
                                        Model model) {
        ResponseUserDto existingUser = usersService.findByUsernameAndEmailAndRole(
                user.getUsername(), user.getEmail(), user.getRole());

        if (existingUser == null) {
            model.addAttribute("error", "User not found. Please check your details.");
            return "forgot-password";
        }

        if (user.getPassword() == null || confirmPassword == null ||
                !user.getPassword().equals(confirmPassword)) {
            model.addAttribute("error", "Passwords do not match. Please try again.");
            return "forgot-password";
        }

        usersService.updateUserPassword(existingUser.getId(), user.getPassword());
        model.addAttribute("success", "Your password has been successfully updated.");

        return "redirect:/logIn";
    }



}

