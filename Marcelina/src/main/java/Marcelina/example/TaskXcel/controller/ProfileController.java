package Marcelina.example.TaskXcel.controller;


import Marcelina.example.TaskXcel.dto.RequestUserDto;
import Marcelina.example.TaskXcel.dto.ResponseTaskDto;
import Marcelina.example.TaskXcel.dto.ResponseUserDto;
import Marcelina.example.TaskXcel.model.Users;
import Marcelina.example.TaskXcel.service.TaskService;
import Marcelina.example.TaskXcel.service.UsersService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;
import java.util.Optional;

@Controller
@RequestMapping("/profile")
public class ProfileController {

    @Autowired
    private UsersService userService;

    @Autowired
    private TaskService taskService;

    @Autowired
    private PasswordEncoder passwordEncoder;


    @GetMapping
    public String showProfilePage(Model model, HttpSession session) {

        RequestUserDto currentUser = (RequestUserDto) session.getAttribute("currentUser");

        if (currentUser == null) {
            return "redirect:/logIn"; // Redirect to login if user is not in session
        }

        String username = currentUser.getUsername();

        Users user = userService.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        List<ResponseTaskDto> assignedTasks = taskService.getAllTaskByUsername(username);

        model.addAttribute("user", user);
        model.addAttribute("assignedTasks", assignedTasks);
        return "profile";
    }


    // Update email and preferences
    @PostMapping("/update-email")
    public String updateEmail(@RequestParam String newEmail, HttpSession session, Model model) {
        // Retrieve the current user from the session
        RequestUserDto currentUser = (RequestUserDto) session.getAttribute("currentUser");

        if (currentUser == null) {
            return "redirect:/logIn";
        }

        String username = currentUser.getUsername();
        userService.updateEmail(username, newEmail);

        model.addAttribute("success", "Email updated successfully!");
        return "redirect:/profile";
    }

    // Change password
    @PostMapping("/change-password")
    public String changePassword(@RequestParam String currentPassword,
                                 @RequestParam String newPassword,
                                 @RequestParam String confirmPassword,
                                 HttpSession session,
                                 Model model) {
        // Retrieve the current user from the session
        RequestUserDto currentUser = (RequestUserDto) session.getAttribute("currentUser");

        if (currentUser == null) {
            return "redirect:/logIn"; // Redirect to login if the user is not in session
        }

        String username = currentUser.getUsername();
        Users user = userService.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Verify the current password
        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            model.addAttribute("error", "Current password is incorrect.");
            return "profile"; // Stay on profile page to show error
        }

        // Check if new password and confirm password match
        if (!newPassword.equals(confirmPassword)) {
            model.addAttribute("error", "New password and confirm password do not match.");
            return "profile"; // Stay on profile page to show error
        }

        // Update the password
        userService.updateUserPassword(user.getId(), newPassword);

        model.addAttribute("success", "Password updated successfully!");
        return "redirect:/profile";
    }

}
