package Marcelina.example.TaskXcel.controller;

import Marcelina.example.TaskXcel.dto.RequestUserDto;
import Marcelina.example.TaskXcel.dto.ResponseUserDto;
import Marcelina.example.TaskXcel.service.UsersService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/logIn")
public class LoginController {

    @Autowired
    private  UsersService usersService;

    @Autowired
    private AuthenticationManager authenticationManager;

//    @PreAuthorize("hasAnyRole('EMPLOYEE', 'MANAGER')")
    @GetMapping
    public String showLoginForm(Model model) {
        model.addAttribute("user", new RequestUserDto());
        return "LoginPage";
    }


    @PostMapping
    public String login(@ModelAttribute("user") RequestUserDto user,
                        HttpSession session,
                        RedirectAttributes redirectAttributes) {
        ResponseUserDto authenticatedUser = usersService.findByUsernameAndPasswordAndRole(user.getUsername(), user.getPassword());

        if (authenticatedUser != null) {
            user.setRole(authenticatedUser.getRole());
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUsername(),
                            user.getPassword()));
            SecurityContext securityContext = SecurityContextHolder.getContext();
            securityContext.setAuthentication(authentication);
            session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
            session.setAttribute("currentUser", user);
            session.setAttribute("employeeId", authenticatedUser.getId());
            switch (authenticatedUser.getRole()) {
                case "ROLE_ADMIN":
                    return "redirect:/users";
                case "ROLE_MANAGER":
                    return "redirect:/dashboard";
                case "ROLE_EMPLOYEE":
                    return "redirect:/tasks";
                default:
                    redirectAttributes.addFlashAttribute("error", "Invalid role");
                    return "redirect:/error/404";
            }
        } else {
            redirectAttributes.addFlashAttribute("error", "Invalid username or password");
            return "redirect:/error/500";
        }
    }

}