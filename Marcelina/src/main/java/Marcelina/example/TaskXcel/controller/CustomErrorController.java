package Marcelina.example.TaskXcel.controller;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/error")
public class CustomErrorController {

    @GetMapping("/404")
    public String handleNotFound(Model model, @ModelAttribute("error") String error) {
        model.addAttribute("errorMessage", error);
        return "error/404";
    }

    @GetMapping("/500")
    public String handleServerError(Model model, @ModelAttribute("error") String error) {
        model.addAttribute("errorMessage", error);
        return "error/500";
    }
}
