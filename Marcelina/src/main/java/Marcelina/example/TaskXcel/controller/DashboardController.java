package Marcelina.example.TaskXcel.controller;
import Marcelina.example.TaskXcel.dto.ResponseTaskDto;
import Marcelina.example.TaskXcel.dto.ResponseUserDto;
import Marcelina.example.TaskXcel.model.Users;
import Marcelina.example.TaskXcel.service.UsersService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import Marcelina.example.TaskXcel.service.TaskService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.time.LocalDateTime;
import java.util.List;
    @Controller
    @RequestMapping("/dashboard")
    public class DashboardController {

        @Autowired
        private TaskService taskService;

        @Autowired
        private UsersService userService;


//        @PreAuthorize("hasAnyRole('MANAGER')")
        @GetMapping
        public String showDashboard(Model model, HttpSession session) {
            List<ResponseTaskDto> tasks = taskService.getAllTasks();
            // Calculate task metrics
            int totalTasks = tasks.size();
            int completedTasks = (int) tasks.stream().filter(task -> "COMPLETED".equals(task.getStatus())).count();
            int overdueTasks = (int) tasks.stream()
                    .filter(task -> task.getDueDate() != null && task.getDueDate().isBefore(LocalDateTime.now()) && !"COMPLETED".equals(task.getStatus()))
                    .count();
            // Add task data to the model
            model.addAttribute("tasks", tasks);
            model.addAttribute("totalTasks", totalTasks);
            model.addAttribute("completedTasks", completedTasks);
            model.addAttribute("overdueTasks", overdueTasks);

            return "Dashboard";
        }


        // Delete task by ID
        @PostMapping("/delete/{id}")
        public String deleteTask(@PathVariable("id") Long taskId) {
            System.out.println("Deleting task with ID: " + taskId);
            taskService.deleteTaskById(taskId);
            return "redirect:/dashboard";
        }
    }
