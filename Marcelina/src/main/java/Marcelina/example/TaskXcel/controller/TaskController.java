package Marcelina.example.TaskXcel.controller;

import Marcelina.example.TaskXcel.dto.RequestTaskDto;
import Marcelina.example.TaskXcel.dto.ResponseTaskDto;
import Marcelina.example.TaskXcel.dto.ResponseUserDto;
import Marcelina.example.TaskXcel.model.Task;
import Marcelina.example.TaskXcel.service.PDFGeneratorService;
import Marcelina.example.TaskXcel.service.TaskService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Controller
@RequestMapping("/tasks")
public class TaskController {

    @Autowired
    private TaskService taskService;
    @Autowired
    private PDFGeneratorService pdfGeneratorService;


    //    @PreAuthorize("hasAnyRole('EMPLOYEE', 'MANAGER')")
    @GetMapping()
    public String showCreateTasks(
            @RequestParam(required = false) String title,
            @RequestParam(required = false) String description,
            @RequestParam(required = false) String dueDate,
            @RequestParam(required = false) String priority,
            @RequestParam(required = false) String status,
            Model model, HttpSession session) {

        Long employeeId = (Long) session.getAttribute("employeeId");
        if (employeeId == null) {
            return "redirect:/logIn";
        }

        List<ResponseTaskDto> tasks = taskService.getTasksByUser(employeeId);

        Stream<ResponseTaskDto> filtered = tasks.stream();
        if (title != null && !title.trim().isEmpty()) {
            filtered = filtered.filter(task ->
                    task.getTitle() != null && task.getTitle().toLowerCase().contains(title.toLowerCase()));
        }
        if (description != null && !description.trim().isEmpty()) {
            filtered = filtered.filter(task ->
                    task.getDescription() != null && task.getDescription().toLowerCase().contains(description.toLowerCase()));
        }
        if (dueDate != null && !dueDate.trim().isEmpty()) {
            filtered = filtered.filter(task ->
                    task.getDueDate() != null && task.getDueDate().toString().contains(dueDate));
        }
        if (priority != null && !priority.trim().isEmpty()) {
            filtered = filtered.filter(task ->
                    task.getPriority() != null && task.getPriority().equalsIgnoreCase(priority));
        }
        if (status != null && !status.trim().isEmpty()) {
            filtered = filtered.filter(task ->
                    task.getStatus() != null && task.getStatus().equalsIgnoreCase(status));
        }


        List<ResponseTaskDto> filteredTasks = filtered.collect(Collectors.toList());
        model.addAttribute("tasks", filteredTasks);
        return "task-list";
    }

    @GetMapping("/create")
    public String showCreateTaskForm(Model model) {
        RequestTaskDto task = new RequestTaskDto();

        if (task.getDueDate() != null) {
            task.setDueDate(LocalDateTime.parse(task.getDueDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm"))));
        }
        model.addAttribute("task", task);
        return "Create-Task";
    }


    @PostMapping("/create")
    public String addTask(@ModelAttribute("task") RequestTaskDto task, BindingResult result, Model model) {
        if (result.hasErrors()) {
            model.addAttribute("task", task);
            return "Create-Task";
        }
        taskService.createTask(task);
        return "redirect:/dashboard";
    }

    @PostMapping("/update/{id}")
    public String updateTaskStatus(@PathVariable("id") Long taskId) {
        taskService.updateTaskStatus(taskId, "COMPLETED");
        return "redirect:/tasks";
    }

    @GetMapping("/filter")
    public String filterTasksByPriority(@RequestParam(required = false) String priority,
                                        Model model,
                                        HttpSession session) {
        Long employeeId = (Long) session.getAttribute("employeeId");

        if (employeeId == null) {
            return "redirect:/logIn";
        }

        List<ResponseTaskDto> tasks;
        if (priority == null || priority.isEmpty()) {
            tasks = taskService.getTasksByUser(employeeId);
        } else {
            tasks = taskService.getTasksByUserAndPriority(employeeId, priority);
        }
        model.addAttribute("tasks", tasks);

        return "task-list";
    }

    @GetMapping("/pdf")
    public ResponseEntity<byte[]> generatePdf() {
        List<ResponseTaskDto> tasks = taskService.getAllTasks();
        byte[] pdfContent = pdfGeneratorService.generateTaskPdf(tasks);

        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "attachment; filename=tasks.pdf");

        return new ResponseEntity<>(pdfContent, headers, HttpStatus.OK);
    }
}
