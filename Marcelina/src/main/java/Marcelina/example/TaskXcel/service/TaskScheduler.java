package Marcelina.example.TaskXcel.service;

import Marcelina.example.TaskXcel.dto.ResponseTaskDto;
import Marcelina.example.TaskXcel.model.Task;
import Marcelina.example.TaskXcel.model.Users;
import lombok.RequiredArgsConstructor;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;
@Service
@RequiredArgsConstructor
public class TaskScheduler {

    private final TaskService taskService;
    private final EmailService emailService;
    private final UsersService userService;

    @Scheduled(cron = "0 0 9 * * ?")
    public void sendReminderEmails() {
        List<ResponseTaskDto> tasksDueSoon = taskService.getTasksDueSoon();
        for (ResponseTaskDto task : tasksDueSoon) {
            String userEmail = userService.getUserEmailById(task.getUserId());

            if (userEmail != null) {
                String subject = "Reminder: Task Due Soon";
                String message = String.format(
                        "Dear User,\n\n" +
                                "This is a reminder that your task '%s' is due soon.\n\n" +
                                "Description: %s\n" +
                                "Due Date: %s\n\n" +
                                "Please ensure to complete it on time.\n\n" +
                                "Best regards,\n" +
                                "TaskXcel Team",
                        task.getTitle(), task.getDescription(), task.getDueDate()
                );
                emailService.sendEmail(userEmail, subject, message);
            } else {
                LoggerFactory.getLogger(TaskScheduler.class)
                        .warn("User email not found for task ID: " + task.getId());
            }
        }
    }
}
