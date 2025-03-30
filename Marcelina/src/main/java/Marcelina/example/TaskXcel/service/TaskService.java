package Marcelina.example.TaskXcel.service;

import Marcelina.example.TaskXcel.dto.RequestTaskDto;
import Marcelina.example.TaskXcel.dto.ResponseTaskDto;
import Marcelina.example.TaskXcel.exception.TaskNotFoundException;
import Marcelina.example.TaskXcel.mapper.TaskMapper;
import Marcelina.example.TaskXcel.model.Task;
import Marcelina.example.TaskXcel.repository.TaskRepository;
import com.itextpdf.text.Document;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.PdfWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.FileOutputStream;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;

@Service
public class TaskService {

    @Autowired
    private static Logger log = LoggerFactory.getLogger(TaskService.class);
    @Autowired
    private TaskRepository taskRepository;
    @Autowired
    private TaskMapper mapper;

    public List<ResponseTaskDto> getAllTasks() {
        List<Task> list =  taskRepository.findAll();
        return list.stream().map(mapper::mapToResponse).toList();

    }

    public void createTask( RequestTaskDto task) {
        Task createdTask = mapper.mapToEntity(task);
        Task savedTask = taskRepository.save(createdTask);
    }

    public List<ResponseTaskDto> getTasksByUser(Long employeeId) {
        List<Task> listOfTaskByUserId = taskRepository.findByUserId(employeeId);
        return  listOfTaskByUserId.stream()
                .map(mapper::mapToResponse)
                .toList();
    }


    public List<ResponseTaskDto> getTasksUser(Long employeeId) {
        List<Task> listOfTaskByUserId = taskRepository.findByUserId(employeeId);
        return  listOfTaskByUserId.stream()
                .map(mapper::mapToResponse)
                .toList();
    }

    public List<ResponseTaskDto> getTasksByPriority(String priority) {
        List<Task> listOfTaskByPriority = taskRepository.findByPriority(priority);
        return  listOfTaskByPriority.stream()
                .map(mapper::mapToResponse)
                .toList();
    }


    public void updateTaskStatus(Long taskId, String status) {
        Task task = taskRepository.findById(taskId)
                .orElseThrow(() -> new RuntimeException("Task not found with id: " + taskId));

        task.setStatus(status);
        taskRepository.save(task);
    }


    public List<ResponseTaskDto> getTasksDueSoon() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime dueSoon = now.plusHours(24);
        List<Task> listOfTaskDueSoon = taskRepository.findByDueDateBetween(now, dueSoon);
        return  listOfTaskDueSoon.stream()
                .map(mapper::mapToResponse)
                .toList();
    }


    public void generateTaskReport(List<ResponseTaskDto> tasks) {
        Document document = new Document();
        try {
            // Create a PDF writer instance and specify the file output stream
            PdfWriter.getInstance(document, new FileOutputStream("task_report.pdf"));

            // Open the document to start adding content
            document.open();

            // Add task data to PDF
            for (ResponseTaskDto task : tasks) {
                // Adding task title and description to the PDF document
                document.add(new Paragraph("Title: " + task.getTitle()));
                document.add(new Paragraph("Description: " + task.getDescription()));
                document.add(new Paragraph(" "));
            }

            // Close the document (this writes the PDF to the file)
            document.close();
        } catch (Exception e) {
            log.error("Error generating task report", e);
        }
    }


    public void deleteTask(Long id) {
        taskRepository.deleteById(id);
    }

    public ResponseTaskDto getTaskById(Long id) {
         Task task = taskRepository.findById(id)
                 .orElseThrow(() -> new TaskNotFoundException("Task with ID " + id + " not found"));
        return  mapper.mapToResponse(task);
    }


    public void updateTask(Long id, RequestTaskDto taskDTO) {
        Task existingTask = taskRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Task not found"));

        existingTask.setTitle(taskDTO.getTitle());
        existingTask.setDescription(taskDTO.getDescription());
        existingTask.setDueDate(taskDTO.getDueDate());
        existingTask.setPriority(taskDTO.getPriority());
        existingTask.setStatus(taskDTO.getStatus());

        taskRepository.save(existingTask);
    }


    public void deleteTaskById(Long id) {
        taskRepository.deleteById(id);
    }

    public List<ResponseTaskDto> getTasksByUserAndPriority(Long employeeId, String priority) {
        List<Task> tasks = taskRepository.findByUserIdAndPriority(employeeId, priority);

        return tasks.stream()
                .map(mapper::mapToResponse)
                .toList();
    }

    public List<ResponseTaskDto> getAllTaskByUsername(String username) {
        List<Task> list = taskRepository.findAllTaskByUsername(username);
        return list.stream()
                .map(mapper::mapToResponse)
                .toList();

    }
}
