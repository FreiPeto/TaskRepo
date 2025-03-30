package Marcelina.example.TaskXcel.mapper;

import Marcelina.example.TaskXcel.dto.RequestTaskDto;
import Marcelina.example.TaskXcel.dto.ResponseTaskDto;
import Marcelina.example.TaskXcel.model.Task;
import Marcelina.example.TaskXcel.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;


@RequiredArgsConstructor
@Component
public class TaskMapper {

    private final UserRepository userRepository;

    public Task mapToEntity(RequestTaskDto requestTaskDto) {
        if (requestTaskDto == null) {
            return null;
        }

        return Task.builder()
                .title(requestTaskDto.getTitle())
                .description(requestTaskDto.getDescription())
                .priority(requestTaskDto.getPriority())
                .status(requestTaskDto.getStatus())
                .dueDate(requestTaskDto.getDueDate())
                .user(userRepository.findById(requestTaskDto.getUserId())
                        .orElseThrow(() -> new RuntimeException("User not found!!")))
                .build();
    }


    public ResponseTaskDto mapToResponse(Task task) {
        if (task == null) {
            return null;
        }

        return ResponseTaskDto.builder()
                .id(task.getId())
                .userId(task.getUser().getId())
                .dueDate(task.getDueDate())
                .title(task.getTitle())
                .description(task.getDescription())
                .priority(task.getPriority())
                .status(task.getStatus())
                .build();
    }
}