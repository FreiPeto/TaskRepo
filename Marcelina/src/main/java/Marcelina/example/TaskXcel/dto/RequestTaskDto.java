package Marcelina.example.TaskXcel.dto;

import lombok.*;

import java.time.LocalDateTime;

//includes the fields that the client needs to provide

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RequestTaskDto {
    private String title;
    private String description;
    private LocalDateTime dueDate;
    private String priority;
    private String status;
    private Long userId;

    public static class RespondChatMessageDto {
    }
}
