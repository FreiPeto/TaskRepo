package Marcelina.example.TaskXcel.dto;


import lombok.*;

import java.time.LocalDateTime;

//transfer data when returning a Task from the backend to the client
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ResponseTaskDto {

    private Long id;
    private String title;
    private String description;
    private LocalDateTime dueDate;
    private String priority;
    private String status;
    private Long userId;


}
