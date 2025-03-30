package Marcelina.example.TaskXcel.dto;

import lombok.*;

import java.util.List;

//transfer data when returning a Task from the backend to the client
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ResponseUserDto {

    private Long id;
    private String username;
    private String email;
    private List<String> taskDescriptions;
    private String role;
}
