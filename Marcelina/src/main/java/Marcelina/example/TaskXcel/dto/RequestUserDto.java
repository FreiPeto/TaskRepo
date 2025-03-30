package Marcelina.example.TaskXcel.dto;
//includes the fields that the client needs to provide

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;



@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class RequestUserDto {
    @NotBlank
    private String username;

    @NotBlank
    private String password;

    @NotBlank
    private String email;

    @NotNull
    private String role;

}