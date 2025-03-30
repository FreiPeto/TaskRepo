package Marcelina.example.TaskXcel.mapper;

import Marcelina.example.TaskXcel.dto.RequestUserDto;
import Marcelina.example.TaskXcel.dto.ResponseUserDto;
import Marcelina.example.TaskXcel.model.Task;
import Marcelina.example.TaskXcel.model.Users;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Component
public class UserMapper {

    public Users mapToEntity(RequestUserDto requestUserDto){

        return Users.builder()
                .username(requestUserDto.getUsername())
                .password(requestUserDto.getPassword())
                .role(requestUserDto.getRole())
                .email(requestUserDto.getEmail())
                .build();
    }


    public ResponseUserDto mapToResponse(Users users) {

        List<String> taskDescriptions = users.getTasks().stream().map(Task::getDescription)
                .collect(Collectors.toList());

        return ResponseUserDto.builder()
                .id(users.getId())
                .username(users.getUsername())
                .taskDescriptions(taskDescriptions)
                .role(users.getRole())
                .email(users.getEmail())
                .build();
    }
}
