package Marcelina.example.TaskXcel.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "task")
public class Task {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String title;

    @Column(nullable = false)
    private String description;

    @Column(nullable = false)
    private LocalDateTime dueDate;

    @Column(nullable = false)
    private String priority;

    @Column(nullable = false)
    private String status;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "users_Id", nullable = false)
    private Users user;


}
