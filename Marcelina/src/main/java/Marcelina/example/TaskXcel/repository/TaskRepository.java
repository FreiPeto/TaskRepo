package Marcelina.example.TaskXcel.repository;

import Marcelina.example.TaskXcel.model.Task;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface TaskRepository extends JpaRepository<Task, Long> {

    List<Task> findByUserId(Long userId);
    List<Task> findByPriority(String priority);
    List<Task> findByStatus(String status);

    @Query("SELECT t FROM Task t WHERE t.dueDate BETWEEN :startDate AND :endDate")
    List<Task> findByDueDateBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    List<Task> findByUserIdAndPriority(Long employeeId, String priority);


    @Query("SELECT t FROM Task t WHERE t.user.username = :username")
    List<Task> findAllTaskByUsername(@Param("username") String username);
}
