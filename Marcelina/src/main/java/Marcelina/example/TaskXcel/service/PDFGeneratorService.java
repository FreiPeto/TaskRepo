package Marcelina.example.TaskXcel.service;
import Marcelina.example.TaskXcel.dto.ResponseTaskDto;

import com.itextpdf.text.Document;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.*;
import org.springframework.stereotype.Service;
import java.io.ByteArrayOutputStream;
import java.util.List;

@Service
public class PDFGeneratorService {

    public byte[] generateTaskPdf(List<ResponseTaskDto> tasks) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            Document document = new Document();
            PdfWriter.getInstance(document, out);
            document.open();


            Font titleFont = new Font(Font.FontFamily.HELVETICA, 16, Font.BOLD);
            Paragraph title = new Paragraph("Task List", titleFont);
            title.setAlignment(Element.ALIGN_CENTER);
            document.add(title);
            document.add(Chunk.NEWLINE);

            PdfPTable table = new PdfPTable(5);
            table.setWidthPercentage(100);
            table.setWidths(new float[]{1f, 3f, 2f, 2f, 2f});

            Font headerFont = new Font(Font.FontFamily.HELVETICA, 12, Font.BOLD);
            addTableHeader(table, "Task ID", headerFont);
            addTableHeader(table, "Title", headerFont);
            addTableHeader(table, "Priority", headerFont);
            addTableHeader(table, "Due Date", headerFont);
            addTableHeader(table, "Status", headerFont);

            for (ResponseTaskDto task : tasks) {
                table.addCell(String.valueOf(task.getId()));
                table.addCell(task.getTitle() != null ? task.getTitle() : "N/A");
                table.addCell(task.getPriority() != null ? task.getPriority() : "N/A");
                table.addCell(task.getDueDate() != null ? task.getDueDate().toString() : "N/A");
                table.addCell(task.getStatus() != null ? task.getStatus() : "N/A");
            }

            document.add(table);
            document.close();

            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Error generating PDF", e);
        }
    }


    private void addTableHeader(PdfPTable table, String columnTitle, Font font) {
        PdfPCell header = new PdfPCell(new Phrase(columnTitle, font));
        header.setHorizontalAlignment(Element.ALIGN_CENTER);
        header.setBackgroundColor(BaseColor.LIGHT_GRAY);
        table.addCell(header);
    }
}