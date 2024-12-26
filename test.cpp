#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <vector>

class FileManager {
private:
    char* buffer;
    size_t bufferSize;
    
public:
    FileManager(size_t size = 1024) : bufferSize(size) {
        buffer = (char*)malloc(size);
        if (!buffer) {
            printf("Memory allocation failed\n");
            exit(1);
        }
    }
    
    ~FileManager() {
        if (buffer) {
            free(buffer);
        }
    }
    
    bool writeUsingStdLib(const char* filename, const char* data) {
        FILE* file = fopen(filename, "w");
        if (!file) {
            printf("Failed to open file\n");
            return false;
        }
        
        size_t len = strlen(data);
        size_t written = fwrite(data, 1, len, file);
        
        fclose(file);
        return written == len;
    }
    
    bool readUsingStdLib(const char* filename) {
        FILE* file = fopen(filename, "r");
        if (!file) {
            printf("Failed to open file\n");
            return false;
        }
        
        size_t read = fread(buffer, 1, bufferSize - 1, file);
        buffer[read] = '\0';
        
        printf("Read content: %s\n", buffer);
        fclose(file);
        return true;
    }
    
    bool writeUsingOS(const char* filename, const char* data) {
        int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            printf("Failed to open file\n");
            return false;
        }
        
        size_t len = strlen(data);
        ssize_t written = write(fd, data, len);
        
        close(fd);
        return written == len;
    }
    
    bool readUsingOS(const char* filename) {
        int fd = open(filename, O_RDONLY);
        if (fd < 0) {
            printf("Failed to open file\n");
            return false;
        }
        
        ssize_t bytesRead = read(fd, buffer, bufferSize - 1);
        if (bytesRead >= 0) {
            buffer[bytesRead] = '\0';
            printf("Read content: %s\n", buffer);
        }
        
        close(fd);
        return bytesRead >= 0;
    }
    
    void processFiles() {
        strcpy(buffer, "Hello World!");
        printf("Processing files...\n");
        
        // Create a backup directory
        mkdir("backup", 0755);
        
        // Fork a process to handle backup
        pid_t pid = fork();
        
        if (pid == 0) {  // Child process
            printf("Backup process started\n");
            writeUsingStdLib("backup/file1.txt", buffer);
            exit(0);
        } else if (pid > 0) {  // Parent process
            writeUsingOS("main_file.txt", buffer);
        }
    }
};

int main() {
    FileManager fm;
    
    // Test standard library functions
    printf("Testing Standard Library functions...\n");
    fm.writeUsingStdLib("test_std.txt", "Testing Standard Library");
    fm.readUsingStdLib("test_std.txt");
    
    // Test OS functions
    printf("\nTesting OS functions...\n");
    fm.writeUsingOS("test_os.txt", "Testing OS Functions");
    fm.readUsingOS("test_os.txt");
    
    // Test combined operations
    printf("\nTesting combined operations...\n");
    fm.processFiles();
    
    // Memory operations
    void* ptr = malloc(100);
    memset(ptr, 0, 100);
    free(ptr);
    
    return 0;
}
