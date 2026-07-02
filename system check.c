#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>

#define PROC_DIR "/proc"
#define MAX_PATH 512
#define MAX_LINE 1024

// Struttura per tenere traccia dei processi trovati
typedef struct {
    int found;
    int pid;
    char state;
    char cmdline[MAX_LINE];
} process_info_t;

// Verifica se una stringa è un numero (PID)
static int is_numeric(const char *str) {
    while (*str) {
        if (!isdigit(*str)) return 0;
        str++;
    }
    return 1;
}

// Legge il contenuto di un file in /proc/[pid]/
static int read_proc_file(int pid, const char *filename, char *buffer, size_t size) {
    char path[MAX_PATH];
    snprintf(path, sizeof(path), PROC_DIR "/%d/%s", pid, filename);
    
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    
    if (fgets(buffer, size, fp) == NULL) {
        fclose(fp);
        return 0;
    }
    
    // Rimuovi newline finale
    buffer[strcspn(buffer, "\n")] = '\0';
    fclose(fp);
    return 1;
}

// Controlla se un processo è process_api
static int is_process_api(int pid, process_info_t *info) {
    char buffer[MAX_LINE];
    
    // Leggi /proc/[pid]/comm
    if (!read_proc_file(pid, "comm", buffer, sizeof(buffer))) {
        return 0;
    }
    
    if (strcmp(buffer, "process_api") != 0) {
        return 0;
    }
    
    // Leggi /proc/[pid]/cmdline
    char path[MAX_PATH];
    snprintf(path, sizeof(path), PROC_DIR "/%d/cmdline", pid);
    FILE *fp = fopen(path, "r");
    if (fp) {
        size_t len = fread(buffer, 1, sizeof(buffer) - 1, fp);
        if (len > 0) {
            buffer[len] = '\0';
            // Converti null byte in spazi
            for (size_t i = 0; i < len - 1; i++) {
                if (buffer[i] == '\0') buffer[i] = ' ';
            }
            strncpy(info->cmdline, buffer, MAX_LINE - 1);
        }
        fclose(fp);
    }
    
    // Leggi /proc/[pid]/status per lo stato
    if (read_proc_file(pid, "status", buffer, sizeof(buffer))) {
        // Cerca la linea "State:"
        char path2[MAX_PATH];
        snprintf(path2, sizeof(path2), PROC_DIR "/%d/status", pid);
        FILE *fp2 = fopen(path2, "r");
        if (fp2) {
            while (fgets(buffer, sizeof(buffer), fp2)) {
                if (strncmp(buffer, "State:", 6) == 0) {
                    sscanf(buffer, "State:\t%c", &info->state);
                    break;
                }
            }
            fclose(fp2);
        }
    }
    
    return 1;
}

// Verifica se il processo è accessibile (non zombie, non kernel thread)
static int is_process_healthy(process_info_t *info) {
    // S (sleeping), R (running), D (uninterruptible sleep) sono stati validi
    return (info->state == 'S' || info->state == 'R' || info->state == 'D');
}

// Diagnostica il filesystem /mnt/skills
static void diagnose_filesystem() {
    printf("\n[*] Verifica filesystem /mnt/skills/public...\n");
    
    struct stat st;
    if (stat("/mnt/skills/public", &st) == 0) {
        printf("    Directory esiste\n");
        
        // Conta file e directory
        DIR *dir = opendir("/mnt/skills/public");
        if (dir) {
            int file_count = 0;
            int dir_count = 0;
            struct dirent *entry;
            
            while ((entry = readdir(dir)) != NULL) {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                    continue;
                }
                
                char fullpath[MAX_PATH];
                snprintf(fullpath, sizeof(fullpath), "/mnt/skills/public/%s", entry->d_name);
                
                if (stat(fullpath, &st) == 0) {
                    if (S_ISDIR(st.st_mode)) {
                        dir_count++;
                    } else {
                        file_count++;
                    }
                }
            }
            closedir(dir);
            printf("    Contenuto: %d file, %d directory\n", file_count, dir_count);
        }
    } else {
        printf("    [!] Directory non accessibile: %s\n", strerror(errno));
    }
}

int main() {
    printf("=== Sandbox Diagnostics ===\n\n");
    printf("[*] Scansione processi in corso...\n");
    
    DIR *proc = opendir(PROC_DIR);
    if (!proc) {
        printf("[!] ERRORE: impossibile aprire " PROC_DIR "\n");
        printf("[!] Il sandbox NON è inizializzato correttamente\n");
        return 1;
    }
    
    process_info_t api_info = {0};
    int total_processes = 0;
    int my_pid = getpid();
    
    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        if (!is_numeric(entry->d_name)) continue;
        
        int pid = atoi(entry->d_name);
        if (pid == my_pid) continue; // Salta se stesso
        
        total_processes++;
        
        process_info_t info = {0};
        if (is_process_api(pid, &info)) {
            info.pid = pid;
            info.found = 1;
            memcpy(&api_info, &info, sizeof(process_info_t));
            break; // Trovato, esci dal loop
        }
    }
    closedir(proc);
    
    printf("[*] Processi totali (escluso self): %d\n\n", total_processes);
    
    if (!api_info.found) {
        printf("[!] process_api NON TROVATO\n");
        printf("[!] Il processo principale del sandbox non è in esecuzione\n");
        printf("[!] Il sandbox NON è inizializzato correttamente\n");
        return 1;
    }
    
    printf("[+] process_api TROVATO:\n");
    printf("    PID:     %d\n", api_info.pid);
    printf("    Stato:   %c", api_info.state);
    
    switch (api_info.state) {
        case 'S': printf(" (sleeping - normale)\n"); break;
        case 'R': printf(" (running)\n"); break;
        case 'D': printf(" (I/O wait)\n"); break;
        case 'Z': printf(" (zombie - ANOMALO!)\n"); break;
        case 'T': printf(" (stopped - ANOMALO!)\n"); break;
        default:  printf(" (sconosciuto)\n"); break;
    }
    
    printf("    CMD:     %s\n", api_info.cmdline[0] ? api_info.cmdline : "(vuoto)");
    
    // Verifica salute del processo
    if (!is_process_healthy(&api_info)) {
        printf("\n[!] process_api è in uno stato anomalo (%c)\n", api_info.state);
        printf("[!] Il sandbox potrebbe non funzionare correttamente\n");
        return 1;
    }
    
    // Test di accesso al processo
    if (kill(api_info.pid, 0) == 0) {
        printf("    Accesso:  OK (segnale 0 inviato)\n");
    } else {
        printf("    Accesso:  FALLITO (%s)\n", strerror(errno));
        printf("\n[!] Impossibile comunicare con process_api\n");
        return 1;
    }
    
    diagnose_filesystem();
    
    printf("\n");
    printf("========================================\n");
    printf("  [OK] Il tuo sandbox è correttamente\n");
    printf("       inizializzato\n");
    printf("========================================\n");
    
    return 0;
}
