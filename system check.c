#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>

#define PROC_DIR "/proc"
#define MAX_PATH 512
#define MAX_LINE 1024
#define MAX_PROCESSES 256

// Struttura per tenere traccia di un processo generico
typedef struct {
    int pid;
    char comm[256];
    char state;
    char cmdline[MAX_LINE];
} process_info_t;

// Verifica se una stringa è un numero (PID)
static int is_numeric(const char *str) {
    if (*str == '\0') return 0;
    while (*str) {
        if (!isdigit((unsigned char)*str)) return 0;
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

    buffer[strcspn(buffer, "\n")] = '\0';
    fclose(fp);
    return 1;
}

// Raccoglie informazioni su un processo
static int get_process_info(int pid, process_info_t *info) {
    char buffer[MAX_LINE];

    memset(info, 0, sizeof(*info));
    info->pid = pid;

    // comm
    if (!read_proc_file(pid, "comm", buffer, sizeof(buffer))) {
        return 0;
    }
    strncpy(info->comm, buffer, sizeof(info->comm) - 1);

    // cmdline
    char path[MAX_PATH];
    snprintf(path, sizeof(path), PROC_DIR "/%d/cmdline", pid);
    FILE *fp = fopen(path, "r");
    if (fp) {
        size_t len = fread(buffer, 1, sizeof(buffer) - 1, fp);
        if (len > 0) {
            buffer[len] = '\0';
            for (size_t i = 0; i < len - 1; i++) {
                if (buffer[i] == '\0') buffer[i] = ' ';
            }
            strncpy(info->cmdline, buffer, MAX_LINE - 1);
        }
        fclose(fp);
    }

    // status -> State
    snprintf(path, sizeof(path), PROC_DIR "/%d/status", pid);
    fp = fopen(path, "r");
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strncmp(buffer, "State:", 6) == 0) {
                sscanf(buffer, "State:\t%c", &info->state);
                break;
            }
        }
        fclose(fp);
    }

    return 1;
}

// Verifica se il processo è in uno stato "sano"
static int is_process_healthy(const process_info_t *info) {
    return (info->state == 'S' || info->state == 'R' || info->state == 'D');
}

// Conta e mostra i processi totali, evidenziando stati anomali
static void scan_processes(void) {
    printf("[*] Scansione processi in corso...\n");

    DIR *proc = opendir(PROC_DIR);
    if (!proc) {
        printf("[!] ERRORE: impossibile aprire " PROC_DIR " (%s)\n", strerror(errno));
        printf("[!] Il sandbox NON è inizializzato correttamente\n");
        return;
    }

    int total = 0;
    int running = 0, sleeping = 0, zombie = 0, stopped = 0, other = 0;
    int my_pid = getpid();

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        if (!is_numeric(entry->d_name)) continue;

        int pid = atoi(entry->d_name);
        if (pid == my_pid) continue;

        process_info_t info;
        if (!get_process_info(pid, &info)) continue;

        total++;

        switch (info.state) {
            case 'R': running++; break;
            case 'S': case 'D': sleeping++; break;
            case 'Z': zombie++; break;
            case 'T': stopped++; break;
            default:  other++; break;
        }

        // Mostra solo processi anomali
        if (info.state == 'Z' || info.state == 'T') {
            printf("    [!] PID %-6d %-20s stato=%c (%s)\n",
                   info.pid, info.comm, info.state,
                   info.state == 'Z' ? "zombie" : "stopped");
        }
    }
    closedir(proc);

    printf("[*] Processi totali (escluso self): %d\n", total);
    printf("    Running: %d | Sleeping: %d | Zombie: %d | Stopped: %d | Altro: %d\n",
           running, sleeping, zombie, stopped, other);

    if (zombie > 0 || stopped > 0) {
        printf("[!] Rilevati processi in stati anomali\n");
    } else {
        printf("[+] Nessun processo in stato anomalo\n");
    }
}

// Diagnostica una directory (esistenza, permessi, contenuto)
static void diagnose_directory(const char *path) {
    printf("\n[*] Verifica directory %s...\n", path);

    struct stat st;
    if (stat(path, &st) != 0) {
        printf("    [!] Non accessibile: %s\n", strerror(errno));
        return;
    }

    printf("    Esiste\n");
    printf("    Permessi: %o\n", st.st_mode & 0777);
    printf("    Owner UID: %d, GID: %d\n", st.st_uid, st.st_gid);

    if (!S_ISDIR(st.st_mode)) {
        printf("    [!] Non è una directory\n");
        return;
    }

    DIR *dir = opendir(path);
    if (!dir) {
        printf("    [!] Impossibile leggere il contenuto: %s\n", strerror(errno));
        return;
    }

    int files = 0, dirs = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char fullpath[MAX_PATH];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);

        struct stat est;
        if (stat(fullpath, &est) == 0) {
            if (S_ISDIR(est.st_mode)) dirs++;
            else files++;
        }
    }
    closedir(dir);

    printf("    Contenuto: %d file, %d directory\n", files, dirs);
}

// Controlla se il processo corrente ha privilegi elevati
static void check_privileges(void) {
    printf("\n[*] Verifica privilegi...\n");
    if (geteuid() == 0) {
        printf("    [!] In esecuzione come root (UID 0)\n");
    } else {
        printf("    Esecuzione come UID %d\n", geteuid());
    }
}

// Controlla se /proc è montato e accessibile
static void check_proc(void) {
    printf("\n[*] Verifica /proc...\n");
    struct stat st;
    if (stat(PROC_DIR, &st) != 0) {
        printf("    [!] " PROC_DIR " non accessibile: %s\n", strerror(errno));
        return;
    }
    if (!S_ISDIR(st.st_mode)) {
        printf("    [!] " PROC_DIR " non è una directory\n");
        return;
    }
    printf("    OK\n");
}

// Controlla l'accesso a /dev/null, /dev/zero, /dev/random
static void check_devices(void) {
    printf("\n[*] Verifica device di base...\n");
    const char *devices[] = {"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"};
    for (size_t i = 0; i < sizeof(devices) / sizeof(devices[0]); i++) {
        if (access(devices[i], F_OK) == 0) {
            printf("    %s: presente\n", devices[i]);
        } else {
            printf("    %s: MANCANTE (%s)\n", devices[i], strerror(errno));
        }
    }
}

int main(void) {
    printf("=== Sandbox Diagnostics (generico) ===\n");

    check_proc();
    check_privileges();
    scan_processes();
    check_devices();

    // Diagnostica alcune directory tipiche
    diagnose_directory("/tmp");
    diagnose_directory("/mnt/skills/public");
    diagnose_directory("/var/tmp");

    printf("\n");
    printf("========================================\n");
    printf("  [OK] Diagnostica completata\n");
    printf("========================================\n");

    return 0;
}
