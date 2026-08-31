/*
 * tape.c - Linux TAPE command for communicating with a z/VM CMS Tape Proxy
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/mtio.h>
#include <stdarg.h>
#include <syslog.h>
#include <iconv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <sys/select.h>
#include <sys/inotify.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <limits.h>
#include <time.h>

#ifndef AF_IUCV
#define AF_IUCV 32
#endif
#ifndef PF_IUCV
#define PF_IUCV AF_IUCV
#endif

#ifndef IUCV_SOCKADDR_DEFINED
#define IUCV_SOCKADDR_DEFINED
struct sockaddr_iucv {
    sa_family_t    siucv_family;
    unsigned short siucv_port;
    unsigned int   siucv_addr;
    char           siucv_nodeid[8];
    char           siucv_user_id[8];
    char           siucv_name[8];
};
#endif

#define MAX_BUF 1024
#define RESPONSE_BUF_SIZE 4096
#define RESPONSE_TERMINATOR 0x00
#define DEFAULT_PORT "4443"
#define DEFAULT_HOST "localhost"
#define DEFAULT_TIMEOUT 30
#define CONNECT_TIMEOUT 20
#define DEFAULT_RETAIN "7"
#define DEFAULT_EBCDIC_CODEPAGE "IBM037"
#define LOCK_DIR "/run/lock/tape"
#define OWNER_DIR "/run/tape"
#define REQUIRED_GROUP "tapes"
#define DEFAULT_IUCV_NAME "TAPESRV"
#define TAPE_SYSFS_CLASS "tape390"
#define SYSLOG_TAG "tape"
#define TAPE_BLOCK_SIZE 32760
#define SL_RECORD_LEN 80

int   no_tls        = -1;
int   use_tls        = 0;
char *config_path    = NULL;
char *host           = NULL;
char *port           = NULL;
char *cms_password   = NULL;
int   timeout_seconds = DEFAULT_TIMEOUT;
int   debug          = 0;

char *ca_file        = NULL;
char *key_file       = NULL;
char *certificate    = NULL;

char *ebcdic_codepage = NULL;

int   iucv_flag          = 0;
int   iucv_flag_from_cli = 0;   /* set when --iucv appears on the command line;
                                    lets parse_config() know not to let a
                                    config-file "iucv=" setting override it,
                                    matching the CLI-wins convention used for
                                    every other option in this file. */
char *iucv_userid    = NULL;
char *iucv_name      = NULL;

int   vdev_min = 0x0180;
int   vdev_max = 0x018F;

char *volser         = NULL;
char *mode           = NULL;
int   mode_explicit  = 0;
char *retain         = NULL;
char *retention_default_cfg = NULL;
int   retention_max  = 0;
char *vdev_opt       = NULL;
char *detach_path    = NULL;
char *dsn_opt        = NULL;   /* --dsn: HDR1 dataset name (write) or search target (scan) */
char *infile_opt     = NULL;   /* --in: input file for write, instead of stdin */
char *outfile_opt    = NULL;   /* --out: output file for read/verify, instead of stdout */
int   scan_before    = 0;      /* --before: scan positions at HDR1 for overwrite, not DATA */
int   write_append   = 0;      /* --append: position past the last file before writing */
int   write_extra    = 0;      /* --extra: write shows progress + a sha256 checksum */
char *verify_checksum_opt = NULL; /* --checksum: expected sha256 hex for "tape verify" (optional) */
char *command_mode   = NULL;
int   help_flag      = 0;
int   reset_all      = 0;
/*
 * count_opt backs --count/-n, whose meaning is command-dependent:
 *   fsf  -> number of tape marks to forward space past (default 1)
 *   scan -> which occurrence of a repeated dataset name to locate,
 *           1-based (default 1, i.e. the first)
 */
int   count_opt      = 1;

int      sockfd = -1;
SSL     *ssl = NULL;
SSL_CTX *ctx = NULL;

struct passwd *pw = NULL;
char *vm_userid = NULL;

char *g_reserved_vdev = NULL;
int   g_reserved_lock_fd = -1;
int   g_mount_confirmed = 0;

static const char *dev_prefixes[]  = { "ntibm", "rtibm", "btibm" };

/* ---- small utilities ----------------------------------------------------- */

void debug_log(const char *fmt, ...) {
    if (!debug) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

void string_to_upper(char *str) {
    for (int i = 0; str[i] != '\0'; i++)
        str[i] = toupper((unsigned char) str[i]);
}

void trim_whitespace(char *str) {
    char *end;
    while (*str && isspace((unsigned char) *str)) str++;
    if (*str == 0) return;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char) *end)) end--;
    *(end + 1) = '\0';
}

void strip_quotes(char *str) {
    size_t len = strlen(str);
    if (len >= 2 && ((str[0] == '"'  && str[len - 1] == '"') ||
                      (str[0] == '\'' && str[len - 1] == '\''))) {
        str[len - 1] = '\0';
        memmove(str, str + 1, len - 1);
    }
}

void set_iucv_field(char *field, const char *value) {
    memset(field, ' ', 8);
    if (!value) return;
    size_t len = strlen(value);
    if (len > 8) len = 8;
    for (size_t i = 0; i < len; i++)
        field[i] = toupper((unsigned char) value[i]);
}

/* Pluralization helpers, used throughout output messages instead of a
 * hardcoded "(s)" suffix. */
const char *day_word(long n)        { return (n == 1) ? "day" : "days"; }
const char *block_word(long n)      { return (n == 1) ? "block" : "blocks"; }
const char *mark_word(long n)       { return (n == 1) ? "mark" : "marks"; }
const char *device_word(long n)     { return (n == 1) ? "device" : "devices"; }
const char *occurrence_word(long n) { return (n == 1) ? "occurrence" : "occurrences"; }

const char *filename_base(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

void sha256_hex(const unsigned char *digest, unsigned int len, char *out_hex) {
    static const char hexchars[] = "0123456789abcdef";
    for (unsigned int i = 0; i < len; i++) {
        out_hex[i * 2]     = hexchars[(digest[i] >> 4) & 0xF];
        out_hex[i * 2 + 1] = hexchars[digest[i] & 0xF];
    }
    out_hex[len * 2] = '\0';
}

int run_argv(char *const argv[], char *capture_buf, size_t capture_size) {
    int pipefd[2] = {-1, -1};
    if (capture_buf && pipe(pipefd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        if (capture_buf) { close(pipefd[0]); close(pipefd[1]); }
        return -1;
    }

    if (pid == 0) {
        if (capture_buf) {
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
            close(pipefd[1]);
        } else {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); close(devnull); }
        }
        int devnull_err = open("/dev/null", O_WRONLY);
        if (devnull_err >= 0) { dup2(devnull_err, STDERR_FILENO); close(devnull_err); }

        execvp(argv[0], argv);
        _exit(127);
    }

    int status;
    if (capture_buf) {
        close(pipefd[1]);
        ssize_t n = read(pipefd[0], capture_buf, capture_size - 1);
        if (n < 0) n = 0;
        capture_buf[n] = '\0';
        close(pipefd[0]);
    }
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

void release_vdev_lock(int fd, const char *vdev_hex);
void remove_owner_request(const char *vdev_hex);
void detach_vdev_silently(const char *vdev_hex);

/* ---- signal handling ------------------------------------------------------ */

void disconnect(void) {
    if (ssl)  { SSL_free(ssl); ssl = NULL; }
    if (ctx)  { SSL_CTX_free(ctx); ctx = NULL; }
    if (sockfd != -1) { close(sockfd); sockfd = -1; }
}

void signal_handler(int sig) {
    debug_log("Signal %d received. Sending CANCEL.\n", sig);
    const char *cancel_msg = "CANCEL\n";
    if (sockfd != -1) {
        if (use_tls && ssl) SSL_write(ssl, cancel_msg, strlen(cancel_msg));
        else                send(sockfd, cancel_msg, strlen(cancel_msg), 0);
    }
    disconnect();

    if (g_reserved_vdev) {
        if (!g_mount_confirmed) {
            remove_owner_request(g_reserved_vdev);
        }
        release_vdev_lock(g_reserved_lock_fd, g_reserved_vdev);
        syslog(LOG_NOTICE, "MOUNT INTERRUPTED vdev=%s signal=%d confirmed=%d",
               g_reserved_vdev, sig, g_mount_confirmed);
    }

    exit(1);
}

void install_signals(void) {
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
}

/* ---- config file ----------------------------------------------------------- */

void parse_config(void) {
    char home_conf[PATH_MAX];
    const char *home = getenv("HOME");
    if (home) snprintf(home_conf, sizeof(home_conf), "%s/.tape.conf", home);

    const char *files[4];
    files[0] = config_path;
    files[1] = "./tape.conf";
    files[2] = home ? home_conf : NULL;
    files[3] = "/etc/tape.conf";

    FILE *fp = NULL;
    for (int i = 0; i < 4; i++) {
        if (!files[i]) continue;
        debug_log("Checking for configuration file: %s\n", files[i]);
        fp = fopen(files[i], "r");
        if (fp) break;
    }
    if (!fp) return;

    char line[MAX_BUF];
    while (fgets(line, sizeof(line), fp)) {
        trim_whitespace(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        char *equals = strchr(line, '=');
        if (!equals) continue;
        *equals = '\0';
        char *key = line;
        char *value = equals + 1;
        trim_whitespace(key);
        trim_whitespace(value);
        strip_quotes(value);

        if      (strcmp(key, "host") == 0 && !host)         host = strdup(value);
        else if (strcmp(key, "port") == 0 && !port)         port = strdup(value);
        else if (strcmp(key, "timeout") == 0)                timeout_seconds = atoi(value);
        else if (strcmp(key, "password") == 0 && !cms_password) cms_password = strdup(value);
        else if (strcmp(key, "vdev_min") == 0)               vdev_min = (int) strtol(value, NULL, 16);
        else if (strcmp(key, "vdev_max") == 0)               vdev_max = (int) strtol(value, NULL, 16);
        else if (strcmp(key, "iucv") == 0) {
            if (!iucv_flag_from_cli) {
                iucv_flag = (strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0 ||
                             strcmp(value, "1") == 0);
            }
        }
        else if (strcmp(key, "iucv_userid") == 0 && !iucv_userid) iucv_userid = strdup(value);
        else if (strcmp(key, "iucv_name") == 0 && !iucv_name)     iucv_name = strdup(value);
        else if (strcmp(key, "tls") == 0) {
            if (no_tls == -1) {
                int tls_enabled = (strcasecmp(value, "yes") == 0 ||
                                    strcasecmp(value, "true") == 0 ||
                                    strcmp(value, "1") == 0);
                no_tls = tls_enabled ? 0 : 1;
            }
        }
        else if (strcmp(key, "ca_file") == 0 && !ca_file)       ca_file = strdup(value);
        else if (strcmp(key, "key_file") == 0 && !key_file)     key_file = strdup(value);
        else if (strcmp(key, "certificate") == 0 && !certificate) certificate = strdup(value);
        else if (strcmp(key, "retention_default") == 0 && !retention_default_cfg)
            retention_default_cfg = strdup(value);
        else if (strcmp(key, "retention_max") == 0) retention_max = atoi(value);
        else if (strcmp(key, "ebcdic_codepage") == 0 && !ebcdic_codepage) ebcdic_codepage = strdup(value);
    }
    fclose(fp);
}

/* ---- CLI parsing ------------------------------------------------------------ */

enum {
    OPT_HOST = 1000, OPT_PORT, OPT_NOTLS, OPT_IUCV, OPT_IUCV_USERID,
    OPT_IUCV_NAME, OPT_ALL, OPT_CA_FILE, OPT_KEY_FILE, OPT_CERTIFICATE
};

void show_help(void) {
    printf(
"Usage: tape <mount|detach|det|rewind|rew|fsf|write|read|wtm|scan|map|verify|query|reset> [options]\n"
"\n"
"Commands:\n"
"  mount           Mount a tape by volser, or a scratch tape if --volser is omitted\n"
"  detach, det     Detach a mounted tape device (defaults to your mounted tape)\n"
"  rewind, rew     Rewind a mounted tape (defaults to your mounted tape)\n"
"  fsf             Forward space past the next tape mark (or N with --count)\n"
"  write           Write a labeled SL file to tape (HDR1/HDR2 + data + EOF1/EOF2\n"
"                  + tape marks), e.g. tape write --in myfile.bin. Writes one\n"
"                  file per invocation; use a shell loop for multiple files\n"
"                  (see EXAMPLES).\n"
"  read            Read a tape file, stopping at the tape mark, e.g. tape read --out myfile.bin\n"
"  wtm             Write a single tape mark with no data transfer\n"
"  scan            Search the tape for a file by --dsn and position to read it\n"
"                  (or, with --before/-b, position to overwrite it). With\n"
"                  --count/-n, locates the Nth occurrence of the name.\n"
"  map             List every SL file on the tape (dsn, dates, size)\n"
"  verify          Read the positioned file and compute its sha256 checksum;\n"
"                  compares against --checksum/-C <hex> if given, otherwise\n"
"                  just displays it (use after 'tape scan')\n"
"  query           List mounted tapes (root sees all; others see only their own)\n"
"  reset           Detach all your mounted tapes and clear stale reservations.\n"
"                  Root only: --all/-a resets every user's tapes system-wide.\n"
"\n"
"Mount options:\n"
"  --volser, --vol, -v <volser>  Volser to mount (omit for a SCRATCH tape)\n"
"  --mode, -m <READ|WRITE>       Mount mode (default READ; case-insensitive)\n"
"  --read, -R                    Alias for --mode READ\n"
"  --write, -W                   Alias for --mode WRITE\n"
"  --dev, -d <vdev>               Virtual device address (default: first free)\n"
"  --retain, -r <days>            Retention period in days (default 7, or\n"
"                                  'retention_default' from tape.conf; capped\n"
"                                  by 'retention_max' if set)\n"
"\n"
"Detach/rewind/fsf/write/read/wtm/scan/map/verify options:\n"
"  --dev, -d <vdev>                Virtual device address (default: your mounted tape)\n"
"  --path, -p <device path>       Device path to target (alternative to --dev)\n"
"\n"
"Write options:\n"
"  --in, -i <file>                   Read data from this file instead of stdin\n"
"                                     (single file per invocation; shell-expanded\n"
"                                     globs only supply the first match - loop\n"
"                                     instead, see EXAMPLES)\n"
"  --dsn, -f <name>                  HDR1 dataset name, up to 17 chars (default:\n"
"                                     the input file's name, uppercased, if --in\n"
"                                     is given; otherwise the tape's volser)\n"
"  --append, -A                      Position past the last existing file before\n"
"                                     writing, so this file extends the tape\n"
"                                     rather than replacing whatever is currently\n"
"                                     positioned there\n"
"  --extra, -x                       Show write progress and a sha256 checksum\n"
"                                     of the data written\n"
"\n"
"Read options:\n"
"  --out, -o <file>                  Write data to this file instead of stdout\n"
"\n"
"Scan options:\n"
"  --dsn, -f <name>                  Dataset name to search for (required);\n"
"                                     matched case-insensitively\n"
"  --count, -n <N>                   Position to the Nth occurrence of the\n"
"                                     dataset name (default: 1, i.e. the first)\n"
"  --before, -b                      Position to overwrite this file (and\n"
"                                     everything after it) with 'tape write',\n"
"                                     instead of positioning to read it\n"
"\n"
"Verify options:\n"
"  --checksum, -C <hex>              Expected sha256 checksum to compare against.\n"
"                                     Optional: if omitted, the checksum of the\n"
"                                     positioned file is computed and displayed\n"
"                                     instead of compared.\n"
"  --out, -o <file>                  Also save the data to this file while verifying\n"
"\n"
"FSF options:\n"
"  --count, -n <N>                 Number of tape marks to forward space (default 1)\n"
"\n"
"Reset options:\n"
"  --all, -a                       Root only: reset every user's tapes, not just your own\n"
"\n"
"Transport options:\n"
"  --host <host>              CMS Tape Proxy hostname (TCP mode)\n"
"  --port <port>               Port number (TCP mode)\n"
"  --noTLS                     Disable TLS (TCP mode); overridable via tape.conf 'tls='\n"
"  --ca-file <path>            CA bundle to verify the server's TLS certificate\n"
"  --key-file <path>           Client private key (mutual TLS)\n"
"  --certificate <path>        Client certificate (mutual TLS)\n"
"  --iucv                      Use AF_IUCV instead of TCP/IP (blocking connect);\n"
"                               always overrides 'iucv=' in tape.conf\n"
"  --iucv-userid <userid>      Target CMS Tape Proxy VM guest userid (required with --iucv,\n"
"                               unless set via iucv_userid= in tape.conf)\n"
"  --iucv-name <name>          Target IUCV application name (default TAPESRV)\n"
"\n"
"Common options:\n"
"  --config, -c <path>             Configuration file path\n"
"  --password, -P <pass>           CMS Tape Proxy password\n"
"  --timeout, -t <seconds>           Timeout waiting for device to appear\n"
"  --debug, -D                     Show debug output\n"
"  --help, -h                      Show this help\n"
"\n"
"Examples:\n"
"  tape mount --volser ABC123 --mode WRITE --dev 181 --retain 30\n"
"  tape mount -v ABC123 -W -d 181 -r 30\n"
"  tape mount                                     (scratch tape, auto device)\n"
"  tape write --in Makefile                       (dsn defaults to MAKEFILE)\n"
"  tape write -i myfile.bin -f PAYROLL\n"
"  for f in *.c; do tape write --in \"$f\"; done    (write a whole glob, one file each)\n"
"  tape read --out myfile.bin\n"
"  tape wtm\n"
"  tape fsf\n"
"  tape scan --dsn payroll                        (case-insensitive; positions to read)\n"
"  tape scan -f payroll -n 3                      (third occurrence of the name)\n"
"  tape scan --dsn payroll --before                (positions to overwrite)\n"
"  tape map\n"
"  tape detach\n"
"  tape rewind\n"
"  tape query\n"
"  tape reset\n"
"  tape reset --all      (root only)\n"
"\n"
"Backing up and restoring a directory tree:\n"
"  tar cf - /home | tape write --dsn HOME_BACKUP --extra   (backup, show checksum)\n"
"  tape scan --dsn HOME_BACKUP\n"
"  tape read | tar xf - -C /restore                        (restore everything)\n"
"  tape scan --dsn HOME_BACKUP\n"
"  tape read | tar xf - -C /restore home/arty/one.txt       (restore a single file)\n"
"  tar cf - /var | tape write --append --dsn VAR_BACKUP     (add another backup after the first)\n"
"  tape scan --dsn HOME_BACKUP\n"
"  tape verify -C <checksum-from-write>                     (confirm tape matches what was written)\n"
"  tape scan --dsn HOME_BACKUP\n"
"  tape verify -C \"$(tar cf - /home | sha256sum | cut -d' ' -f1)\"  (confirm tape matches source now)\n"
"  tape scan --dsn HOME_BACKUP\n"
"  tape verify                                              (just show the checksum, e.g. to log it)\n"
    );
}

void parse_args(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"volser",      required_argument, 0, 'v'},
        {"vol",         required_argument, 0, 'v'},
        {"mode",        required_argument, 0, 'm'},
        {"read",        no_argument,       0, 'R'},
        {"write",       no_argument,       0, 'W'},
        {"dev",         required_argument, 0, 'd'},
        {"retain",      required_argument, 0, 'r'},
        {"path",        required_argument, 0, 'p'},
        {"config",      required_argument, 0, 'c'},
        {"timeout",     required_argument, 0, 't'},
        {"count",       required_argument, 0, 'n'},
        {"dsn",         required_argument, 0, 'f'},
        {"in",          required_argument, 0, 'i'},
        {"out",         required_argument, 0, 'o'},
        {"before",      no_argument,       0, 'b'},
        {"append",      no_argument,       0, 'A'},
        {"extra",       no_argument,       0, 'x'},
        {"checksum",    required_argument, 0, 'C'},
        {"host",        required_argument, 0, OPT_HOST},
        {"port",        required_argument, 0, OPT_PORT},
        {"password",    required_argument, 0, 'P'},
        {"debug",       no_argument,       0, 'D'},
        {"noTLS",       no_argument,       0, OPT_NOTLS},
        {"ca-file",     required_argument, 0, OPT_CA_FILE},
        {"key-file",    required_argument, 0, OPT_KEY_FILE},
        {"certificate", required_argument, 0, OPT_CERTIFICATE},
        {"help",        no_argument,       0, 'h'},
        {"iucv",        no_argument,       0, OPT_IUCV},
        {"iucv-userid", required_argument, 0, OPT_IUCV_USERID},
        {"iucv-name",   required_argument, 0, OPT_IUCV_NAME},
        {"all",         no_argument,       0, OPT_ALL},
        {0, 0, 0, 0}
    };

    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "v:m:RWd:r:p:c:t:n:f:i:o:bAxC:P:Dha",
                               long_options, &option_index)) != -1) {
        switch (opt) {
            case 'v': volser = strdup(optarg); break;
            case 'm': mode = strdup(optarg); mode_explicit = 1; break;
            case 'R': mode = strdup("READ");  mode_explicit = 1; break;
            case 'W': mode = strdup("WRITE"); mode_explicit = 1; break;
            case 'd': vdev_opt = strdup(optarg); break;
            case 'r': retain = strdup(optarg); break;
            case 'p': detach_path = strdup(optarg); break;
            case 'c': config_path = strdup(optarg); break;
            case 't': timeout_seconds = atoi(optarg); break;
            case 'n': count_opt = atoi(optarg); break;
            case 'f': dsn_opt = strdup(optarg); string_to_upper(dsn_opt); break;
            case 'i': infile_opt = strdup(optarg); break;
            case 'o': outfile_opt = strdup(optarg); break;
            case 'b': scan_before = 1; break;
            case 'A': write_append = 1; break;
            case 'x': write_extra = 1; break;
            case 'C': verify_checksum_opt = strdup(optarg); break;
            case 'P': cms_password = strdup(optarg); break;
            case 'D': debug = 1; break;
            case 'h': help_flag = 1; break;
            case 'a': reset_all = 1; break;
            case OPT_HOST:        host = strdup(optarg); break;
            case OPT_PORT:        port = strdup(optarg); break;
            case OPT_NOTLS:       no_tls = 1; break;
            case OPT_CA_FILE:     ca_file = strdup(optarg); break;
            case OPT_KEY_FILE:    key_file = strdup(optarg); break;
            case OPT_CERTIFICATE: certificate = strdup(optarg); break;
            case OPT_IUCV:        iucv_flag = 1; iucv_flag_from_cli = 1; break;
            case OPT_IUCV_USERID: iucv_userid = strdup(optarg); break;
            case OPT_IUCV_NAME:   iucv_name = strdup(optarg); break;
            case OPT_ALL:         reset_all = 1; break;
            default:
                fprintf(stderr, "Unknown option.\n");
                exit(EXIT_FAILURE);
        }
    }

    if (optind < argc)
        command_mode = strdup(argv[optind]);
}

/* ---- vdev normalization / free-device scanning ------------------------------ */

void normalize_user_vdev(const char *input, char *out4, size_t out4_size) {
    const char *p = input;
    if (strncasecmp(p, "0x", 2) == 0) p += 2;
    const char *dot = strstr(p, "0.0.");
    if (dot) p = dot + 4;

    unsigned int v = (unsigned int) strtoul(p, NULL, 16);
    snprintf(out4, out4_size, "%04X", v & 0xFFFF);
}

int is_vdev_free(const char *vdev_hex) {
    char want[16];
    snprintf(want, sizeof(want), "0.0.%04x", (unsigned int) strtoul(vdev_hex, NULL, 16));

    DIR *dir = opendir("/dev");
    if (!dir) return 1;

    struct dirent *entry;
    int in_use = 0;
    while ((entry = readdir(dir)) != NULL) {
        int match = 0;
        for (size_t p = 0; p < sizeof(dev_prefixes) / sizeof(dev_prefixes[0]); p++) {
            if (strncmp(entry->d_name, dev_prefixes[p], strlen(dev_prefixes[p])) == 0) {
                match = 1;
                break;
            }
        }
        if (!match) continue;

        char sys_path[PATH_MAX], resolved[PATH_MAX];
        snprintf(sys_path, sizeof(sys_path), "/sys/class/" TAPE_SYSFS_CLASS "/%s", entry->d_name);

        ssize_t len = readlink(sys_path, resolved, sizeof(resolved) - 1);
        if (len <= 0) continue;
        resolved[len] = '\0';

        if (strstr(resolved, want)) {
            in_use = 1;
            break;
        }
    }
    closedir(dir);
    return !in_use;
}

char *resolve_device_path_for_vdev_prefix(const char *vdev_hex, const char *prefix) {
    char want[16];
    snprintf(want, sizeof(want), "0.0.%04x", (unsigned int) strtoul(vdev_hex, NULL, 16));

    DIR *dir = opendir("/dev");
    if (!dir) return NULL;

    struct dirent *entry;
    char *result = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, prefix, strlen(prefix)) != 0) continue;

        char sys_path[PATH_MAX], resolved[PATH_MAX];
        snprintf(sys_path, sizeof(sys_path), "/sys/class/" TAPE_SYSFS_CLASS "/%s", entry->d_name);

        ssize_t len = readlink(sys_path, resolved, sizeof(resolved) - 1);
        if (len <= 0) continue;
        resolved[len] = '\0';

        if (strstr(resolved, want)) {
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
            result = strdup(path);
            break;
        }
    }
    closedir(dir);
    return result;
}

char *resolve_device_path_for_vdev(const char *vdev_hex) {
    for (size_t p = 0; p < sizeof(dev_prefixes) / sizeof(dev_prefixes[0]); p++) {
        char *path = resolve_device_path_for_vdev_prefix(vdev_hex, dev_prefixes[p]);
        if (path) return path;
    }
    return NULL;
}

char *resolve_primary_device_path_for_vdev(const char *vdev_hex) {
    return resolve_device_path_for_vdev_prefix(vdev_hex, "ntibm");
}

char *resolve_rewind_device_path_for_vdev(const char *vdev_hex) {
    return resolve_device_path_for_vdev_prefix(vdev_hex, "rtibm");
}

char *resolve_vdev_for_device_path(const char *device_path) {
    const char *devname = strrchr(device_path, '/');
    devname = devname ? devname + 1 : device_path;

    char sys_path[PATH_MAX], resolved[PATH_MAX];
    snprintf(sys_path, sizeof(sys_path), "/sys/class/" TAPE_SYSFS_CLASS "/%s", devname);

    ssize_t len = readlink(sys_path, resolved, sizeof(resolved) - 1);
    if (len <= 0) return NULL;
    resolved[len] = '\0';

    const char *p = strstr(resolved, "0.0.");
    if (!p) return NULL;
    p = strstr(p + 4, "0.0.");
    if (!p) return NULL;

    char norm[8];
    snprintf(norm, sizeof(norm), "%.4s", p + 4);
    for (char *q = norm; *q; q++) *q = toupper((unsigned char) *q);
    return strdup(norm);
}

int user_owns_tape_device(const char *vdev_hex, uid_t uid) {
    char *path = resolve_device_path_for_vdev(vdev_hex);
    if (!path) return 0;

    struct stat st;
    int owns = (stat(path, &st) == 0 && st.st_uid == uid);
    free(path);
    return owns;
}

/* ---- vdev locking ------------------------------------------------------------- */

int reserve_vdev_lock(const char *vdev_hex) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s.lock", LOCK_DIR, vdev_hex);

    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd >= 0) {
        char buf[32];
        int n = snprintf(buf, sizeof(buf), "%d\n", getpid());
        if (write(fd, buf, n) < 0) { /* best effort */ }
        return fd;
    }

    if (errno != EEXIST) {
        debug_log("reserve_vdev_lock: open(%s) failed: %s\n", path, strerror(errno));
        return -1;
    }

    FILE *lf = fopen(path, "r");
    if (lf) {
        pid_t owner_pid = 0;
        int got = fscanf(lf, "%d", &owner_pid);
        fclose(lf);
        if (got == 1 && owner_pid > 0 && kill(owner_pid, 0) == -1 && errno == ESRCH) {
            unlink(path);
            return reserve_vdev_lock(vdev_hex);
        }
    }
    return -1;
}

void release_vdev_lock(int fd, const char *vdev_hex) {
    if (fd >= 0) close(fd);
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s.lock", LOCK_DIR, vdev_hex);
    unlink(path);
}

int lock_specific_vdev(const char *vdev_hex) {
    if (!is_vdev_free(vdev_hex)) {
        fprintf(stderr, "Device %s is already in use.\n", vdev_hex);
        return -1;
    }
    int fd = reserve_vdev_lock(vdev_hex);
    if (fd < 0) {
        struct stat st;
        char lockpath[PATH_MAX];
        snprintf(lockpath, sizeof(lockpath), "%s/%s.lock", LOCK_DIR, vdev_hex);
        if (stat(lockpath, &st) == 0) {
            fprintf(stderr, "Device %s is currently reserved by another request.\n"
                             "If you believe this is stale, try 'tape reset'.\n", vdev_hex);
        } else {
            fprintf(stderr, "Unable to reserve device %s: %s "
                             "(check that %s exists and is writable, "
                             "and that this binary is running setuid-root)\n",
                    vdev_hex, strerror(errno), LOCK_DIR);
        }
        return -1;
    }
    if (!is_vdev_free(vdev_hex)) {
        release_vdev_lock(fd, vdev_hex);
        fprintf(stderr, "Device %s became in-use while reserving it.\n", vdev_hex);
        return -1;
    }
    return fd;
}

char *select_free_vdev_and_lock(int *out_lock_fd) {
    for (int v = vdev_min; v <= vdev_max; v++) {
        char vdev_hex[5];
        snprintf(vdev_hex, sizeof(vdev_hex), "%04X", v);

        if (!is_vdev_free(vdev_hex)) continue;

        int fd = reserve_vdev_lock(vdev_hex);
        if (fd < 0) continue;

        if (!is_vdev_free(vdev_hex)) {
            release_vdev_lock(fd, vdev_hex);
            continue;
        }

        *out_lock_fd = fd;
        return strdup(vdev_hex);
    }
    *out_lock_fd = -1;
    return NULL;
}

/* ---- owner-request handoff to the udev helper --------------------------------- */

typedef struct {
    uid_t uid;
    char  mode[16];
    char  volser[16];
    char  retain[16];
} owner_info_t;

int read_owner_info(const char *vdev_hex, owner_info_t *info) {
    memset(info, 0, sizeof(*info));
    info->uid = (uid_t) -1;
    snprintf(info->mode, sizeof(info->mode), "?");
    snprintf(info->volser, sizeof(info->volser), "?");
    snprintf(info->retain, sizeof(info->retain), "0");

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s.owner", OWNER_DIR, vdev_hex);
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[128];
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if      (strncmp(line, "UID=", 4) == 0)    info->uid = (uid_t) atoi(line + 4);
        else if (strncmp(line, "MODE=", 5) == 0)   snprintf(info->mode, sizeof(info->mode), "%.15s", line + 5);
        else if (strncmp(line, "VOLSER=", 7) == 0) snprintf(info->volser, sizeof(info->volser), "%.15s", line + 7);
        else if (strncmp(line, "RETAIN=", 7) == 0) snprintf(info->retain, sizeof(info->retain), "%.15s", line + 7);
    }
    fclose(f);
    return 0;
}

void write_owner_info(const char *vdev_hex, const owner_info_t *info) {
    mkdir(OWNER_DIR, 0700);
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s.owner", OWNER_DIR, vdev_hex);
    FILE *f = fopen(path, "w");
    if (!f) {
        debug_log("Warning: could not create %s: %s\n", path, strerror(errno));
        return;
    }
    fprintf(f, "UID=%d\nMODE=%s\nVOLSER=%s\nRETAIN=%s\n",
            info->uid, info->mode, info->volser, info->retain);
    fclose(f);
    chmod(path, 0600);
}

void remove_owner_request(const char *vdev_hex) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s.owner", OWNER_DIR, vdev_hex);
    unlink(path);
}

int find_owned_vdevs(uid_t uid, char found[][8], int max_found) {
    DIR *dir = opendir(OWNER_DIR);
    if (!dir) return 0;

    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(dir)) != NULL && count < max_found) {
        char *dot = strstr(entry->d_name, ".owner");
        if (!dot) continue;

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", OWNER_DIR, entry->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;

        uid_t file_uid = (uid_t) -1;
        char line[128];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "UID=", 4) == 0) {
                file_uid = (uid_t) atoi(line + 4);
                break;
            }
        }
        fclose(f);

        if (file_uid == uid) {
            size_t vlen = dot - entry->d_name;
            if (vlen >= sizeof(found[0])) vlen = sizeof(found[0]) - 1;
            memcpy(found[count], entry->d_name, vlen);
            found[count][vlen] = '\0';
            count++;
        }
    }
    closedir(dir);
    return count;
}

/*
 * Best-effort, client-side pre-flight check: does any current .owner
 * file already record this volser as mounted (on any vdev, by any
 * user)? This only sees mounts made from this same client machine - a
 * volser mounted from a different Linux guest via the same proxy is
 * invisible here - but it catches the common single-guest case where
 * the CMS Tape Proxy currently hangs until timeout on a MOUNT request
 * for an already-mounted volser, rather than responding promptly with
 * an error. This is a client-side mitigation for a known server-side
 * issue, not a substitute for a proper server-side fix. Returns 1 and
 * fills out_vdev if found, 0 otherwise.
 */
int find_vdev_for_mounted_volser(const char *target_volser, char *out_vdev, size_t out_size) {
    DIR *dir = opendir(OWNER_DIR);
    if (!dir) return 0;

    struct dirent *entry;
    int found = 0;
    while (!found && (entry = readdir(dir)) != NULL) {
        char *dot = strstr(entry->d_name, ".owner");
        if (!dot) continue;

        char vdev[8];
        size_t vlen = dot - entry->d_name;
        if (vlen >= sizeof(vdev)) vlen = sizeof(vdev) - 1;
        memcpy(vdev, entry->d_name, vlen);
        vdev[vlen] = '\0';

        owner_info_t oinfo;
        if (read_owner_info(vdev, &oinfo) != 0) continue;

        if (strcasecmp(oinfo.volser, target_volser) == 0) {
            snprintf(out_vdev, out_size, "%s", vdev);
            found = 1;
        }
    }
    closedir(dir);
    return found;
}

/* ---- group membership ----------------------------------------------------------- */

int user_in_group(const char *username, const char *groupname) {
    struct group *gr = getgrnam(groupname);
    if (!gr) {
        debug_log("Warning: group '%s' does not exist.\n", groupname);
        return 0;
    }

    struct passwd *pwent = getpwnam(username);
    if (pwent && pwent->pw_gid == gr->gr_gid) return 1;

    for (char **m = gr->gr_mem; m && *m; m++)
        if (strcmp(*m, username) == 0) return 1;

    return 0;
}

/* ---- VM guest userid -------------------------------------------------------------- */

char *userid(void) {
    FILE *f = fopen("/proc/sysinfo", "r");
    if (!f) {
        debug_log("Unable to open /proc/sysinfo: %s\n", strerror(errno));
        return NULL;
    }

    char line[256];
    char *result = NULL;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VM00 Name:", 10) == 0) {
            char tag1[16], tag2[16], useridbuf[16];
            if (sscanf(line, "%15s %15s %15s", tag1, tag2, useridbuf) == 3) {
                result = strdup(useridbuf);
            }
            break;
        }
    }
    fclose(f);

    if (!result)
        debug_log("VM00 Name: line not found in /proc/sysinfo\n");

    return result;
}

/* ---- runtime directories ------------------------------------------------------------- */

void ensure_runtime_dirs(void) {
    mkdir("/run/lock", 0755);
    if (mkdir(LOCK_DIR, 0700) != 0 && errno != EEXIST)
        fprintf(stderr, "Warning: could not create %s: %s\n", LOCK_DIR, strerror(errno));
    if (mkdir(OWNER_DIR, 0700) != 0 && errno != EEXIST)
        fprintf(stderr, "Warning: could not create %s: %s\n", OWNER_DIR, strerror(errno));
}

/* ---- device wait -------------------------------------------------------------------- */

int device_ready_for_vdev(const char *vdev_hex, uid_t expect_uid, char *out_path, size_t out_size) {
    char *devpath = resolve_primary_device_path_for_vdev(vdev_hex);
    if (!devpath) return 0;

    struct stat st;
    int ready = 0;
    if (stat(devpath, &st) == 0 && st.st_uid == expect_uid) {
        snprintf(out_path, out_size, "%s", devpath);
        ready = 1;
    }
    free(devpath);
    return ready;
}

char *wait_for_device_by_vdev(const char *vdev_hex, uid_t expect_uid, int timeout_sec) {
    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) { perror("inotify_init1"); return NULL; }

    int wd = inotify_add_watch(fd, "/dev", IN_CREATE | IN_ATTRIB | IN_MOVED_TO);
    if (wd < 0) { perror("inotify_add_watch"); close(fd); return NULL; }

    static char result[PATH_MAX];
    if (device_ready_for_vdev(vdev_hex, expect_uid, result, sizeof(result))) {
        close(fd);
        return strdup(result);
    }

    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    time_t start = time(NULL);

    while (time(NULL) - start < timeout_sec) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

        int sel = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (sel > 0 && FD_ISSET(fd, &rfds)) {
            ssize_t n = read(fd, buf, sizeof(buf));
            (void) n;
        }

        if (device_ready_for_vdev(vdev_hex, expect_uid, result, sizeof(result))) {
            close(fd);
            return strdup(result);
        }
    }

    close(fd);
    return NULL;
}

/*
 * Forward Space File: skip forward past the next tape mark using the
 * driver's own file-marking support (MTFSF).
 */
int fsf_device(const char *vdev_hex, int count) {
    char *devpath = resolve_primary_device_path_for_vdev(vdev_hex);
    if (!devpath) return -1;

    int fd = open(devpath, O_RDONLY);
    if (fd < 0) {
        debug_log("fsf_device: open(%s) failed: %s\n", devpath, strerror(errno));
        free(devpath);
        return -1;
    }

    struct mtop mt = { .mt_op = MTFSF, .mt_count = count };
    int rc = ioctl(fd, MTIOCTOP, &mt);
    if (rc != 0)
        debug_log("fsf_device: MTFSF on %s failed: %s\n", devpath, strerror(errno));

    close(fd);
    free(devpath);
    return rc;
}

/*
 * Position a tape at "first write position" (rewind to load point, then
 * one MTFSF). Note: for a normal mount/attach, this is unnecessary -
 * CMS/attach already leaves the tape here. Used specifically by
 * "tape map" (always, when done cataloging) and "tape scan" (when the
 * requested dsn isn't found), to restore the tape to that same standard
 * position rather than stranding it wherever the walk stopped.
 */
int position_tape_after_vol1(const char *vdev_hex) {
    char *rewind_path = resolve_rewind_device_path_for_vdev(vdev_hex);
    if (!rewind_path) return -1;
    int rfd = open(rewind_path, O_RDONLY);
    if (rfd < 0) { free(rewind_path); return -1; }
    close(rfd);   /* rewind-on-close: tape is now at load point */
    free(rewind_path);

    return fsf_device(vdev_hex, 1);
}

/*
 * Read the VOL1 standard label from a freshly mounted SCRATCH tape to
 * recover its volser. Rewind device opened+closed first to force load
 * point, then the 80-byte VOL1 record is read from the no-rewind device
 * and converted from EBCDIC. Afterward, MTFSF positions past whatever
 * follows VOL1 (nothing, a real HDR1/HDR2, or a placeholder/dummy
 * HDR1-style record laid down by the tape management system that
 * initialized the scratch pool) and its trailing tape mark, restoring
 * the standard "first write position" that was disturbed by the
 * explicit rewind. Returns NULL if VOL1 cannot be read/parsed at all -
 * the caller treats this as a mount failure and detaches the device,
 * rather than proceeding with an unverifiable volser.
 */
char *read_tape_label_volser(const char *vdev_hex) {
    char *rewind_path = resolve_rewind_device_path_for_vdev(vdev_hex);
    if (!rewind_path) return NULL;
    int rfd = open(rewind_path, O_RDONLY);
    if (rfd < 0) { free(rewind_path); return NULL; }
    close(rfd);
    free(rewind_path);

    char *norewind_path = resolve_primary_device_path_for_vdev(vdev_hex);
    if (!norewind_path) return NULL;
    int fd = open(norewind_path, O_RDONLY);
    if (fd < 0) { free(norewind_path); return NULL; }

    unsigned char raw[256];
    ssize_t n = read(fd, raw, sizeof(raw));
    if (n < 10) { close(fd); free(norewind_path); return NULL; }

    iconv_t cd = iconv_open("ASCII", ebcdic_codepage);
    if (cd == (iconv_t) -1) {
        debug_log("read_tape_label_volser: iconv_open(%s) failed: %s\n",
                   ebcdic_codepage, strerror(errno));
        close(fd); free(norewind_path);
        return NULL;
    }

    char ascii[256] = {0};
    char *inbuf = (char *) raw;
    char *outbuf = ascii;
    size_t inleft = (size_t) n;
    size_t outleft = sizeof(ascii) - 1;
    size_t rc = iconv(cd, &inbuf, &inleft, &outbuf, &outleft);
    iconv_close(cd);
    if (rc == (size_t) -1) {
        debug_log("read_tape_label_volser: iconv conversion failed: %s\n", strerror(errno));
        close(fd); free(norewind_path);
        return NULL;
    }

    if (strncmp(ascii, "VOL1", 4) != 0) {
        debug_log("read_tape_label_volser: no VOL1 label found (got: %.4s)\n", ascii);
        close(fd); free(norewind_path);
        return NULL;
    }

    char volser[8] = {0};
    memcpy(volser, ascii + 4, 6);
    trim_whitespace(volser);

    struct mtop mt = { .mt_op = MTFSF, .mt_count = 1 };
    if (ioctl(fd, MTIOCTOP, &mt) != 0) {
        syslog(LOG_WARNING, "MOUNT vdev=%s: failed to position past pre-first-file "
                             "metadata after reading VOL1 label: %s", vdev_hex, strerror(errno));
        debug_log("read_tape_label_volser: MTFSF after VOL1 failed on %s: %s\n",
                   norewind_path, strerror(errno));
    }

    close(fd);
    free(norewind_path);

    if (volser[0] == '\0') return NULL;
    return strdup(volser);
}

/* ---- Standard Label record construction (HDR1/HDR2/EOF1/EOF2) ----------------------
 *
 * Field layout per IBM's published struct definitions
 * (https://www.ibm.com/support/pages/standard-label-format-tapes).
 * HDR1/EOF1 and HDR2/EOF2 share identical field layouts, differing only
 * in the labid ("HDR" vs "EOF"). Every label record (VOL1, HDR1, HDR2,
 * EOF1, EOF2) is EBCDIC text on the tape, converted via ebcdic_codepage.
 * The DATA payload moved by "tape write"/"tape read" is never touched
 * by this conversion - it is opaque binary as far as tape.c is concerned.
 *
 * struct hdr1_label {              struct hdr2_label {
 *   char labid[3];   off 0           char labid[3];  off 0
 *   char labno;      off 3           char labno;     off 3
 *   char filid[17];  off 4           char rcfmt;     off 4
 *   char fstid[6];   off 21          char blkln[5];  off 5
 *   char fscno[4];   off 27          char recln[5];  off 10
 *   char fsqno[4];   off 31          char rsvd1[35]; off 15
 *   char genno[4];   off 35          char boffl[2];  off 50
 *   char gnvno[2];   off 39          char rsvd2[28]; off 52
 *   char crdat[6];   off 41        };                (total 80)
 *   char exdat[6];   off 47
 *   char acces;      off 53
 *   char blkct[6];   off 54
 *   char syscd[13];  off 60
 *   char rsvd1[7];   off 73
 * };                (total 80)
 *
 * fsqno (file sequence number) IS a mandatory field in the record layout
 * (fixed byte positions), but its CONTENT is not relied on for anything
 * functional in this program: scan_or_map_tape() navigates by physically
 * walking labels/tapemarks, never by reading this field back. There is
 * no reliable source for this program to populate it accurately, so it
 * is always written as a constant 0. fscno (file section number) is
 * always 1, since multivolume files are not supported.
 *
 * Tapes initialized by IBM Tape Manager's scratch-pool preparation
 * appear to carry a placeholder record immediately after VOL1 -
 * observed on real hardware as an "HDR1"-labeled record filled with
 * binary zeros rather than proper space-padded/blank fields, with NO
 * matching HDR2, directly followed by a tape mark. This is treated as
 * opaque pre-first-file metadata, not a real file.
 *
 * The intended "write two tape marks then backspace over one"
 * end-of-file convention has been observed on real hardware to NOT
 * reliably collapse - both tape marks can remain physically present, so
 * the true gap between two consecutive files' label groups may be more
 * than one tape mark. scan_or_map_tape()'s forward traversal tolerates
 * this (see skip_to_next_hdr1()). For "tape scan --before", rather than
 * backspacing over a possibly-ambiguous number of tapemarks, the tape
 * is instead backspaced over exactly 2 RECORDS (MTBSR) - the HDR1 and
 * HDR2 just read to identify the match - which is always exactly right
 * regardless of any tapemark-count ambiguity elsewhere on the tape.
 * "tape write --append" applies the same principle: it locates the end
 * by processing every existing file's records explicitly (never
 * guessing at a tapemark count for a nonexistent "next" file) and stops
 * immediately after the last file's EOF2, which our own reader already
 * accepts as a valid position to begin a new HDR1 from.
 *
 * A separate, unresolved item: /dev/btibm<n> is not a character tape
 * device at all - per IBM's own tape driver documentation it is a
 * BLOCK device intended for mounting a filesystem (e.g. ISO9660)
 * written to tape, not for sequential I/O the way ntibm/rtibm are used
 * throughout this program. It therefore lives under /sys/class/block
 * (or /sys/block), not /sys/class/tape390, so the lookup functions
 * below never resolve it - this is known and considered out of scope
 * for now (tabled), not a bug to be fixed opportunistically.
 */

void put_alpha(char *rec, int off, const char *val, int len) {
    memset(rec + off, ' ', len);
    if (!val) return;
    int n = (int) strlen(val);
    if (n > len) n = len;
    memcpy(rec + off, val, n);
}

void put_numeric(char *rec, int off, long val, int len) {
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%0*ld", len, val);
    int tlen = (int) strlen(tmp);
    if (tlen > len)
        memcpy(rec + off, tmp + (tlen - len), len);
    else
        memcpy(rec + off, tmp, len);
}

/*
 * IBM standard-label date field: 1 blank + 2-digit year + 3-digit
 * day-of-year ("yyddd"), 6 chars total.
 *
 * The modulo results are assigned to plain int variables first, which
 * GCC's -Wformat-truncation value-range tracking follows correctly; a
 * (short) cast around the expression directly does NOT reliably narrow
 * the range in this compiler's analysis and should be avoided. The
 * output buffer is sized 12 (well beyond the 7 bytes strictly needed)
 * so no value in the narrowed range can be flagged as an overflow risk.
 */
void format_label_date(time_t t, char *out /* caller provides >= 12 bytes */) {
    struct tm tmv;
    localtime_r(&t, &tmv);
    int yy   = tmv.tm_year % 100;
    int yday = (tmv.tm_yday + 1) % 1000;   /* day-of-year is always 1-366 in practice */
    snprintf(out, 12, " %02d%03d", yy, yday);
}

/*
 * Convert an already-extracted, whitespace-trimmed IBM standard-label
 * date field (5 chars, "yyddd") into "mm/dd/yyyy (yyddd)" for display
 * in "tape map". Years 00-99 are assumed to mean 2000-2099, since any
 * date this program produces or reads is inherently contemporary.
 */
void format_display_date(const char *label_date, char *out, size_t outsize) {
    int yy = 0, ddd = 0;
    if (sscanf(label_date, "%2d%3d", &yy, &ddd) != 2 || ddd < 1) {
        snprintf(out, outsize, "%s", label_date[0] ? label_date : "??????");
        return;
    }

    struct tm tmv;
    memset(&tmv, 0, sizeof(tmv));
    tmv.tm_year = yy + 100;   /* 2000 + yy, expressed as years since 1900 */
    tmv.tm_mon  = 0;
    tmv.tm_mday = ddd;        /* day-of-year; mktime() normalizes this into a real calendar date */
    tmv.tm_hour = 12;         /* avoid DST edge cases */
    if (mktime(&tmv) == (time_t) -1) {
        snprintf(out, outsize, "%.5s", label_date);
        return;
    }

    snprintf(out, outsize, "%02d/%02d/%04d (%02d%03d)",
             tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_year + 1900, yy, ddd);
}

/* Extract a fixed-width field from an already-decoded ASCII 80-byte
 * record, trimmed of whitespace, for display purposes (scan/map). */
void extract_field(const char *rec, int off, int len, char *out, size_t outsize) {
    size_t n = (size_t) len < outsize - 1 ? (size_t) len : outsize - 1;
    memcpy(out, rec + off, n);
    out[n] = '\0';
    trim_whitespace(out);
}

void build_type1_record(char rec[SL_RECORD_LEN], const char *labid3, char labno,
                         const char *dsn, int fscno, long fsqno,
                         const char *retain_days_str, long blkct) {
    memset(rec, ' ', SL_RECORD_LEN);
    put_alpha(rec, 0, labid3, 3);
    rec[3] = labno;
    put_alpha(rec, 4, dsn, 17);             /* filid */
    put_alpha(rec, 21, NULL, 6);            /* fstid - not used */
    put_numeric(rec, 27, fscno, 4);         /* fscno - file section (always 1, single volume) */
    put_numeric(rec, 31, fsqno, 4);         /* fsqno - always 0; see block comment above */
    put_numeric(rec, 35, 0, 4);             /* genno - not used */
    put_numeric(rec, 39, 0, 2);             /* gnvno - not used */

    time_t now = time(NULL);
    char crdat[12], exdat[12];
    format_label_date(now, crdat);
    long retain_days = retain_days_str ? atol(retain_days_str) : 0;
    format_label_date(now + retain_days * 86400, exdat);
    put_alpha(rec, 41, crdat, 6);
    put_alpha(rec, 47, exdat, 6);

    put_alpha(rec, 53, " ", 1);             /* acces - " " = all */
    put_numeric(rec, 54, blkct, 6);         /* blkct - 0 for HDR1 (unknown until write completes),
                                                actual count for EOF1 */
    put_alpha(rec, 60, "LINUXTAPE", 13);    /* syscd - identifies the writing system */
    put_alpha(rec, 73, NULL, 7);            /* rsvd1 */
}

void build_type2_record(char rec[SL_RECORD_LEN], const char *labid3, char labno) {
    memset(rec, ' ', SL_RECORD_LEN);
    put_alpha(rec, 0, labid3, 3);
    rec[3] = labno;
    rec[4] = 'U';                                  /* rcfmt: 'U' - undefined format;
                                                        each block is one opaque record with no
                                                        internal structure, which is the honest
                                                        description of what tape write does. */
    put_numeric(rec, 5, TAPE_BLOCK_SIZE, 5);        /* blkln - max block length used */
    put_numeric(rec, 10, 0, 5);                     /* recln - not meaningful for RECFM=U */
    put_alpha(rec, 15, NULL, 35);                   /* rsvd1 */
    put_numeric(rec, 50, 0, 2);                     /* boffl - no buffer offset */
    put_alpha(rec, 52, NULL, 28);                   /* rsvd2 */
}

/* Convert an 80-byte ASCII record to the configured EBCDIC codepage and
 * write it to fd as a single physical block. */
int write_sl_record(int fd, const char ascii[SL_RECORD_LEN]) {
    iconv_t cd = iconv_open(ebcdic_codepage, "ASCII");
    if (cd == (iconv_t) -1) {
        debug_log("write_sl_record: iconv_open(to %s) failed: %s\n",
                   ebcdic_codepage, strerror(errno));
        return -1;
    }

    char ebcdic[SL_RECORD_LEN];
    char *inbuf = (char *) ascii;
    char *outbuf = ebcdic;
    size_t inleft = SL_RECORD_LEN, outleft = SL_RECORD_LEN;
    size_t rc = iconv(cd, &inbuf, &inleft, &outbuf, &outleft);
    iconv_close(cd);
    if (rc == (size_t) -1 || outleft != 0) {
        debug_log("write_sl_record: iconv conversion failed: %s\n", strerror(errno));
        return -1;
    }

    ssize_t n = write(fd, ebcdic, SL_RECORD_LEN);
    return (n == SL_RECORD_LEN) ? 0 : -1;
}

/* Read one 80-byte SL record from fd, converting EBCDIC->ASCII into
 * ascii_out. Returns 1 on a full record, 0 if a tape mark was hit
 * (zero-length read), -1 on error/short read. */
int read_sl_record(int fd, char ascii_out[SL_RECORD_LEN]) {
    unsigned char raw[SL_RECORD_LEN];
    ssize_t n = read(fd, raw, SL_RECORD_LEN);
    if (n == 0) return 0;
    if (n < 0) return -1;
    if (n != SL_RECORD_LEN) return -1;

    iconv_t cd = iconv_open("ASCII", ebcdic_codepage);
    if (cd == (iconv_t) -1) return -1;
    char *inbuf = (char *) raw;
    char *outbuf = ascii_out;
    size_t inleft = SL_RECORD_LEN, outleft = SL_RECORD_LEN;
    size_t rc = iconv(cd, &inbuf, &inleft, &outbuf, &outleft);
    iconv_close(cd);
    if (rc == (size_t) -1) return -1;
    return 1;
}

int mtfsf_fd(int fd, int count) {
    struct mtop mt = { .mt_op = MTFSF, .mt_count = count };
    return ioctl(fd, MTIOCTOP, &mt);
}

int mtbsr_fd(int fd, int count) {
    struct mtop mt = { .mt_op = MTBSR, .mt_count = count };
    return ioctl(fd, MTIOCTOP, &mt);
}

/*
 * Write HDR1 and HDR2 labels for a new file. fscno is always 1 (single
 * volume; no multivolume support). fsqno is always written as 0 - see
 * the block comment above build_type1_record for why.
 */
int write_hdr1_hdr2(int fd, const char *dsn, int fscno, const char *retain_days_str) {
    char rec[SL_RECORD_LEN];
    build_type1_record(rec, "HDR", '1', dsn, fscno, 0, retain_days_str, 0);
    if (write_sl_record(fd, rec) != 0) return -1;
    build_type2_record(rec, "HDR", '2');
    if (write_sl_record(fd, rec) != 0) return -1;
    return 0;
}

/*
 * Write EOF1 and EOF2 trailer labels for a completed file, with the
 * actual block count now known.
 */
int write_eof1_eof2(int fd, const char *dsn, int fscno,
                     const char *retain_days_str, long blkct) {
    char rec[SL_RECORD_LEN];
    build_type1_record(rec, "EOF", '1', dsn, fscno, 0, retain_days_str, blkct);
    if (write_sl_record(fd, rec) != 0) return -1;
    build_type2_record(rec, "EOF", '2');
    if (write_sl_record(fd, rec) != 0) return -1;
    return 0;
}

/*
 * Skip forward from immediately after EOF2 to the next file's HDR1,
 * tolerating more than one consecutive tape mark between files (see the
 * block comment above build_type1_record). Returns 1 if another HDR1
 * was found (its content is left in rec_out, already consumed - i.e.
 * the caller should NOT call read_sl_record again for it), 0 if no more
 * files (ran out of tries, or hit unrecorded/blank tape - a read error
 * this close to a run of tape marks is treated as normal end-of-data,
 * not a hard failure), -1 on an unexpected record type.
 */
int skip_to_next_hdr1(int fd, char rec_out[SL_RECORD_LEN]) {
    for (int tries = 0; tries < 5; tries++) {
        int r = read_sl_record(fd, rec_out);
        if (r == 1) {
            if (strncmp(rec_out, "HDR", 3) == 0 && rec_out[3] == '1')
                return 1;
            debug_log("skip_to_next_hdr1: expected HDR1, got unexpected record content\n");
            return -1;
        }
        if (r < 0) {
            debug_log("skip_to_next_hdr1: read error near end of recorded data "
                       "(treated as end of tape content): %s\n", strerror(errno));
            return 0;
        }
        /* r == 0: another tape mark; loop and try again. */
    }
    return 0;   /* several consecutive marks with nothing behind them */
}

/*
 * Walk a mounted SL tape's file label groups starting from VOL1, either
 * searching for a specific dsn (tape scan, target_dsn != NULL, matched
 * case-insensitively) or cataloging every file found (tape map,
 * target_dsn == NULL, is_map=1).
 *
 * After VOL1, a single MTFSF skips whatever pre-first-file metadata
 * occupies the region up to the first tape mark. From there, each file
 * is: HDR1, HDR2, tape mark, DATA, tape mark, EOF1, EOF2, then one or
 * more tape marks before the next file's HDR1 (see skip_to_next_hdr1()).
 * The "BLOCKS" figure shown by "tape map" is EOF1's real block count,
 * not HDR2's fixed max-block-size field.
 *
 * When scanning (target_dsn set), "occurrence" (1-based) selects which
 * match to stop at, so tapes with repeated dataset names can be
 * navigated to a specific instance - out_matches_seen, if non-NULL, is
 * set to the number of matches actually encountered by the time the
 * function returns.
 *
 * out_file_count, if non-NULL, is set to the total number of files
 * fully walked regardless of dsn matching - used by
 * position_tape_for_append() to count existing files on the tape
 * (called with target_dsn == NULL, so no match is ever found and the
 * function walks the entire tape before returning).
 *
 * On reaching the desired occurrence:
 *   before == 0 -> cross the tapemark after HDR2, positioned at DATA,
 *                  ready for "tape read".
 *   before == 1 -> backspace exactly 2 records (the HDR1/HDR2 just
 *                  read), positioned back at HDR1, ready for
 *                  "tape write" to overwrite this file (and everything
 *                  physically after it).
 * scan+not-found, or map -> repositioned to first write position.
 *
 * Returns 1 if the desired occurrence was found (scan only), 0 if not
 * (scan) / always (map or NULL target_dsn), -1 on I/O error.
 */
int scan_or_map_tape(const char *vdev_hex, const char *target_dsn, int is_map,
                      int before, int occurrence, int *out_matches_seen,
                      int *out_file_count) {
    if (out_matches_seen) *out_matches_seen = 0;
    if (out_file_count) *out_file_count = 0;

    char *rewind_path = resolve_rewind_device_path_for_vdev(vdev_hex);
    if (!rewind_path) return -1;
    int rfd = open(rewind_path, O_RDONLY);
    if (rfd < 0) { free(rewind_path); return -1; }
    close(rfd);
    free(rewind_path);

    char *norewind_path = resolve_primary_device_path_for_vdev(vdev_hex);
    if (!norewind_path) return -1;
    int fd = open(norewind_path, O_RDONLY);
    if (fd < 0) { free(norewind_path); return -1; }

    char rec[SL_RECORD_LEN];
    int r = read_sl_record(fd, rec);
    if (r != 1 || strncmp(rec, "VOL1", 4) != 0) {
        debug_log("scan_or_map_tape: expected VOL1, did not find it\n");
        close(fd);
        free(norewind_path);
        return -1;
    }

    if (mtfsf_fd(fd, 1) != 0) {
        debug_log("scan_or_map_tape: failed to position past pre-first-file "
                   "metadata after VOL1: %s\n", strerror(errno));
        close(fd);
        free(norewind_path);
        return -1;
    }

    if (is_map)
        printf("%-4s %-17s %-19s  %-19s  %-6s\n",
               "FILE", "DSN", "CREATED   (Julian)", "EXPIRES   (Julian)", "BLOCKS");

    int found = 0;
    int file_number = 1;
    int matches_seen = 0;
    int files_processed = 0;
    int have_pending_hdr1 = 0;

    while (1) {
        if (!have_pending_hdr1) {
            r = read_sl_record(fd, rec);
            if (r == 0) break;   /* no HDR1 at all: empty (post-metadata) tape */
            if (r != 1) {
                debug_log("scan_or_map_tape: I/O error reading label\n");
                close(fd); free(norewind_path);
                return -1;
            }
        }
        have_pending_hdr1 = 0;

        if (strncmp(rec, "HDR", 3) != 0 || rec[3] != '1') {
            debug_log("scan_or_map_tape: expected HDR1, got unexpected record\n");
            break;
        }

        char dsn[18], crdat[7], exdat[7];
        extract_field(rec, 4, 17, dsn, sizeof(dsn));
        extract_field(rec, 41, 6, crdat, sizeof(crdat));
        extract_field(rec, 47, 6, exdat, sizeof(exdat));

        r = read_sl_record(fd, rec);
        if (r != 1 || strncmp(rec, "HDR", 3) != 0 || rec[3] != '2') {
            debug_log("scan_or_map_tape: expected HDR2 after HDR1\n");
            close(fd); free(norewind_path);
            return -1;
        }

        int is_match = (target_dsn && strcasecmp(dsn, target_dsn) == 0);
        if (is_match) matches_seen++;

        if (is_match && matches_seen == occurrence) {
            if (before) {
                /* Back up exactly over the HDR1 and HDR2 records just
                 * read, landing precisely at HDR1's start regardless of
                 * any tapemark-count ambiguity elsewhere on the tape. */
                if (mtbsr_fd(fd, 2) != 0) {
                    debug_log("scan_or_map_tape: failed to backspace to HDR1 for write: %s\n",
                               strerror(errno));
                    close(fd); free(norewind_path);
                    return -1;
                }
            } else {
                /* Position at start of DATA: cross the tapemark after HDR2. */
                if (mtfsf_fd(fd, 1) != 0) {
                    debug_log("scan_or_map_tape: failed to position past HDR2 tapemark: %s\n",
                               strerror(errno));
                    close(fd); free(norewind_path);
                    return -1;
                }
            }
            found = 1;
            close(fd);
            free(norewind_path);
            if (out_matches_seen) *out_matches_seen = matches_seen;
            if (out_file_count) *out_file_count = files_processed + 1;
            return 1;
        }

        /* Not the desired occurrence (either not a match, or a match
         * but not yet the Nth one, or cataloging for map): skip past
         * DATA to reach EOF1 - two tapemarks crossed (after-HDR2,
         * after-DATA) from the current position (right after HDR2). */
        char blkct_s[8];
        snprintf(blkct_s, sizeof(blkct_s), "?");
        if (mtfsf_fd(fd, 2) != 0) {
            debug_log("scan_or_map_tape: failed to position past DATA to EOF1\n");
            break;
        }
        r = read_sl_record(fd, rec);
        if (r == 1 && strncmp(rec, "EOF", 3) == 0 && rec[3] == '1') {
            extract_field(rec, 54, 6, blkct_s, sizeof(blkct_s));
        } else {
            debug_log("scan_or_map_tape: expected EOF1 after data "
                       "(file may not have been written by tape write)\n");
        }

        if (is_map) {
            char crdat_disp[24], exdat_disp[24];
            format_display_date(crdat, crdat_disp, sizeof(crdat_disp));
            format_display_date(exdat, exdat_disp, sizeof(exdat_disp));
            printf("%-4d %-17s %-19s  %-19s  %-6s\n",
                   file_number, dsn, crdat_disp, exdat_disp, blkct_s);
        }

        /* Consume EOF2 (best effort - not fatal if this isn't literally
         * EOF2; we still attempt to find the next file). */
        read_sl_record(fd, rec);

        files_processed++;

        int nr = skip_to_next_hdr1(fd, rec);
        if (nr == 1) {
            have_pending_hdr1 = 1;
            file_number++;
            continue;
        } else if (nr == 0) {
            break;
        } else {
            close(fd); free(norewind_path);
            return -1;
        }
    }

    close(fd);
    free(norewind_path);

    if (position_tape_after_vol1(vdev_hex) != 0) {
        debug_log("scan_or_map_tape: failed to reposition tape after scan/map\n");
    }

    if (out_matches_seen) *out_matches_seen = matches_seen;
    if (out_file_count) *out_file_count = files_processed;
    return found;
}

/*
 * Position the tape to append a new file after the last existing one.
 * Two passes: (1) silently count existing files N (also leaves the
 * tape rewound to first-write position, as a side effect of
 * scan_or_map_tape's normal cleanup); (2) walk forward again,
 * processing files 1..N-1 via the same tolerant next-HDR1 logic used
 * elsewhere (safe, since a real next file is known to exist for each),
 * then stop immediately after reading file N's EOF2 without attempting
 * a lookahead for a nonexistent file N+1 - that lookahead is exactly
 * the step that would otherwise consume an unknown, hardware-dependent
 * number of tape marks. If N == 0 (empty tape), the tape is already
 * correctly positioned by pass 1 and nothing further is done.
 */
int position_tape_for_append(const char *vdev_hex) {
    int total_files = 0;
    if (scan_or_map_tape(vdev_hex, NULL, 0, 0, 1, NULL, &total_files) < 0) {
        debug_log("position_tape_for_append: failed to count existing files\n");
        return -1;
    }
    if (total_files == 0) return 0;

    char *rewind_path = resolve_rewind_device_path_for_vdev(vdev_hex);
    if (!rewind_path) return -1;
    int rfd = open(rewind_path, O_RDONLY);
    if (rfd < 0) { free(rewind_path); return -1; }
    close(rfd);
    free(rewind_path);

    char *norewind_path = resolve_primary_device_path_for_vdev(vdev_hex);
    if (!norewind_path) return -1;
    int fd = open(norewind_path, O_RDONLY);
    if (fd < 0) { free(norewind_path); return -1; }

    char rec[SL_RECORD_LEN];
    int r = read_sl_record(fd, rec);
    if (r != 1 || strncmp(rec, "VOL1", 4) != 0) {
        close(fd); free(norewind_path);
        return -1;
    }
    if (mtfsf_fd(fd, 1) != 0) {
        close(fd); free(norewind_path);
        return -1;
    }

    int have_pending_hdr1 = 0;
    for (int i = 1; i <= total_files; i++) {
        if (!have_pending_hdr1) {
            r = read_sl_record(fd, rec);
            if (r != 1 || strncmp(rec, "HDR", 3) != 0 || rec[3] != '1') {
                close(fd); free(norewind_path);
                return -1;
            }
        }
        have_pending_hdr1 = 0;

        r = read_sl_record(fd, rec);
        if (r != 1 || strncmp(rec, "HDR", 3) != 0 || rec[3] != '2') {
            close(fd); free(norewind_path);
            return -1;
        }

        if (mtfsf_fd(fd, 2) != 0) {
            close(fd); free(norewind_path);
            return -1;
        }
        read_sl_record(fd, rec);   /* EOF1, best effort */
        read_sl_record(fd, rec);   /* EOF2, best effort */

        if (i < total_files) {
            int nr = skip_to_next_hdr1(fd, rec);
            if (nr == 1) {
                have_pending_hdr1 = 1;
            } else {
                close(fd); free(norewind_path);
                return -1;
            }
        }
        /* i == total_files: stop here - right after file N's EOF2. */
    }

    close(fd);
    free(norewind_path);
    return 0;
}

/* ---- networking: TCP + TLS -------------------------------------------------------- */

int connect_with_timeout(struct addrinfo *rp, int timeout_sec) {
    int flags, result, sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sock < 0) return -1;

    flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    result = connect(sock, rp->ai_addr, rp->ai_addrlen);
    if (result < 0 && errno != EINPROGRESS) { close(sock); return -1; }
    if (result == 0) return sock;

    fd_set writefds;
    struct timeval tv;
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    result = select(sock + 1, NULL, &writefds, NULL, &tv);
    if (result > 0) {
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) return sock;
    }

    close(sock);
    return -1;
}

int ssl_connect_with_timeout(SSL *ssl_conn, int timeout_sec) {
    time_t start = time(NULL);
    for (;;) {
        int r = SSL_connect(ssl_conn);
        if (r == 1) return 0;

        int err = SSL_get_error(ssl_conn, r);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        int remaining = timeout_sec - (int) (time(NULL) - start);
        if (remaining <= 0) {
            fprintf(stderr, "TLS handshake with %s:%s timed out\n", host, port);
            return -1;
        }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sockfd, &fds);
        struct timeval tv = { .tv_sec = remaining, .tv_usec = 0 };

        int sel = (err == SSL_ERROR_WANT_READ)
                    ? select(sockfd + 1, &fds, NULL, NULL, &tv)
                    : select(sockfd + 1, NULL, &fds, NULL, &tv);
        if (sel <= 0) {
            fprintf(stderr, "TLS handshake with %s:%s timed out\n", host, port);
            return -1;
        }
    }
}

int connect_to_server_tcp(void) {
    struct addrinfo hints, *res, *rp;
    int ret;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((ret = getaddrinfo(host, port, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sockfd = connect_with_timeout(rp, CONNECT_TIMEOUT);
        if (sockfd >= 0) break;
    }
    freeaddrinfo(res);

    if (sockfd < 0) {
        fprintf(stderr, "Unable to connect to CMS Tape Proxy at %s:%s\n", host, port);
        return -1;
    }

    debug_log("Connected to %s:%s (%s mode)\n", host, port, use_tls ? "TLS" : "plaintext");

    if (use_tls) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { ERR_print_errors_fp(stderr); return -1; }

        if (ca_file) {
            if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
                fprintf(stderr, "Failed to load CA file %s\n", ca_file);
                ERR_print_errors_fp(stderr);
                return -1;
            }
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        } else {
            fprintf(stderr,
                "Warning: no ca_file configured; the CMS Tape Proxy's TLS certificate "
                "will NOT be verified. The connection is encrypted but unauthenticated "
                "and vulnerable to interception. Set 'ca_file' in tape.conf (or pass "
                "--ca-file) to enable verification.\n");
        }

        if (certificate && key_file) {
            if (SSL_CTX_use_certificate_file(ctx, certificate, SSL_FILETYPE_PEM) != 1 ||
                SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1 ||
                SSL_CTX_check_private_key(ctx) != 1) {
                fprintf(stderr, "Failed to load client certificate/key (%s / %s)\n",
                        certificate, key_file);
                ERR_print_errors_fp(stderr);
                return -1;
            }
        } else if (certificate || key_file) {
            fprintf(stderr, "Both 'certificate' and 'key_file' must be set together "
                             "for client TLS authentication; ignoring the one given.\n");
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);

        if (ca_file) {
            X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
            X509_VERIFY_PARAM_set1_host(vpm, host, 0);
        }

        if (ssl_connect_with_timeout(ssl, CONNECT_TIMEOUT) != 0) return -1;

        if (ca_file) {
            long verify_result = SSL_get_verify_result(ssl);
            if (verify_result != X509_V_OK) {
                fprintf(stderr, "TLS certificate verification failed: %s\n",
                        X509_verify_cert_error_string(verify_result));
                return -1;
            }
            debug_log("TLS certificate verified against %s\n", ca_file);
        }
    }
    return 0;
}

/* ---- networking: AF_IUCV ----------------------------------------------------------- */

int connect_iucv_with_timeout(int timeout_sec) {
    int fd = socket(AF_IUCV, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket(AF_IUCV)");
        return -1;
    }

    /*
     * AF_IUCV connect() was not reliable in non-blocking mode in
     * testing. IUCV failures are reflected immediately by CP rather
     * than needing an async "still connecting" wait, so there's little
     * practical benefit to non-blocking + select()-based timeout here -
     * the socket is therefore left in its default blocking mode. The
     * fcntl() call and the select()-based timeout logic further down
     * are kept, commented out / effectively unreachable, purely as
     * documentation of the approach that was tried.
     *
     * int flags = fcntl(fd, F_GETFL, 0);
     * fcntl(fd, F_SETFL, flags | O_NONBLOCK);
     */

    struct sockaddr_iucv addr;
    memset(&addr, 0, sizeof(addr));
    addr.siucv_family = AF_IUCV;
    memset(addr.siucv_nodeid, ' ', sizeof(addr.siucv_nodeid));
    set_iucv_field(addr.siucv_user_id, iucv_userid);
    set_iucv_field(addr.siucv_name, iucv_name);

    int result = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
    if (result == 0) return fd;

    if (errno != EINPROGRESS && errno != EAGAIN && errno != EWOULDBLOCK) {
        perror("connect(AF_IUCV)");
        close(fd);
        return -1;
    }

    /*
     * Reachable only if O_NONBLOCK is re-enabled above. With a
     * blocking socket, connect() never returns here - it returns 0 on
     * success or a real error immediately. Kept as documentation of
     * the previously-attempted approach.
     */
    fd_set wfds;
    struct timeval tv;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    result = select(fd + 1, NULL, &wfds, NULL, &tv);
    if (result > 0) {
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) return fd;
        fprintf(stderr, "IUCV connect failed: %s\n", strerror(so_error));
    } else {
        fprintf(stderr, "IUCV connect to %.8s.%.8s timed out\n", iucv_userid, iucv_name);
    }

    close(fd);
    return -1;
}

int connect_to_server(void) {
    if (iucv_flag) {
        sockfd = connect_iucv_with_timeout(CONNECT_TIMEOUT);
        if (sockfd < 0) return -1;
        debug_log("Connected via AF_IUCV to %.8s.%.8s\n", iucv_userid, iucv_name);
        return 0;
    }
    return connect_to_server_tcp();
}

/* ---- send / receive -------------------------------------------------------------- */

int send_line(const char *msg) {
    size_t len = strlen(msg);
    if (use_tls && ssl) return SSL_write(ssl, msg, (int) len) > 0 ? 0 : -1;
    return send(sockfd, msg, len, 0) == (ssize_t) len ? 0 : -1;
}

/*
 * Receive the CMS Tape Proxy's response to a request, reading until
 * the explicit terminator byte (x'00', NUL - identical in EBCDIC and
 * ASCII, so it requires no special handling on the server side to
 * survive EBCDIC->ASCII conversion) is seen or the buffer fills. A
 * multi-line ERROR response - the proxy uses x'25' (EBCDIC LF) as its
 * internal line-split character, which converts cleanly to ASCII '\n'
 * through the standard codepage tables - is returned in full,
 * including embedded newlines, for display to the user. The
 * terminator itself is not included in the returned string.
 */
int recv_response_timeout(char *buf, size_t size, int timeout_sec) {
    size_t total = 0;
    time_t start = time(NULL);

    while (total < size - 1) {
        int remaining_timeout = timeout_sec - (int) (time(NULL) - start);
        if (remaining_timeout <= 0) break;

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        struct timeval tv = { .tv_sec = remaining_timeout, .tv_usec = 0 };

        int sel = select(sockfd + 1, &rfds, NULL, NULL, &tv);
        if (sel <= 0) break;

        unsigned char byte;
        int n = (use_tls && ssl) ? SSL_read(ssl, &byte, 1)
                                  : recv(sockfd, &byte, 1, 0);
        if (n <= 0) break;

        if (byte == RESPONSE_TERMINATOR) {
            buf[total] = '\0';
            return (int) total;
        }
        buf[total++] = (char) byte;
    }

    if (total == 0) return -1;   /* nothing received at all before timeout/EOF */
    buf[total] = '\0';           /* connection closed or buffer full without a terminator */
    return (int) total;
}

/*
 * Parse the CMS Tape Proxy's response to a MOUNT request. Success is
 * an exact "OK" token - the literal response "OK", or "OK" followed by
 * a space or newline and further content (e.g. "OK VOLSER=ABC123").
 * Anything else - most commonly a multi-line ERROR response reflecting
 * a site tape-mount policy or server-side error (may itself span
 * multiple lines) - is a failure; the caller displays the full
 * response text to the user and exits non-zero.
 */
int parse_mount_response(const char *response, char *volser_out, size_t volser_out_size) {
    int is_ok = (strcmp(response, "OK") == 0) ||
                (strncmp(response, "OK ", 3) == 0) ||
                (strncmp(response, "OK\n", 3) == 0);
    if (!is_ok) return -1;

    const char *p = strstr(response, "VOLSER=");
    if (p) {
        p += 7;
        size_t i = 0;
        while (p[i] && p[i] != ' ' && p[i] != '\n' && i < volser_out_size - 1) {
            volser_out[i] = p[i];
            i++;
        }
        volser_out[i] = '\0';
    }
    return 0;
}

/* ---- mount / detach / rewind / fsf / write / read / wtm / scan / map / verify / query / reset */

void do_mount(void) {
    if (!user_in_group(pw->pw_name, REQUIRED_GROUP)) {
        syslog(LOG_NOTICE, "MOUNT DENIED user=%s uid=%d reason=\"not in group %s\"",
               pw->pw_name, pw->pw_uid, REQUIRED_GROUP);
        fprintf(stderr, "Permission denied: '%s' is not a member of group '%s'.\n",
                pw->pw_name, REQUIRED_GROUP);
        exit(EXIT_FAILURE);
    }

    if (strcmp(mode, "READ") != 0 && strcmp(mode, "WRITE") != 0) {
        fprintf(stderr, "Invalid mode '%s' (expected READ or WRITE).\n", mode);
        exit(EXIT_FAILURE);
    }

    int is_scratch = (volser == NULL);
    if (is_scratch) {
        if (mode_explicit && strcmp(mode, "WRITE") != 0) {
            fprintf(stderr, "Scratch tapes must be mounted in WRITE mode.\n");
            exit(EXIT_FAILURE);
        }
        mode = "WRITE";
    }

    {
        char *endp;
        long retain_val = strtol(retain, &endp, 10);
        if (*endp != '\0' || retain_val < 0) {
            fprintf(stderr, "Invalid --retain value '%s' (expected a non-negative integer).\n", retain);
            exit(EXIT_FAILURE);
        }
        if (retention_max > 0 && retain_val > retention_max) {
            fprintf(stderr, "Requested retention of %ld days exceeds the configured "
                             "maximum of %d days.\n", retain_val, retention_max);
            exit(EXIT_FAILURE);
        }
    }

    /* Client-side pre-flight check for a known server-side issue: a
     * MOUNT request for an already-mounted volser currently hangs
     * until timeout instead of failing promptly. Only catches volsers
     * mounted from this same client machine. */
    if (!is_scratch) {
        char existing_vdev[8];
        if (find_vdev_for_mounted_volser(volser, existing_vdev, sizeof(existing_vdev))) {
            char *existing_path = resolve_device_path_for_vdev(existing_vdev);
            syslog(LOG_NOTICE, "MOUNT DENIED user=%s uid=%d volser=%s "
                                "reason=\"already mounted on vdev %s\"",
                   pw->pw_name, pw->pw_uid, volser, existing_vdev);
            fprintf(stderr, "Request denied: Tape %s is already mounted at %s on %s.\n",
                    volser, existing_vdev, existing_path ? existing_path : "(pending)");
            free(existing_path);
            exit(EXIT_FAILURE);
        }
    }

    int lock_fd = -1;
    char *chosen_vdev;

    if (vdev_opt) {
        char norm[8];
        normalize_user_vdev(vdev_opt, norm, sizeof(norm));
        lock_fd = lock_specific_vdev(norm);
        if (lock_fd < 0) exit(EXIT_FAILURE);
        chosen_vdev = strdup(norm);
    } else {
        chosen_vdev = select_free_vdev_and_lock(&lock_fd);
        if (!chosen_vdev) {
            fprintf(stderr, "No free tape device address available in range %04X-%04X.\n",
                    vdev_min, vdev_max);
            exit(EXIT_FAILURE);
        }
    }

    debug_log("Reserved vdev %s (lock fd %d)\n", chosen_vdev, lock_fd);
    g_reserved_vdev = chosen_vdev;
    g_reserved_lock_fd = lock_fd;
    g_mount_confirmed = 0;

    owner_info_t oinfo;
    memset(&oinfo, 0, sizeof(oinfo));
    oinfo.uid = pw->pw_uid;
    snprintf(oinfo.mode, sizeof(oinfo.mode), "%s", mode);
    snprintf(oinfo.volser, sizeof(oinfo.volser), "%s", is_scratch ? "PENDING" : volser);
    snprintf(oinfo.retain, sizeof(oinfo.retain), "%s", retain);
    write_owner_info(chosen_vdev, &oinfo);

    char msg[MAX_BUF];
    if (is_scratch) {
        snprintf(msg, sizeof(msg),
                 "MOUNT SCRATCH MODE=WRITE VDEV=%s RETPD=%s VMUSER=%s LOCALUSER=%s AUTH=%s\n",
                 chosen_vdev, retain, vm_userid ? vm_userid : "", pw->pw_name,
                 cms_password ? cms_password : "");
    } else {
        snprintf(msg, sizeof(msg),
                 "MOUNT VOLSER=%s MODE=%s VDEV=%s RETPD=%s VMUSER=%s LOCALUSER=%s AUTH=%s\n",
                 volser, mode, chosen_vdev, retain, vm_userid ? vm_userid : "", pw->pw_name,
                 cms_password ? cms_password : "");
    }

    if (connect_to_server() != 0) {
        remove_owner_request(chosen_vdev);
        release_vdev_lock(lock_fd, chosen_vdev);
        g_reserved_vdev = NULL;
        exit(EXIT_FAILURE);
    }

    debug_log("Sending: %s", msg);
    if (send_line(msg) != 0) {
        fprintf(stderr, "Failed to send mount request.\n");
        remove_owner_request(chosen_vdev);
        release_vdev_lock(lock_fd, chosen_vdev);
        g_reserved_vdev = NULL;
        disconnect();
        exit(EXIT_FAILURE);
    }

    char response[RESPONSE_BUF_SIZE];
    if (recv_response_timeout(response, sizeof(response), CONNECT_TIMEOUT) <= 0) {
        fprintf(stderr, "No response from CMS Tape Proxy server.\n");
        remove_owner_request(chosen_vdev);
        release_vdev_lock(lock_fd, chosen_vdev);
        g_reserved_vdev = NULL;
        disconnect();
        exit(EXIT_FAILURE);
    }
    debug_log("Received: %s\n", response);

    char assigned_volser[16] = {0};
    if (parse_mount_response(response, assigned_volser, sizeof(assigned_volser)) != 0) {
        char syslog_msg[256];
        snprintf(syslog_msg, sizeof(syslog_msg), "%.255s", response);
        for (char *p = syslog_msg; *p; p++) if (*p == '\n') *p = ' ';

        syslog(LOG_ERR, "MOUNT FAILED user=%s uid=%d vdev=%s reason=\"%s\"",
               pw->pw_name, pw->pw_uid, chosen_vdev, syslog_msg);
        fprintf(stderr, "Mount request failed:\n%s\n", response);
        remove_owner_request(chosen_vdev);
        release_vdev_lock(lock_fd, chosen_vdev);
        g_reserved_vdev = NULL;
        disconnect();
        exit(EXIT_FAILURE);
    }
    disconnect();
    g_mount_confirmed = 1;

    snprintf(oinfo.volser, sizeof(oinfo.volser), "%s", is_scratch ? assigned_volser : volser);
    write_owner_info(chosen_vdev, &oinfo);

    release_vdev_lock(lock_fd, chosen_vdev);
    g_reserved_vdev = NULL;

    char *devpath = wait_for_device_by_vdev(chosen_vdev, pw->pw_uid, timeout_seconds);
    if (!devpath) {
        syslog(LOG_ERR, "MOUNT TIMEOUT user=%s uid=%d vdev=%s "
                         "(CMS mount succeeded but device never became owned)",
               pw->pw_name, pw->pw_uid, chosen_vdev);
        fprintf(stderr, "Timed out waiting for device %s to become available.\n"
                         "The tape may still be attached; check 'tape query', "
                         "and use 'tape reset' if it is stuck.\n", chosen_vdev);
        exit(EXIT_FAILURE);
    }

    char *final_volser;
    if (is_scratch) {
        /* Also positions the tape at first write position as a side
         * effect. If VOL1 cannot be read at all, treat as a mount
         * failure: detach automatically rather than report success
         * with an unverifiable volser. */
        final_volser = read_tape_label_volser(chosen_vdev);
        if (!final_volser) {
            syslog(LOG_ERR, "MOUNT FAILED user=%s uid=%d vdev=%s "
                             "reason=\"unable to read VOL1 label from scratch tape\"",
                   pw->pw_name, pw->pw_uid, chosen_vdev);
            fprintf(stderr, "Unable to read the VOL1 label from the scratch tape on "
                             "device %s; detaching.\n", chosen_vdev);
            detach_vdev_silently(chosen_vdev);
            free(devpath);
            exit(EXIT_FAILURE);
        }
        snprintf(oinfo.volser, sizeof(oinfo.volser), "%s", final_volser);
        write_owner_info(chosen_vdev, &oinfo);
    } else {
        /* Existing volser (READ or WRITE): CMS/attach already leaves the
         * tape positioned just after the first tape mark - no explicit
         * positioning needed here. */
        final_volser = strdup(volser);
    }

    if (strcmp(mode, "WRITE") == 0) {
        long retain_days = atol(retain);
        printf("Tape %s mounted on %s as %s (mode-WRITE, retention %s %s)\n",
               final_volser, chosen_vdev, devpath, retain, day_word(retain_days));
    } else {
        printf("Tape %s mounted on %s as %s (mode-READ)\n",
               final_volser, chosen_vdev, devpath);
    }

    syslog(LOG_INFO, "MOUNT user=%s uid=%d vdev=%s volser=%s mode=%s retain=%s device=%s",
           pw->pw_name, pw->pw_uid, chosen_vdev, final_volser, mode, retain, devpath);

    free(final_volser);
    free(devpath);
    free(chosen_vdev);
}

int resolve_target_vdev(char *norm_vdev, size_t norm_size) {
    if (vdev_opt) {
        normalize_user_vdev(vdev_opt, norm_vdev, norm_size);
        return 0;
    }
    if (detach_path) {
        char *v = resolve_vdev_for_device_path(detach_path);
        if (!v) {
            fprintf(stderr, "Unable to determine virtual device for path %s\n", detach_path);
            return -1;
        }
        snprintf(norm_vdev, norm_size, "%s", v);
        free(v);
        return 0;
    }

    char found[8][8];
    int count = find_owned_vdevs(pw->pw_uid, found, 8);
    if (count == 0) {
        fprintf(stderr, "No tape device is currently mounted for user '%s'.\n", pw->pw_name);
        return -1;
    } else if (count > 1) {
        fprintf(stderr, "Multiple tape devices are mounted for user '%s'; specify --dev:\n",
                pw->pw_name);
        for (int i = 0; i < count; i++) fprintf(stderr, "  %s\n", found[i]);
        return -1;
    }
    snprintf(norm_vdev, norm_size, "%s", found[0]);
    return 0;
}

void do_detach(void) {
    char norm_vdev[8] = {0};
    if (resolve_target_vdev(norm_vdev, sizeof(norm_vdev)) != 0)
        exit(EXIT_FAILURE);

    if (!user_owns_tape_device(norm_vdev, pw->pw_uid)) {
        syslog(LOG_NOTICE, "DETACH DENIED user=%s uid=%d vdev=%s reason=\"not owner\"",
               pw->pw_name, pw->pw_uid, norm_vdev);
        fprintf(stderr, "You do not own a tape device at address %s\n", norm_vdev);
        exit(EXIT_FAILURE);
    }

    char bus_id[16];
    snprintf(bus_id, sizeof(bus_id), "0.0.%s", norm_vdev);

    char *argv1[] = { "chccwdev", "-d", bus_id, NULL };
    int rc1 = run_argv(argv1, NULL, 0);
    if (rc1 != 0) debug_log("chccwdev -d returned %d (continuing)\n", rc1);

    char *argv2[] = { "vmcp", "det", norm_vdev, NULL };
    int rc2 = run_argv(argv2, NULL, 0);
    if (rc2 != 0) {
        syslog(LOG_ERR, "DETACH FAILED user=%s uid=%d vdev=%s rc=%d",
               pw->pw_name, pw->pw_uid, norm_vdev, rc2);
        fprintf(stderr, "vmcp det failed for device %s (rc=%d)\n", norm_vdev, rc2);
        exit(EXIT_FAILURE);
    }

    remove_owner_request(norm_vdev);
    syslog(LOG_INFO, "DETACH user=%s uid=%d vdev=%s", pw->pw_name, pw->pw_uid, norm_vdev);
    printf("Tape device %s has been detached.\n", norm_vdev);
}

void do_rewind(void) {
    char norm_vdev[8] = {0};
    if (resolve_target_vdev(norm_vdev, sizeof(norm_vdev)) != 0)
        exit(EXIT_FAILURE);

    if (!user_owns_tape_device(norm_vdev, pw->pw_uid)) {
        syslog(LOG_NOTICE, "REWIND DENIED user=%s uid=%d vdev=%s reason=\"not owner\"",
               pw->pw_name, pw->pw_uid, norm_vdev);
        fprintf(stderr, "You do not own a tape device at address %s\n", norm_vdev);
        exit(EXIT_FAILURE);
    }

    char *rewind_path = resolve_rewind_device_path_for_vdev(norm_vdev);
    if (!rewind_path) {
        fprintf(stderr, "Unable to locate rewind device for device %s\n", norm_vdev);
        exit(EXIT_FAILURE);
    }

    int fd = open(rewind_path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", rewind_path, strerror(errno));
        free(rewind_path);
        exit(EXIT_FAILURE);
    }
    close(fd);

    syslog(LOG_INFO, "REWIND user=%s uid=%d vdev=%s device=%s",
           pw->pw_name, pw->pw_uid, norm_vdev, rewind_path);
    printf("Tape on device %s has been rewound.\n", norm_vdev);
    free(rewind_path);
}

void do_fsf(void) {
    char norm_vdev[8] = {0};
    if (resolve_target_vdev(norm_vdev, sizeof(norm_vdev)) != 0)
        exit(EXIT_FAILURE);

    if (!user_owns_tape_device(norm_vdev, pw->pw_uid)) {
        syslog(LOG_NOTICE, "FSF DENIED user=%s uid=%d vdev=%s reason=\"not owner\"",
               pw->pw_name, pw->pw_uid, norm_vdev);
        fprintf(stderr, "You do not own a tape device at address %s\n", norm_vdev);
        exit(EXIT_FAILURE);
    }

    if (count_opt < 1) {
        fprintf(stderr, "Invalid --count value '%d' (expected a positive integer).\n", count_opt);
        exit(EXIT_FAILURE);
    }

    if (fsf_device(norm_vdev, count_opt) != 0) {
        fprintf(stderr, "Failed to forward space %d tape %s on device %s: %s\n",
                count_opt, mark_word(count_opt), norm_vdev, strerror(errno));
        exit(EXIT_FAILURE);
    }

    syslog(LOG_INFO, "FSF user=%s uid=%d vdev=%s count=%d",
           pw->pw_name, pw->pw_uid, norm_vdev, count_opt);
    printf("Advanced past %d tape %s on device %s.\n", count_opt, mark_word(count_opt), norm_vdev);
}

void do_write(void) {
    char norm_vdev[8] = {0};
    if (resolve_target_vdev(norm_vdev, sizeof(norm_vdev)) != 0)
        exit(EXIT_FAILURE);

    if (!user_owns_tape_device(norm_vdev, pw->pw_uid)) {
        syslog(LOG_NOTICE, "WRITE DENIED user=%s uid=%d vdev=%s reason=\"not owner\"",
               pw->pw_name, pw->pw_uid, norm_vdev);
        fprintf(stderr, "You do not own a tape device at address %s\n", norm_vdev);
        exit(EXIT_FAILURE);
    }

    owner_info_t oinfo;
    if (read_owner_info(norm_vdev, &oinfo) != 0) {
        fprintf(stderr, "Unable to read mount metadata for device %s (try remounting).\n", norm_vdev);
        exit(EXIT_FAILURE);
    }
    if (strcmp(oinfo.mode, "WRITE") != 0) {
        fprintf(stderr, "Device %s was not mounted in WRITE mode; cannot write.\n", norm_vdev);
        exit(EXIT_FAILURE);
    }

    if (write_append) {
        if (position_tape_for_append(norm_vdev) != 0) {
            fprintf(stderr, "Failed to position tape %s for append "
                             "(run with --debug for detail).\n", norm_vdev);
            exit(EXIT_FAILURE);
        }
        debug_log("do_write: positioned for append on vdev %s\n", norm_vdev);
    }

    char derived_dsn[18] = {0};
    const char *dsn;
    if (dsn_opt) {
        dsn = dsn_opt;
    } else if (infile_opt) {
        snprintf(derived_dsn, sizeof(derived_dsn), "%s", filename_base(infile_opt));
        string_to_upper(derived_dsn);
        dsn = derived_dsn;
    } else {
        dsn = oinfo.volser;
    }

    int infd = STDIN_FILENO;
    if (infile_opt) {
        infd = open(infile_opt, O_RDONLY);
        if (infd < 0) {
            fprintf(stderr, "Failed to open input file %s: %s\n", infile_opt, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    char *devpath = resolve_primary_device_path_for_vdev(norm_vdev);
    if (!devpath) {
        fprintf(stderr, "Unable to locate device for %s\n", norm_vdev);
        if (infile_opt) close(infd);
        exit(EXIT_FAILURE);
    }

    int fd = open(devpath, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", devpath, strerror(errno));
        if (infile_opt) close(infd);
        free(devpath);
        exit(EXIT_FAILURE);
    }

    if (write_hdr1_hdr2(fd, dsn, 1, oinfo.retain) != 0) {
        fprintf(stderr, "Failed to write HDR1/HDR2 labels on %s: %s\n", devpath, strerror(errno));
        if (infile_opt) close(infd);
        close(fd); free(devpath);
        exit(EXIT_FAILURE);
    }

    struct mtop mt_sep1 = { .mt_op = MTWEOF, .mt_count = 1 };
    if (ioctl(fd, MTIOCTOP, &mt_sep1) != 0) {
        fprintf(stderr, "Failed to write tape mark after HDR2 on %s: %s\n", devpath, strerror(errno));
        if (infile_opt) close(infd);
        close(fd); free(devpath);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX *mdctx = NULL;
    if (write_extra) {
        mdctx = EVP_MD_CTX_new();
        if (!mdctx || EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
            fprintf(stderr, "Warning: failed to initialize checksum; continuing without it.\n");
            if (mdctx) { EVP_MD_CTX_free(mdctx); mdctx = NULL; }
        }
    }

    char *buf = malloc(TAPE_BLOCK_SIZE);
    if (!buf) {
        fprintf(stderr, "Out of memory\n");
        if (mdctx) EVP_MD_CTX_free(mdctx);
        if (infile_opt) close(infd);
        close(fd); free(devpath);
        exit(EXIT_FAILURE);
    }

    ssize_t n;
    long long total = 0;
    long block_count = 0;
    while ((n = read(infd, buf, TAPE_BLOCK_SIZE)) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(fd, buf + off, n - off);
            if (w < 0) {
                fprintf(stderr, "Write to %s failed: %s\n", devpath, strerror(errno));
                if (mdctx) EVP_MD_CTX_free(mdctx);
                free(buf); if (infile_opt) close(infd); close(fd); free(devpath);
                exit(EXIT_FAILURE);
            }
            off += w;
        }
        total += n;
        block_count++;
        if (mdctx) EVP_DigestUpdate(mdctx, buf, (size_t) n);
        if (write_extra && block_count % 32 == 0)
            fprintf(stderr, "  ... %lld bytes written so far\n", total);
    }
    if (n < 0) {
        fprintf(stderr, "Read from input failed: %s\n", strerror(errno));
        if (mdctx) EVP_MD_CTX_free(mdctx);
        free(buf); if (infile_opt) close(infd); close(fd); free(devpath);
        exit(EXIT_FAILURE);
    }
    free(buf);
    if (infile_opt) close(infd);

    int problems = 0;

    /* Tape mark separates data from EOF1/EOF2. */
    struct mtop mt_sep2 = { .mt_op = MTWEOF, .mt_count = 1 };
    if (ioctl(fd, MTIOCTOP, &mt_sep2) != 0) {
        fprintf(stderr, "Warning: %lld bytes written, but failed to write tape mark "
                         "before EOF1/EOF2 on %s: %s\n", total, devpath, strerror(errno));
        problems = 1;
    } else if (write_eof1_eof2(fd, dsn, 1, oinfo.retain, block_count) != 0) {
        fprintf(stderr, "Warning: %lld bytes written, but failed to write EOF1/EOF2 "
                         "labels on %s: %s\n", total, devpath, strerror(errno));
        problems = 1;
    }

    /* Two tape marks (end-of-data convention, also guarantees a proper
     * EOT marker), then backspace over the second so the tape is left
     * positioned to extend the volume with another file next time. Note:
     * on some drivers this backspace does not reliably collapse the two
     * marks into one - see the block comment above build_type1_record. */
    struct mtop mt_end = { .mt_op = MTWEOF, .mt_count = 2 };
    if (ioctl(fd, MTIOCTOP, &mt_end) != 0) {
        fprintf(stderr, "Warning: failed to write closing tape marks on %s: %s\n",
                devpath, strerror(errno));
        problems = 1;
    } else {
        struct mtop mt_bsf = { .mt_op = MTBSF, .mt_count = 1 };
        if (ioctl(fd, MTIOCTOP, &mt_bsf) != 0) {
            fprintf(stderr, "Warning: failed to reposition tape after closing marks "
                             "on %s: %s\n", devpath, strerror(errno));
            problems = 1;
        }
    }

    close(fd);

    char checksum_hex[EVP_MAX_MD_SIZE * 2 + 1] = {0};
    if (mdctx) {
        if (!problems) {
            unsigned char digest[EVP_MAX_MD_SIZE];
            unsigned int digest_len = 0;
            EVP_DigestFinal_ex(mdctx, digest, &digest_len);
            sha256_hex(digest, digest_len, checksum_hex);
        }
        EVP_MD_CTX_free(mdctx);
    }

    syslog(problems ? LOG_WARNING : LOG_INFO,
           "WRITE user=%s uid=%d vdev=%s device=%s dsn=%s blocks=%ld bytes=%lld "
           "problems=%d append=%d checksum=%s",
           pw->pw_name, pw->pw_uid, norm_vdev, devpath, dsn, block_count, total,
           problems, write_append, checksum_hex[0] ? checksum_hex : "-");

    fprintf(stderr, "%lld bytes written to tape %s on %s as %s (dsn \"%s\", %ld %s)%s\n",
            total, oinfo.volser, norm_vdev, devpath, dsn, block_count, block_word(block_count),
            problems ? " - completed with warnings, see above" : "");
    if (checksum_hex[0])
        fprintf(stderr, "SHA256 checksum: %s\n", checksum_hex);

    free(devpath);

    if (problems) exit(EXIT_FAILURE);
}

void do_read(void) {
    char norm_vdev[8] = {0};
    if (resolve_target_vdev(norm_vdev, sizeof(norm_vdev)) != 0)
        exit(EXIT_FAILURE);

    if (!user_owns_tape_device(norm_vdev, pw->pw_uid)) {
        syslog(LOG_NOTICE, "READ DENIED user=%s uid=%d vdev=%s reason=\"not owner\"",
               pw->pw_name, pw->pw_uid, norm_vdev);
        fprintf(stderr, "You do not own a tape device at address %s\n", norm_vdev);
        exit(EXIT_FAILURE);
    }

    owner_info_t oinfo;
    read_owner_info(norm_vdev, &oinfo);   /* non-fatal if missing; volser defaults to "?" */

    int outfd = STDOUT_FILENO;
    if (outfile_opt) {
        outfd = open(outfile_opt, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (outfd < 0) {
            fprintf(stderr, "Failed to open output file %s: %s\n", outfile_opt, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    char *devpath = resolve_primary_device_path_for_vdev(norm_vdev);
    if (!devpath) {
        fprintf(stderr, "Unable to locate device for %s\n", norm_vdev);
        if (outfile_opt) close(outfd);
        exit(EXIT_FAILURE);
    }

    int fd = open(devpath, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", devpath, strerror(errno));
        if (outfile_opt) close(outfd);
        free(devpath);
        exit(EXIT_FAILURE);
    }

    char *buf = malloc(TAPE_BLOCK_SIZE);
    if (!buf) {
        fprintf(stderr, "Out of memory\n");
        if (outfile_opt) close(outfd);
        close(fd); free(devpath);
        exit(EXIT_FAILURE);
    }

    ssize_t n;
    long long total = 0;
    while ((n = read(fd, buf, TAPE_BLOCK_SIZE)) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(outfd, buf + off, n - off);
            if (w < 0) {
                fprintf(stderr, "Write to output failed: %s\n", strerror(errno));
                free(buf); if (outfile_opt) close(outfd); close(fd); free(devpath);
                exit(EXIT_FAILURE);
            }
            off += w;
        }
        total += n;
    }
    if (n < 0) {
        fprintf(stderr, "Read from %s failed: %s\n", devpath, strerror(errno));
        free(buf); if (outfile_opt) close(outfd); close(fd); free(devpath);
        exit(EXIT_FAILURE);
    }
    free(buf);
    close(fd);
    if (outfile_opt) close(outfd);

    syslog(LOG_INFO, "READ user=%s uid=%d vdev=%s device=%s bytes=%lld",
           pw->pw_name, pw->pw_uid, norm_vdev, devpath, total);
    fprintf(stderr, "%lld bytes read from tape %s on %s as %s (stopped at tape mark/EOF).\n",
            total, oinfo.volser, norm_vdev, devpath);
    free(devpath);
}

void do_wtm(void) {
    char norm_vdev[8] = {0};
    if (resolve_target_vdev(norm_vdev, sizeof(norm_vdev)) != 0)
        exit(EXIT_FAILURE);

    if (!user_owns_tape_device(norm_vdev, pw->pw_uid)) {
        syslog(LOG_NOTICE, "WTM DENIED user=%s uid=%d vdev=%s reason=\"not owner\"",
               pw->pw_name, pw->pw_uid, norm_vdev);
        fprintf(stderr, "You do not own a tape device at address %s\n", norm_vdev);
        exit(EXIT_FAILURE);
    }

    owner_info_t oinfo;
    if (read_owner_info(norm_vdev, &oinfo) != 0) {
        fprintf(stderr, "Unable to read mount metadata for device %s (try remounting).\n", norm_vdev);
        exit(EXIT_FAILURE);
    }
    if (strcmp(oinfo.mode, "WRITE") != 0) {
        fprintf(stderr, "Device %s was not mounted in WRITE mode; cannot write a tape mark.\n", norm_vdev);
        exit(EXIT_FAILURE);
    }

    char *devpath = resolve_primary_device_path_for_vdev(norm_vdev);
    if (!devpath) {
        fprintf(stderr, "Unable to locate device for %s\n", norm_vdev);
        exit(EXIT_FAILURE);
    }

    int fd = open(devpath, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", devpath, strerror(errno));
        free(devpath);
        exit(EXIT_FAILURE);
    }

    struct mtop mt = { .mt_op = MTWEOF, .mt_count = 1 };
    if (ioctl(fd, MTIOCTOP, &mt) != 0) {
        fprintf(stderr, "Failed to write tape mark on %s: %s\n", devpath, strerror(errno));
        close(fd); free(devpath);
        exit(EXIT_FAILURE);
    }
    close(fd);

    syslog(LOG_INFO, "WTM user=%s uid=%d vdev=%s device=%s", pw->pw_name, pw->pw_uid, norm_vdev, devpath);
    printf("Tape mark written on device %s.\n", norm_vdev);
    free(devpath);
}

void do_scan(void) {
    char norm_vdev[8] = {0};
    if (resolve_target_vdev(norm_vdev, sizeof(norm_vdev)) != 0)
        exit(EXIT_FAILURE);

    if (!user_owns_tape_device(norm_vdev, pw->pw_uid)) {
        syslog(LOG_NOTICE, "SCAN DENIED user=%s uid=%d vdev=%s reason=\"not owner\"",
               pw->pw_name, pw->pw_uid, norm_vdev);
        fprintf(stderr, "You do not own a tape device at address %s\n", norm_vdev);
        exit(EXIT_FAILURE);
    }

    if (!dsn_opt) {
        fprintf(stderr, "tape scan requires --dsn <name> (or -f <name>) to search for.\n");
        exit(EXIT_FAILURE);
    }

    if (count_opt < 1) {
        fprintf(stderr, "Invalid --count value '%d' (expected a positive integer).\n", count_opt);
        exit(EXIT_FAILURE);
    }

    int matches_seen = 0;
    int rc = scan_or_map_tape(norm_vdev, dsn_opt, 0, scan_before, count_opt, &matches_seen, NULL);
    if (rc < 0) {
        fprintf(stderr, "Error scanning device %s for dsn '%s' (run with --debug for detail).\n",
                norm_vdev, dsn_opt);
        exit(EXIT_FAILURE);
    }
    if (rc == 0) {
        syslog(LOG_INFO, "SCAN user=%s uid=%d vdev=%s dsn=%s occurrence=%d matches_seen=%d found=0 before=%d",
               pw->pw_name, pw->pw_uid, norm_vdev, dsn_opt, count_opt, matches_seen, scan_before);
        if (matches_seen == 0)
            fprintf(stderr, "Dataset '%s' not found on device %s.\n", dsn_opt, norm_vdev);
        else
            fprintf(stderr, "Only %d %s of dataset '%s' found on device %s; requested occurrence %d.\n",
                    matches_seen, occurrence_word(matches_seen), dsn_opt, norm_vdev, count_opt);
        exit(EXIT_FAILURE);
    }

    syslog(LOG_INFO, "SCAN user=%s uid=%d vdev=%s dsn=%s occurrence=%d found=1 before=%d",
           pw->pw_name, pw->pw_uid, norm_vdev, dsn_opt, count_opt, scan_before);
    if (scan_before)
        printf("Found '%s' (occurrence %d) on device %s; tape positioned to write over this file.\n",
               dsn_opt, count_opt, norm_vdev);
    else
        printf("Found '%s' (occurrence %d) on device %s; tape positioned to read this file.\n",
               dsn_opt, count_opt, norm_vdev);
}

void do_map(void) {
    char norm_vdev[8] = {0};
    if (resolve_target_vdev(norm_vdev, sizeof(norm_vdev)) != 0)
        exit(EXIT_FAILURE);

    if (!user_owns_tape_device(norm_vdev, pw->pw_uid)) {
        syslog(LOG_NOTICE, "MAP DENIED user=%s uid=%d vdev=%s reason=\"not owner\"",
               pw->pw_name, pw->pw_uid, norm_vdev);
        fprintf(stderr, "You do not own a tape device at address %s\n", norm_vdev);
        exit(EXIT_FAILURE);
    }

    int rc = scan_or_map_tape(norm_vdev, NULL, 1, 0, 1, NULL, NULL);
    if (rc < 0) {
        fprintf(stderr, "Error mapping device %s (run with --debug for detail).\n", norm_vdev);
        exit(EXIT_FAILURE);
    }

    syslog(LOG_INFO, "MAP user=%s uid=%d vdev=%s", pw->pw_name, pw->pw_uid, norm_vdev);
}

void do_verify(void) {
    char norm_vdev[8] = {0};
    if (resolve_target_vdev(norm_vdev, sizeof(norm_vdev)) != 0)
        exit(EXIT_FAILURE);

    if (!user_owns_tape_device(norm_vdev, pw->pw_uid)) {
        syslog(LOG_NOTICE, "VERIFY DENIED user=%s uid=%d vdev=%s reason=\"not owner\"",
               pw->pw_name, pw->pw_uid, norm_vdev);
        fprintf(stderr, "You do not own a tape device at address %s\n", norm_vdev);
        exit(EXIT_FAILURE);
    }

    /* --checksum/-C is optional: if omitted, this is a "compute and
     * display" operation rather than a comparison. */

    owner_info_t oinfo;
    read_owner_info(norm_vdev, &oinfo);

    int outfd = -1;
    if (outfile_opt) {
        outfd = open(outfile_opt, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (outfd < 0) {
            fprintf(stderr, "Failed to open output file %s: %s\n", outfile_opt, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    char *devpath = resolve_primary_device_path_for_vdev(norm_vdev);
    if (!devpath) {
        fprintf(stderr, "Unable to locate device for %s\n", norm_vdev);
        if (outfd >= 0) close(outfd);
        exit(EXIT_FAILURE);
    }

    int fd = open(devpath, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", devpath, strerror(errno));
        if (outfd >= 0) close(outfd);
        free(devpath);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx || EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "Failed to initialize checksum computation.\n");
        if (mdctx) EVP_MD_CTX_free(mdctx);
        if (outfd >= 0) close(outfd);
        close(fd); free(devpath);
        exit(EXIT_FAILURE);
    }

    char *buf = malloc(TAPE_BLOCK_SIZE);
    if (!buf) {
        fprintf(stderr, "Out of memory\n");
        EVP_MD_CTX_free(mdctx);
        if (outfd >= 0) close(outfd);
        close(fd); free(devpath);
        exit(EXIT_FAILURE);
    }

    ssize_t n;
    long long total = 0;
    while ((n = read(fd, buf, TAPE_BLOCK_SIZE)) > 0) {
        EVP_DigestUpdate(mdctx, buf, (size_t) n);
        if (outfd >= 0) {
            ssize_t off = 0;
            while (off < n) {
                ssize_t w = write(outfd, buf + off, n - off);
                if (w < 0) {
                    fprintf(stderr, "Write to output failed: %s\n", strerror(errno));
                    free(buf); EVP_MD_CTX_free(mdctx);
                    close(outfd); close(fd); free(devpath);
                    exit(EXIT_FAILURE);
                }
                off += w;
            }
        }
        total += n;
    }
    if (n < 0) {
        fprintf(stderr, "Read from %s failed: %s\n", devpath, strerror(errno));
        free(buf); EVP_MD_CTX_free(mdctx);
        if (outfd >= 0) close(outfd);
        close(fd); free(devpath);
        exit(EXIT_FAILURE);
    }
    free(buf);
    close(fd);
    if (outfd >= 0) close(outfd);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_DigestFinal_ex(mdctx, digest, &digest_len);
    EVP_MD_CTX_free(mdctx);

    char hex[EVP_MAX_MD_SIZE * 2 + 1];
    sha256_hex(digest, digest_len, hex);

    if (!verify_checksum_opt) {
        /* Compute-and-display mode: no comparison, no pass/fail. */
        syslog(LOG_INFO, "VERIFY user=%s uid=%d vdev=%s device=%s bytes=%lld mode=display",
               pw->pw_name, pw->pw_uid, norm_vdev, devpath, total);
        printf("Checksum of tape %s on %s as %s (%lld bytes):\n",
               oinfo.volser, norm_vdev, devpath, total);
        printf("SHA256 checksum: %s\n", hex);
        free(devpath);
        return;
    }

    int match = (strcasecmp(hex, verify_checksum_opt) == 0);

    syslog(match ? LOG_INFO : LOG_WARNING,
           "VERIFY user=%s uid=%d vdev=%s device=%s bytes=%lld match=%d",
           pw->pw_name, pw->pw_uid, norm_vdev, devpath, total, match);

    if (match) {
        printf("Checksum verified: tape %s on %s as %s (%lld bytes).\n",
               oinfo.volser, norm_vdev, devpath, total);
        printf("SHA256 checksum: %s\n", hex);
    } else {
        fprintf(stderr, "Checksum MISMATCH: tape %s on %s as %s\n"
                         "Expected SHA256 checksum: %s\n"
                         "Actual SHA256 checksum:   %s\n",
                oinfo.volser, norm_vdev, devpath, verify_checksum_opt, hex);
    }

    free(devpath);
    if (!match) exit(EXIT_FAILURE);
}

void do_query(void) {
    int is_root = (getuid() == 0);

    DIR *dir = opendir(OWNER_DIR);
    if (!dir) {
        printf("No tapes currently mounted.\n");
        return;
    }

    printf("%-6s %-14s %-10s %-6s %-10s\n", "VDEV", "DEVICE", "USER", "MODE", "VOLSER");

    struct dirent *entry;
    int shown = 0;
    while ((entry = readdir(dir)) != NULL) {
        char *dot = strstr(entry->d_name, ".owner");
        if (!dot) continue;

        char vdev[8];
        size_t vlen = dot - entry->d_name;
        if (vlen >= sizeof(vdev)) vlen = sizeof(vdev) - 1;
        memcpy(vdev, entry->d_name, vlen);
        vdev[vlen] = '\0';

        owner_info_t oinfo;
        if (read_owner_info(vdev, &oinfo) != 0) continue;

        if (!is_root && oinfo.uid != pw->pw_uid) continue;

        struct passwd *owner_pw = getpwuid(oinfo.uid);
        char *devpath = resolve_device_path_for_vdev(vdev);

        printf("%-6s %-14s %-10s %-6s %-10s\n",
               vdev, devpath ? devpath : "(pending)",
               owner_pw ? owner_pw->pw_name : "?", oinfo.mode, oinfo.volser);

        free(devpath);
        shown++;
    }
    closedir(dir);

    if (shown == 0)
        printf(is_root ? "(no tapes currently mounted)\n"
                        : "(you have no tapes currently mounted)\n");
}

/* ---- reset ---------------------------------------------------------------------- */

void detach_vdev_silently(const char *vdev_hex) {
    char bus_id[16];
    snprintf(bus_id, sizeof(bus_id), "0.0.%s", vdev_hex);

    char *argv1[] = { "chccwdev", "-d", bus_id, NULL };
    run_argv(argv1, NULL, 0);

    char *argv2[] = { "vmcp", "det", (char *) vdev_hex, NULL };
    int rc = run_argv(argv2, NULL, 0);
    debug_log("detach_vdev_silently: vmcp det %s rc=%d\n", vdev_hex, rc);

    remove_owner_request(vdev_hex);
    release_vdev_lock(-1, vdev_hex);

    syslog(LOG_INFO, "RESET vdev=%s", vdev_hex);
}

int collect_vdevs_for_uid(uid_t uid, char found[][8], int max_found) {
    int count = 0;

    for (int v = vdev_min; v <= vdev_max && count < max_found; v++) {
        char vdev_hex[5];
        snprintf(vdev_hex, sizeof(vdev_hex), "%04X", v);
        if (user_owns_tape_device(vdev_hex, uid)) {
            snprintf(found[count], 8, "%s", vdev_hex);
            count++;
        }
    }

    char owner_found[8][8];
    int owner_count = find_owned_vdevs(uid, owner_found, 8);
    for (int i = 0; i < owner_count && count < max_found; i++) {
        int dup = 0;
        for (int j = 0; j < count; j++)
            if (strcmp(found[j], owner_found[i]) == 0) { dup = 1; break; }
        if (!dup) { snprintf(found[count], 8, "%.7s", owner_found[i]); count++; }
    }
    return count;
}

void do_reset(void) {
    if (reset_all && getuid() != 0) {
        fprintf(stderr, "Only root may use 'tape reset --all' (or '-a').\n");
        exit(EXIT_FAILURE);
    }

    if (!reset_all) {
        char found[8][8];
        int count = collect_vdevs_for_uid(pw->pw_uid, found, 8);
        if (count == 0) {
            printf("No tape devices or stale reservations found for user '%s'.\n", pw->pw_name);
            return;
        }
        for (int i = 0; i < count; i++) {
            printf("Resetting device %s...\n", found[i]);
            detach_vdev_silently(found[i]);
        }
        syslog(LOG_NOTICE, "RESET user=%s uid=%d count=%d", pw->pw_name, pw->pw_uid, count);
        printf("Reset complete: %d %s cleared.\n", count, device_word(count));
        return;
    }

    int count = 0;
    for (int v = vdev_min; v <= vdev_max; v++) {
        char vdev_hex[5];
        snprintf(vdev_hex, sizeof(vdev_hex), "%04X", v);

        char *devpath = resolve_device_path_for_vdev(vdev_hex);

        char lockpath[PATH_MAX], ownerpath[PATH_MAX];
        snprintf(lockpath, sizeof(lockpath), "%s/%s.lock", LOCK_DIR, vdev_hex);
        snprintf(ownerpath, sizeof(ownerpath), "%s/%s.owner", OWNER_DIR, vdev_hex);
        struct stat st;
        int has_lock  = (stat(lockpath, &st) == 0);
        int has_owner = (stat(ownerpath, &st) == 0);

        if (devpath || has_lock || has_owner) {
            printf("Resetting device %s...\n", vdev_hex);
            detach_vdev_silently(vdev_hex);
            count++;
        }
        free(devpath);
    }

    syslog(LOG_NOTICE, "RESET --all user=%s uid=%d count=%d", pw->pw_name, pw->pw_uid, count);
    printf("Reset complete: %d %s cleared.\n", count, device_word(count));
}

/* ---- main ------------------------------------------------------------------------- */

int main(int argc, char **argv) {
    setenv("PATH", "/sbin:/usr/sbin:/bin:/usr/bin", 1);

    if (geteuid() != 0) {
        fprintf(stderr,
            "tape: not running with effective uid 0.\n"
            "This program must be installed setuid-root, group tapes:\n"
            "  chown root:tapes %s && chmod 4750 %s\n"
            "and must reside on a filesystem not mounted with 'nosuid'.\n",
            argv[0], argv[0]);
        exit(EXIT_FAILURE);
    }

    openlog(SYSLOG_TAG, LOG_PID, LOG_USER);

    install_signals();
    ensure_runtime_dirs();
    parse_args(argc, argv);

    if (help_flag || !command_mode) {
        show_help();
        closelog();
        return help_flag ? 0 : 1;
    }

    if (!mode)   mode   = strdup("READ");
    if (volser) string_to_upper(volser);
    string_to_upper(mode);

    parse_config();
    if (no_tls == -1) no_tls = 0;
    if (!ebcdic_codepage) ebcdic_codepage = strdup(DEFAULT_EBCDIC_CODEPAGE);

    if (!retain) retain = strdup(retention_default_cfg ? retention_default_cfg : DEFAULT_RETAIN);

    debug_log("Arguments: command=%s volser=%s mode=%s vdev=%s retain=%s "
               "retention_max=%d iucv=%s (from_cli=%d) tls=%s ebcdic_codepage=%s count=%d dsn=%s "
               "before=%d append=%d extra=%d checksum=%s\n",
               command_mode, volser ? volser : "<scratch>", mode,
               vdev_opt ? vdev_opt : "<auto>", retain, retention_max,
               iucv_flag ? "yes" : "no", iucv_flag_from_cli, no_tls ? "off" : "on", ebcdic_codepage,
               count_opt, dsn_opt ? dsn_opt : "<default>", scan_before, write_append,
               write_extra, verify_checksum_opt ? verify_checksum_opt : "<none>");

    if (iucv_flag) {
        use_tls = 0;
        if (!iucv_userid) {
            fprintf(stderr, "Error: --iucv requires --iucv-userid <VMUSERID> "
                             "(or iucv_userid= in the config file).\n");
            closelog();
            exit(EXIT_FAILURE);
        }
        if (!iucv_name) iucv_name = strdup(DEFAULT_IUCV_NAME);
    } else {
        use_tls = !no_tls;
        if (!host) host = strdup(DEFAULT_HOST);
        if (!port) port = strdup(DEFAULT_PORT);
    }

    uid_t uid = getuid();
    pw = getpwuid(uid);
    if (!pw) { perror("getpwuid"); closelog(); exit(EXIT_FAILURE); }

    vm_userid = userid();
    if (vm_userid) debug_log("VM guest userid: %s\n", vm_userid);
    else debug_log("VM guest userid: <unavailable>\n");

    if (strcmp(command_mode, "mount") == 0) {
        do_mount();
    } else if (strcmp(command_mode, "detach") == 0 || strcmp(command_mode, "det") == 0) {
        do_detach();
    } else if (strcmp(command_mode, "rewind") == 0 || strcmp(command_mode, "rew") == 0) {
        do_rewind();
    } else if (strcmp(command_mode, "fsf") == 0) {
        do_fsf();
    } else if (strcmp(command_mode, "write") == 0) {
        do_write();
    } else if (strcmp(command_mode, "read") == 0) {
        do_read();
    } else if (strcmp(command_mode, "wtm") == 0) {
        do_wtm();
    } else if (strcmp(command_mode, "scan") == 0) {
        do_scan();
    } else if (strcmp(command_mode, "map") == 0) {
        do_map();
    } else if (strcmp(command_mode, "verify") == 0) {
        do_verify();
    } else if (strcmp(command_mode, "query") == 0) {
        do_query();
    } else if (strcmp(command_mode, "reset") == 0) {
        do_reset();
    } else {
        fprintf(stderr, "Unknown command '%s' (expected 'mount', 'detach'/'det', "
                         "'rewind'/'rew', 'fsf', 'write', 'read', 'wtm', 'scan', 'map', "
                         "'verify', 'query', or 'reset').\n", command_mode);
        closelog();
        exit(EXIT_FAILURE);
    }

    closelog();
    return 0;
}
