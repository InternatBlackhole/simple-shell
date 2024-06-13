#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

// running mode definitions

// run as an interactive shell.
#define RM_INTER 1
//"be an interpreter"
#define RM_SHELL 2

#define SH_NAME "mysh"

// #define printf(...) dprintf(1, __VA_ARGS__)

#define BI_COMM(command) int command(int argc, char** argv)

static int running_mode = 0;
static int last_exit_status = 0;
static char prompt[9] = SH_NAME;
static char proc_path[256] = "/proc";

typedef int (*builtin)(int argc, char** argv);

char* read_line(char* buffer, int buf_size, int* str_len);
int parse_line(char* line, int line_size,
               char** command, int* argc, char** argv,
               char** inredir, char** outredir, int* bg);
void dispatch(char* command, int argc, char** argv, char* inredir, char* outredir, int bg);
char* process_quote(char* token, char** checkpoint);
pid_t run_program(int argc, char* argv[]);
void sigchld_handler(int signum);

BI_COMM(help);
BI_COMM(status);
BI_COMM(exit_sh);
BI_COMM(name);
BI_COMM(print);
BI_COMM(echo);
BI_COMM(pid);
BI_COMM(ppid);

BI_COMM(dirchange);
BI_COMM(dirwhere);
BI_COMM(dirbase);
BI_COMM(dirmake);
BI_COMM(dirremove);
BI_COMM(dirlist);

BI_COMM(linkhard);
BI_COMM(linksoft);
BI_COMM(linkread);
BI_COMM(linklist);
BI_COMM(unlink_sh);
BI_COMM(rename_sh);
BI_COMM(remove_sh);
BI_COMM(cpcat);

BI_COMM(sysinfo);
BI_COMM(shellinfo);

BI_COMM(proc);
BI_COMM(pids);
BI_COMM(pinfo);
BI_COMM(waitone);
BI_COMM(waitall);

BI_COMM(trap);

BI_COMM(pipes);

const char* builtin_functions[] = {
    "help", "status", "exit", "name", "print", "echo",
    "pid", "ppid", "dirchange", "dirwhere", "dirbase", "dirmake",
    "dirremove", "dirlist", "linkhard", "linksoft", "linkread", "linklist",
    "unlink", "rename", "remove", "cpcat", "sysinfo", "shellinfo",
    "proc", "pids", "pinfo", "waitone", "waitall", "trap", "pipes"};
const int size_builtin_functions = sizeof(builtin_functions) / sizeof(builtin_functions[0]);

const builtin builtin_handles[] = {
    help, status, exit_sh, name, print, echo,
    pid, ppid, dirchange, dirwhere, dirbase, dirmake,
    dirremove, dirlist, linkhard, linksoft, linkread, linklist,
    unlink_sh, rename_sh, remove_sh, cpcat, sysinfo, shellinfo,
    proc, pids, pinfo, waitone, waitall, trap, pipes};

int main(int argc, char** argv) {
    // main function

    // make stdout unbuffered, since stderr is unbuffered
    // because apperantly we have order issues
    setvbuf(stdout, NULL, _IOLBF, 4096);

    int input_type = isatty(STDIN_FILENO);
    int exit_stat = 0;

    if (input_type) {
        // we are a tty, run normally
        running_mode = RM_INTER;
    } else {
        // not a tty, run script mode, and return whatever it does
        running_mode = RM_SHELL;
    }

    struct sigaction action = {0};
    action.sa_handler = sigchld_handler;
    action.sa_flags = SA_NOCLDSTOP | SA_RESTART;  // sa_restart to not interrupt system calls
    int status = sigaction(SIGCHLD, &action, NULL);
    if (status == -1) {
        perror(SH_NAME);
        return 1;
    }

    char in_buffer[1024] = {0};
    while (1) {
        // first display the prompt
        if (running_mode == RM_INTER) {
            printf("%s> ", prompt);
            // idk why but it needs to be flushed, what changed? who knows >:|
            fflush(stdout);
        }

        // read input and put into buffer until you reach new line char
        // the parent shell writes to stdin when you press enter
        int input_len = 0;
        char* input = read_line(in_buffer, sizeof(in_buffer), &input_len);

        // only possible when eof, otherwise at least \n
        if (input_len == 0) {
            // there was an error or we read no line
            exit_stat = running_mode != RM_SHELL;
            break;
        }

        // only possible when empty line
        if (input_len == 1)
            continue;

        // delete \n and decrease length
        input[--input_len] = '\0';

        // all of them are set to their default values at start
        char* command = NULL;
        char* args[256] = {0};
        int argc = 256;
        char *in_redir = NULL, *out_redir = NULL;
        int bg = 0;
        status = parse_line(
            input, input_len,
            &command, &argc, args, &in_redir, &out_redir, &bg);

        // command is null if it can't find first token. either it is a space or #
        if (status == 0 && command != NULL) {
            // parsing had no errors
            dispatch(command, argc, args, in_redir, out_redir, bg);
        }

        // clean buffer
        for (size_t i = 0; i < input_len; i++) {
            in_buffer[i] = 0;
        }
    }

    return exit_stat;
}

// find next delim and replaces it with '\0', returning how many chars it skipped
int next_token(char* string, char delim) {
    int index = 0;
    while (string[index] != delim && string[index] != '\0') {
        index++;
    }

    string[index] = '\0';
    return index;
}

int parse_line(char* line, int line_size,
               char** command, int* argc, char** argv,
               char** in_redir, char** out_redir, int* bg) {
    // custom tokenizer for stuff, could be done better but meh :')

    int current_arg = 0;
    for (size_t index = 0; index < line_size; index++) {
        char cur = line[index];

        if (cur == ' ') {
            // just continue
            continue;
        }

        if (cur == '"') {
            // first encounter, just search for next
            // since there can't be user error i just assume it always ends with '"'
            argv[current_arg++] = &line[++index];
            index += next_token(&line[index], '"');
            continue;
        }

        if (cur == '<') {
            char delim = index + 1 < line_size && line[index + 1] == '"' ? '"' : ' ';
            *in_redir = &line[index += (1 + (delim == '"'))];
            index += next_token(&line[index], delim);
            continue;
        }

        if (cur == '>') {
            char delim = index + 1 < line_size && line[index + 1] == '"' ? '"' : ' ';
            *out_redir = &line[index += (1 + (delim == '"'))];
            index += next_token(&line[index], delim);
            continue;
        }

        if (cur == '#') {
            break;
        }

        if (cur == '&') {
            *bg = 1;
            continue;
        }

        // every other char

        int advance = next_token(&line[index], ' ');
        argv[current_arg++] = &line[index];
        index += advance;
    }
    *command = argv[0];
    *argc = current_arg;
    return 0;
}

// a page size, if it is this
static char internal_buffer[256] = {0};
// next position of buffer to read;
static int buffer_position = 0;
// the last read call read this number of bytes
static int last_read_bytes_num = 0;

/*
Reads from stdin until eof or new line
@returns The buffer if it read at least one character (along with \n), else NULL on eof and error
*/
char* read_line(char* buffer, int buf_size, int* str_len) {
    //\n needs to be included in return
    int arg_buffer_pos = 0;
    int run_while = 1;
    // a dangerous loop
    while (run_while) {
        if (last_read_bytes_num == buffer_position) {
            // if we ran out of buffer then we read
            // will block
            last_read_bytes_num = read(STDIN_FILENO, internal_buffer, sizeof(internal_buffer));
            if (last_read_bytes_num <= 0) {
                // 0 if eof, -1 if error, both cases fail
                *str_len = 0;
                return NULL;
            }
            // read read something
            buffer_position = 0;
        }

        if (buffer_position < last_read_bytes_num && arg_buffer_pos < buf_size - 1) {
            // copy char by char
            char cur = internal_buffer[buffer_position++];
            buffer[arg_buffer_pos++] = cur;
            if (cur == '\n') {
                buffer[arg_buffer_pos] = '\0';
                *str_len = arg_buffer_pos;
                return buffer;
            }
        } else if (arg_buffer_pos == buf_size - 1) {
            // we ran out of buffer and didn't encounter a new line char, should not happen
            fputs("Well we are here, out of buffer and no new line :(", stderr);
            buffer[buf_size - 2] = '\n';
            buffer[buf_size - 1] = '\0';
            *str_len = buf_size;
            return buffer;
        }
    }
}

/*
calls the function by name command with paramters argc, argv
*/
void dispatch(char* command, int argc, char** argv, char* inredir, char* outredir, int bg) {
    // first flush stdin and stdout buffers from stream library

    // since i flush the buffers at the beggining i dont need to save the streams
    // just perform the redirection with file descriptors
    int orig_in = -1, orig_out = -1;  // on purpose undefined

    if (inredir != NULL) {
        orig_in = dup(STDIN_FILENO);
        if (orig_in == -1) {
            return;
        }

        int new_in = open(inredir, O_RDONLY);
        if (new_in == -1) {
            close(orig_in);  // close the already duped stdin
            return;
        }

        int fd = dup2(new_in, STDIN_FILENO);  // closes stdin and dups new_in to it
        if (fd == -1) {
            close(orig_in);
            close(new_in);
            return;
        }

        // orig_in is the original stdin we need to then restore
        close(new_in);  // close it cuz we don't need it
    }

    if (outredir != NULL) {
        fflush(stdout);

        orig_out = dup(STDOUT_FILENO);
        if (orig_out == -1) {
            close(orig_in);
            return;
        }

        int new_out = open(outredir, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (new_out == -1) {
            close(orig_in);
            close(orig_out);  // close the already duped stdout
            return;
        }

        int fd = dup2(new_out, STDOUT_FILENO);  // closes stdout and dups new_in to it
        if (fd == -1) {
            close(orig_in);
            close(orig_out);
            close(new_out);
            return;
        }

        // orig_out is the original stdout we need to then restore
        close(new_out);  // close it cuz we don't need it
    }

    builtin internal_comm = run_program;
    for (size_t i = 0; i < size_builtin_functions; i++) {
        if (strcmp(command, builtin_functions[i]) == 0) {
            internal_comm = builtin_handles[i];
            break;
        }
    }

    // nice desecration boi, this could be made nice probably

    int ret_stat = 1;
    if (internal_comm == run_program) {
        // execute external command, returns -1 on error and > 0 on success
        // ret_stat is the pid of child
        ret_stat = internal_comm(argc, argv);

        // we need to wait on the child unless bg is true
        if (bg) {
            ret_stat = 0;
        } else {
            int status = 0;
            pid_t rpid = waitpid(ret_stat, &status, 0);  // wait for this child to treminate
            if (rpid > 0) {
                // no errors, all is successful, get the status of child
                ret_stat = WIFEXITED(status) ? WEXITSTATUS(status) : 1;  // idk should it be 1?
            } else {
                ret_stat = 1;
            }
        }
    } else {
        // if background internal command, apparently every command needs to support it
        if (bg) {
            // needs to get flushed so that child doesn't flush it itself
            // thus child gets empty buffer
            // NULL flushes all open output streams
            fflush(NULL);
            int status = fork();
            if (status == 0) {
                // child
                // discard all buffered data
                int ret = internal_comm(argc, argv);
                exit(ret);
            }
            ret_stat = status == -1;  // 1 if error occures
        } else {
            ret_stat = internal_comm(argc, argv);
            bg++;
        }
    }

    last_exit_status = ret_stat;

    // restore stdin and stdout

    if (inredir != NULL) {
        // closes prevoius stdin (which is a file) and sets it to original fd
        int status = dup2(orig_in, STDIN_FILENO);
        if (status == -1) {
            // report error but still continue since maybe stdout needs to be restored
            perror(SH_NAME);
        }
    }

    if (outredir != NULL) {
        fflush(stdout);

        // closes prevoius stdout (which is a file) and sets it to original fd
        int status = dup2(orig_out, STDOUT_FILENO);
        if (status == -1) {
            perror(SH_NAME);
        }
    }
}

pid_t run_program(int argc, char* argv[]) {
    // redirection is done for us
    // let's get forking
    // flush all open output streams
    fflush(NULL);
    int pid = fork();
    if (pid == 0) {
        // i am child
        // discard all buffered data
        execvp(argv[0], argv);
        // if exec returns then it failed
        perror(argv[0]);
        // close them all so that streams can't be flushed
        exit(1);  // kill child
    }

    return pid;
}

void sigchld_handler(int signum) {
    int pid, status, serrno;
    serrno = errno;
    while (1) {
        pid = waitpid(-1, &status, WNOHANG);
        if (pid < 0 && errno != ECHILD) {
            perror("waitpid");
            break;
        }
        if (pid <= 0)
            break;
    }
    errno = serrno;
}

#define EXIT_ON_ERROR(s, err) \
    if (s == -1) {            \
        int ___serr = errno;  \
        perror(err);          \
        return ___serr;       \
    }

BI_COMM(help) {
    printf("  ");
    for (size_t i = 0; i < size_builtin_functions; i++) {
        printf("%-10s ", builtin_functions[i]);
        if ((i + 1) % 5 == 0)
            printf("\n  ");
    }
    printf("\n");
    return 0;
}

BI_COMM(status) {
    printf("%d\n", last_exit_status);
    return 0;
}

BI_COMM(exit_sh) {
    int code = atoi(argv[1]);
    exit(code);
}

BI_COMM(name) {
    if (argc == 1) {
        printf("%s\n", prompt);
        return 0;
    }
    int len = strlen(argv[1]);
    if (len > 8) {
        return 1;
    }
    strncpy(prompt, argv[1], sizeof(prompt));
    return 0;
}

BI_COMM(print) {
    for (size_t i = 1; i < argc; i++) {
        if (i == argc - 1)
            printf("%s", argv[i]);
        else
            printf("%s ", argv[i]);
    }
    return 0;
}

BI_COMM(echo) {
    print(argc, argv);
    printf("\n");
    return 0;
}

BI_COMM(pid) {
    printf("%d\n", getpid());
    return 0;
}

BI_COMM(ppid) {
    printf("%d\n", getppid());
    return 0;
}

BI_COMM(cpcat) {
    int infd = 0, outfd = 0;
    int status = 0;

    if (argc == 1) {
        // if they fail, then we can't continue
        infd = dup(0);
        EXIT_ON_ERROR(infd, "cpcat")
        outfd = dup(1);
        if (outfd == -1) {
            int serr = errno;
            perror("cpcat");
            close(infd);
            return serr;
        }
    }

    if (argc == 2) {
        // just in file is given
        int fd = open(argv[1], O_RDONLY);
        if (fd < 0) {
            int __serr = errno;
            perror("cpcat");
            return __serr;
        }
        infd = fd;
        outfd = dup(1);
        if (outfd == -1) {
            int __serr = errno;
            perror("cpcat");
            close(fd);
            return __serr;
        }
    }

    if (argc == 3) {
        int fd = strcmp("-", argv[1]) == 0 ? dup(0) : open(argv[1], O_RDONLY);
        EXIT_ON_ERROR(fd, "cpcat")
        infd = fd;

        int fd2 = strcmp("-", argv[2]) == 0 ? dup(1) : open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0766);
        if (fd2 == -1) {
            int serr = errno;
            perror("cpcat");
            close(fd);
            return serr;
        }
        outfd = fd2;
    }

    // status should succeed
    char buf[1 << 16];  // 16bits of buffer
    int run = 1;
    while (run) {
        int bread = read(infd, buf, sizeof(buf));
        if (bread == -1) {
            status = errno;
            perror("cpcat");
            break;
        }
        if (bread == 0) break;  // EOF

        for (int bwrite = 0; bwrite < bread;) {
            int written = write(outfd, &buf[bwrite], bread - bwrite);
            if (written == -1) {
                status = errno;
                perror("cpcat");
                run = 0;
                break;
            }
            bwrite += written;
        }
    }

    // i dont care if closes fail, just execute it
    close(infd);
    close(outfd);
    return status;
}

BI_COMM(dirchange) {
    char* path = argc == 1 ? "/" : argv[1];
    int status = chdir(path);
    EXIT_ON_ERROR(status, "dirchange")
    return 0;
}

BI_COMM(dirwhere) {
    char buf[256];
    char* path = getcwd(buf, sizeof(buf));
    if (path == NULL) {
        perror("dirwhere");
        return errno;
    }
    printf("%s\n", path);
    return 0;
}

BI_COMM(dirbase) {
    char buf[256];
    char* path = getcwd(buf, sizeof(buf));
    if (path == NULL) {
        perror("dirbase");
        return errno;
    }
    printf("%s\n", basename(path));
    return 0;
}

BI_COMM(dirmake) {
    int stat = mkdir(argv[1], 0766);
    EXIT_ON_ERROR(stat, "dirmake")
    return 0;
}

BI_COMM(dirremove) {
    int stat = rmdir(argv[1]);
    EXIT_ON_ERROR(stat, "dirremove");
    return 0;
}

BI_COMM(dirlist) {
    char* path = ".";
    if (argc > 1) {
        path = argv[1];
    }

    DIR* dir;
    struct dirent* en;
    dir = opendir(path);

    if (dir == NULL) {
        perror("dirlist");
        return errno;
    }

    errno = 0;
    en = readdir(dir);
    if (en != NULL)
        printf("%s", en->d_name);
    while (en = readdir(dir)) {
        printf("  %s", en->d_name);
    }
    printf("\n");
    // NULL was returned, errno should be 0 if no error happened
    if (errno != 0) {
        closedir(dir);
        perror("dirlist");
        return errno;
    }
    closedir(dir);
    return 0;
}

BI_COMM(linkhard) {
    char *dest = argv[1], *name = argv[2];
    int status = link(dest, name);
    EXIT_ON_ERROR(status, "linkhard")
    return 0;
}

BI_COMM(linksoft) {
    char *dest = argv[1], *name = argv[2];
    int status = symlink(dest, name);
    EXIT_ON_ERROR(status, "symlink")
    return 0;
}

BI_COMM(linkread) {
    char buf[512] = {0};
    ssize_t val = readlink(argv[1], buf, sizeof(buf) - 1);
    EXIT_ON_ERROR(val, "readlink")
    // buf[val] = 0;
    printf("%s\n", buf);
    return 0;
}

BI_COMM(linklist) {
    struct stat fil = {};
    int status = lstat(argv[1], &fil);
    EXIT_ON_ERROR(status, "linklist")

    DIR* dir;
    struct dirent* en;
    dir = opendir(".");

    if (dir == NULL) {
        perror("linklist");
        return errno;
    }

    errno = 0;
    while ((en = readdir(dir)) != NULL) {
        if (en->d_ino == fil.st_ino) {
            printf("%s  ", en->d_name);
        }
    }
    printf("\n");
    // NULL was returned, errno should be 0 if no error happened
    if (errno != 0) {
        closedir(dir);
        perror("linklist");
        return errno;
    }
    closedir(dir);

    return 0;
}

BI_COMM(unlink_sh) {
    int status = unlink(argv[1]);
    EXIT_ON_ERROR(status, "unlink");
    return 0;
}

BI_COMM(rename_sh) {
    int status = rename(argv[1], argv[2]);
    EXIT_ON_ERROR(status, "rename")
    return 0;
}

BI_COMM(remove_sh) {
    int status = remove(argv[1]);
    EXIT_ON_ERROR(status, "remove")
    return 0;
}

BI_COMM(sysinfo) {
    struct utsname info = {};
    int status = uname(&info);
    EXIT_ON_ERROR(status, "sysinfo");
    printf("Sysname: %s\nNodename: %s\nRelease: %s\nVersion: %s\nMachine: %s\n",
           info.sysname, info.nodename, info.release, info.version, info.machine);
    return 0;
}

BI_COMM(shellinfo) {
    printf("Uid: %d\nEUid: %d\nGid: %d\nEGid: %d\n",
           getuid(), geteuid(), getgid(), getegid());
    return 0;
}

BI_COMM(proc) {
    if (argc == 1) {
        puts(proc_path);
        return 0;
    }

    int status = access(argv[1], F_OK | R_OK);
    if (status == -1) {
        // just return 1, no need to say anything
        return 1;
    }

    // path exists, set it
    strncpy(proc_path, argv[1], sizeof(proc_path));
    return 0;
}

BI_COMM(pids) {
    DIR* dir;
    struct dirent* en;
    dir = opendir(proc_path);

    if (dir == NULL) {
        perror("pids");
        return errno;
    }

    errno = 0;
    while ((en = readdir(dir)) != NULL) {
        int pid = atoi(en->d_name);
        // error happend if 0 and there can't be a process with pid 0
        if (pid != 0) {
            // if it can be parsed to an integer then it is a pid
            puts(en->d_name);
        }
    }
    // NULL was returned, errno should be 0 if no error happened
    if (errno != 0) {
        closedir(dir);
        perror("pids");
        return errno;
    }
    closedir(dir);
    return 0;
}

BI_COMM(pinfo) {
    DIR* dir;
    struct dirent* en;
    dir = opendir(proc_path);

    if (dir == NULL) {
        perror("pinfo");
        return errno;
    }

    printf("%5s %5s %6s %s\n", "PID", "PPID", "STANJE", "IME");
    char pathbuf[256];
    errno = 0;
    while ((en = readdir(dir)) != NULL) {
        // error happend if 0 and there can't be a process with pid 0
        if (atoi(en->d_name) == 0) continue;
        // if it can be parsed to an integer then it is a pid
        int s = snprintf(pathbuf, sizeof(pathbuf), "%s/%s/stat", proc_path, en->d_name);
        if (s < 0) {
            puts("You broke me, congrats, please report :)");
            break;
        }
        int fd = open(pathbuf, O_RDONLY);
        EXIT_ON_ERROR(fd, "pinfo");
        char buf[128];  // should be plenty
        char *pid, *ppid, *status, *name;
        char* checkpoint = NULL;

        int r = read(fd, buf, sizeof(buf));
        EXIT_ON_ERROR(r, "pinfo")
        pid = strtok_r(buf, " ", &checkpoint);
        name = strtok_r(NULL, "()", &checkpoint);
        status = strtok_r(NULL, " ", &checkpoint);
        ppid = strtok_r(NULL, " ", &checkpoint);
        printf("%5s %5s %6s %s\n", pid, ppid, status, name);
        close(fd);
    }
    // NULL was returned, errno should be 0 if no error happened
    if (errno != 0) {
        closedir(dir);
        perror("pinfo");
        return errno;
    }
    closedir(dir);
    return 0;
}

BI_COMM(waitone) {
    int pid = -1;
    if (argc > 1) {
        pid = atoi(argv[1]);
    }

    int status = 0;
    pid_t chld = waitpid(pid, &status, 0);
    EXIT_ON_ERROR(chld, "waitone")
    return 0;
}

BI_COMM(waitall) {
    int status = 0;

    while (1) {
        // only wait for terminated children
        pid_t pid = wait(&status);
        if (pid == -1 && errno == ECHILD) {
            // this process has no unterminated children, break loop
            break;
        }
    }
    return 0;
}

char* sig_comms[31] = {0};

void sighandler(int signum) {
    char* comm = sig_comms[signum];
    if (comm == NULL) return;

    int len = strlen(comm);
    char* copy = malloc(len + 1);
    strncpy(copy, comm, len);

    char* command = NULL;
    int argc = 256;
    char* argv[256] = {0};
    char *inredir = NULL, *outredir = NULL;
    int bg = 0;

    int status = parse_line(copy, len, &command, &argc, argv, &inredir, &outredir, &bg);

    dispatch(command, argc, argv, inredir, outredir, bg);

    if (signum == SIGCHLD) {
        sigchld_handler(SIGCHLD);
    }

    free(copy);
}

BI_COMM(trap) {
    if (argc == 2) {
        int com_num = atoi(argv[1]);
        if (com_num == SIGKILL || com_num == SIGSTOP)
            return 0;

        struct sigaction prev = {0};

        int status = sigaction(com_num, NULL, &prev);
        EXIT_ON_ERROR(status, "trap")

        if (com_num == SIGCHLD) {
            // set back to normal child handler
            prev.sa_handler = sigchld_handler;
            status = sigaction(SIGCHLD, &prev, NULL);
            EXIT_ON_ERROR(status, "trap");
        }

        char* old_com = sig_comms[com_num];
        sig_comms[com_num] = NULL;
        if (old_com != NULL)
            free(old_com);
        return 0;
    }

    if (argc == 3) {
        int com_num = atoi(argv[1]);
        if (com_num == SIGKILL || com_num == SIGSTOP)
            return 0;

        char* old_com = sig_comms[com_num];
        if (old_com != NULL)
            free(old_com);
        int len = strlen(argv[2]);
        char* str = malloc(len + 1);
        strncpy(str, argv[2], len);
        sig_comms[com_num] = str;

        struct sigaction action = {0};
        action.sa_handler = sighandler;
        action.sa_flags = SA_NOCLDSTOP | SA_RESTART;  // sa_restart to not interrupt system calls

        int status = sigaction(com_num, &action, NULL);
        EXIT_ON_ERROR(status, "trap")
        return 0;
    }

    return 0;
}

BI_COMM(pipes) {
    int ret_stat = 0;
    // the first process has the same stdin as me
    // the last process has the same stdout as me

    int line[2] = {0};
    ret_stat = pipe(line);
    if (ret_stat == -1) {
        ret_stat = errno;
        perror("pipes");
        return ret_stat;  // don't need to continue if we fail here
    }
    int child_out = line[1], child_in = dup(STDIN_FILENO);
    if (child_in == -1) {
        ret_stat = errno;
        perror("pipes");
        return ret_stat;
    }
    int error = 0;

    pid_t* pids = calloc(argc - 1, sizeof(pid_t));

    // flush output streams before forks
    // flush all output streams
    fflush(NULL);
    for (size_t i = 1; i < argc; i++) {
        char* command = NULL;
        char* args[256] = {0};
        int argnum = 256;
        char *in_redir = NULL, *out_redir = NULL;  // irrelavant for this function
        int bg = 0;                                // irrelavant for this function

        ret_stat = parse_line(argv[i], strlen(argv[i]),
                              &command, &argnum, args, &in_redir, &out_redir, &bg);
        if (ret_stat != 0) {
            // there was an error in parsing
            error = 1;
            break;
        }

        int status = fork();
        if (status == 0) {
            // i am child
            // discard all buffered data

            int fd = dup2(child_in, STDIN_FILENO);
            if (fd == -1) {
                perror("pipes");
                exit(1);
            }
            close(child_in);

            child_out = i == argc - 1 ? dup(STDOUT_FILENO) : child_out;
            fd = dup2(child_out, STDOUT_FILENO);
            if (fd == -1) {
                perror("pipes");
                exit(1);
            }
            close(child_out);
            close(line[0]);
            close(line[1]);

            // here is should see if i need to spin a subshell of myself
            for (size_t i = 0; i < size_builtin_functions; i++) {
                if (strcmp(command, builtin_functions[i]) == 0) {
                    exit(builtin_handles[i](argnum, args));
                }
            }

            execvp(command, args);
            perror(command);
            exit(1);
        }

        if (status == -1) {
            ret_stat = errno;
            perror("pipes");
            error = 1;
            break;
        }

        pids[i - 1] = status;

        close(child_in);
        child_in = line[0];

        ret_stat = pipe(line);
        if (ret_stat == -1) {
            ret_stat = errno;
            perror("pipes");
            error = 1;
            break;
        }

        close(child_out);
        child_out = line[1];
    }

    close(child_in);
    close(child_out);
    close(line[0]);
    close(line[1]);

    if (error) {
        // we kill all the children
        for (size_t i = 0; i < argc - 1; i++) {
            kill(pids[i], SIGTERM);  // just kill even if we fail
        }
    } else {
        // wait for all children
        for (size_t i = 0; i < argc - 1; i++) {
            int procstat = 0;
            int stat = waitpid(pids[i], &procstat, 0);
        }
    }

    free(pids);
    return ret_stat;
}
