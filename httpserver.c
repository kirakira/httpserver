#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define min(x, y) ((x < y) ? x : y)

#define BUFFER_SIZE 16384

#define METHOD_BAD  0
#define METHOD_GET  1
#define METHOD_POST 2
#define METHOD_HEAD 3

#define HTTP_1_0    1
#define HTTP_1_1    2

uint16_t port = 8080, qlen = 5;
#define SERVER_NAME "httpserver/0.1"

#define DEFAULT_FILE_COUNT 4
const char *defaultfile[DEFAULT_FILE_COUNT] = {"index.html", "index.htm", "index.php", "default.php"};
char root[BUFFER_SIZE] = ".";

#define CONTENT_TYPE_COUNT 35
char *contentmap[CONTENT_TYPE_COUNT][2] = {{"htm", "text/html"}, {"html", "text/html"}, {"txt", "text/plain"},
                                            {"c", "text/plain"}, {"cpp", "text/plain"}, {"cc", "text/plain"},
                                            {"pl", "text/plain"}, {"h", "text/plain"}, {"css", "text/css"},
                                            {"gif", "image/gif"}, {"png", "image/x-png"}, {"ief", "image/ief"},
                                            {"jpg", "image/jpeg"}, {"jpeg", "image/jpeg"}, {"jpe", "image/jpeg"},
                                            {"tiff", "image/tiff"}, {"tif", "image/tiff"}, {"bmp", "image/x-ms-bmp"},
                                            {"wav", "audio/x-wav"}, {"mpeg", "video/mpeg"}, {"mpg", "video/mpeg"},
                                            {"mpe", "video/mpeg"}, {"qt", "video/quicktime"}, {"mov", "video/quicktime"},
                                            {"avi", "video/x-msvideo"}, {"ps", "application/postscript"}, {"rtf", "application/rtf"},
                                            {"pdf", "application/pdf"}, {"tex", "application/x-tex"}, {"tar", "application/x-tar"},
                                            {"zip", "application/zip"}, {"bin", "application/octet-stream"}, {"exe", "application/octet-stream"},
                                            {"js", "text/javascript"}, {"sh", "application/x-sh"}};
#define DEFAULT_CONTENT_TYPE "application/octet-stream"

#define PHP_CGI "/usr/bin/php-cgi"

struct header
{
    int method;
    char uri[BUFFER_SIZE];
    char host[BUFFER_SIZE];
    char statusline[BUFFER_SIZE];
    int protocol;
    int code;
    char payload[BUFFER_SIZE];
    int contentlen;
    char contenttype[BUFFER_SIZE];
    char cookie[BUFFER_SIZE];
};

void
usage()
{
    fputs("Usage: httpserver [-p PORT] [-d ROOT_DIR] [-b BACKLOG]\n", stderr);
    fputs("Run a simple HTTP server.\n\n", stderr);
    fputs("PORT - Listen port. Default 8080.\n", stderr);
    fputs("ROOT_DIR - Server root directory. Default current working directory.\n", stderr);
    fputs("BACKLOG - Maximum outstanding connections. Defualt 5.\n", stderr);
    fflush(NULL);
}

int
writeall(int fd, const char *buffer, int size)
{
    int r;
    while (size > 0) {
        r = write(fd, buffer, size);
        if (r < 0)
            return 0;
        else {
            buffer += r;
            size -= r;
        }
    }
    return 1;
}

int
initserver(uint16_t port, int qlen)
{
    int fd;
    int reuse = 1;

    struct sockaddr_in serv_addr;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("error opening socket");
        exit(1);
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0) {
        perror("error set socket option");
        close(fd);
        exit(1);
    }

    memset((char *) &serv_addr, 0, sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(fd, (struct sockaddr *) &serv_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("error binding address");
        close(fd);
        exit(1);
    }

    if (listen(fd, qlen) < 0) {
        perror("error listening");
        close(fd);
        exit(1);
    }
    return fd;
}

int
crlf(const char *str, int len)
{
    int i;
    for (i = 0; i < len - 1; ++i)
        if (str[i] == '\r' && str[i + 1] == '\n')
            return i;
    return -1;
}

int
token(const char *str, int len, int *begin, int *end)
{
    int i, state = 0;
    for (i = 0; i < len; ++i)
        if (str[i] == ' ' || str[i] == '\t') {
            if (state == 1) {
                *end = i;
                return 1;
            }
        } else {
            if (state == 0) {
                *begin = i;
                state = 1;
            }
        }
    if (state == 1) {
        *end = len;
        return 1;
    } else
        return 0;
}

int
responseline(int code, int protocol, char *str, int len)
{
    char *ps;
    if (protocol == HTTP_1_0)
        ps = "HTTP/1.0";
    else if (protocol == HTTP_1_1)
        ps = "HTTP/1.1";
    else
        ps = "";

    if (code == 100)
        return snprintf(str, len, "%s 100 Continue\r\n", ps);
    else if (code == 200)
        return snprintf(str, len, "%s 200 OK\r\n", ps);
    else if (code == 301)
        return snprintf(str, len, "%s 301 Found\r\n", ps);
    else if (code == 302)
        return snprintf(str, len, "%s 302 Moved Permanently\r\n", ps);
    else if (code == 400)
        return snprintf(str, len, "%s 400 Bad Request\r\n", ps);
    else if (code == 403)
        return snprintf(str, len, "%s 403 Forbidden\r\n", ps);
    else if (code == 404)
        return snprintf(str, len, "%s 404 Not Found\r\n", ps);
    else if (code == 414)
        return snprintf(str, len, "%s 414 Request-URI Too Long\r\n", ps);
    else if (code == 501)
        return snprintf(str, len, "%s 501 Not Implemented\r\n", ps);
    else if (code == 505)
        return snprintf(str, len, "%s 505 HTTP Version Not Supported\r\n", ps);
    else
        return snprintf(str, len, "%s 500 Internal Server Error\r\n", ps);
}

void
respond2(int fd, int code, int protocol)
{
    char buffer[BUFFER_SIZE];
    int len;
    time_t now;

    len = responseline(code, protocol, buffer, BUFFER_SIZE);
    writeall(fd, buffer, len);

    if (code != 100) {
        if (protocol == HTTP_1_1) {
            len = snprintf(buffer, BUFFER_SIZE, "Connection: close\r\n");
            writeall(fd, buffer, len);
        }

        now = time(NULL);
        len = strftime(buffer, BUFFER_SIZE,
                "Date: %a, %d %b %Y %H:%M:%S GMT\r\n", gmtime(&now));
        writeall(fd, buffer, len);

        len = snprintf(buffer, BUFFER_SIZE, "Server: %s\r\n", SERVER_NAME);
        writeall(fd, buffer, len);
    }
}

void
respond(int fd, int code, int protocol, const char *res, int reslen, const char *headers)
{
    char buffer[BUFFER_SIZE], buffer2[BUFFER_SIZE];
    int len;

    respond2(fd, code, protocol);

    if (code != 100) {
        if (reslen > 0) {
            len = snprintf(buffer, BUFFER_SIZE, "Content-Length: %d\r\n",
                    reslen);
            writeall(fd, buffer, len);
        } else if (code != 100 && code != 200) {
            len = snprintf(buffer, BUFFER_SIZE, "Content-Type: text/plain\r\n");
            writeall(fd, buffer, len);

            reslen = responseline(code, protocol, buffer2, BUFFER_SIZE);
            res = buffer2 + 9;
            reslen -= 9;
        }

        if (headers)
            writeall(fd, headers, strlen(headers));
    }

    len = snprintf(buffer, BUFFER_SIZE, "\r\n");
    writeall(fd, buffer, len);

    if (res)
        writeall(fd, res, reslen);
}

int
statusline(int fd, const char *buffer, int len, struct header *r)
{
    int begin = 0, end = 0, ok = 1;

    memcpy(r->statusline, buffer, len < sizeof(r->statusline) ? len : sizeof(r->statusline));
    r->code = 200;

    if (token(buffer, len, &begin, &end)) {
        if (end - begin >= 3 && strncmp(buffer + begin, "GET", 3) == 0) {
            r->method = METHOD_GET;
        } else if (end - begin >= 4 && strncmp(buffer + begin, "POST", 4) == 0) {
            r->method = METHOD_POST;
        } else if (end - begin >= 4 && strncmp(buffer + begin, "HEAD", 4) == 0) {
            r->method = METHOD_HEAD;
        } else {
            r->method = METHOD_BAD;
            r->code = 501;
            ok = 0;
        }

        buffer += end;
        len -= end;
        if (token(buffer, len, &begin, &end)) {
            if (end - begin < sizeof(r->uri)) {
                memset(r->uri, 0, sizeof(r->uri));
                strncpy(r->uri, buffer + begin, end - begin);
            } else {
                r->code = 414;
                ok = 0;
            }

            buffer += end;
            len -= end;
            if (token(buffer, len, &begin, &end)) {
                if (end - begin >= 8) {
                    if (strncmp(buffer + begin, "HTTP/1.0", 8) == 0)
                        r->protocol = HTTP_1_0;
                    else if (strncmp(buffer + begin, "HTTP/1.1", 8) == 0)
                        r->protocol = HTTP_1_1;
                    else if (strncmp(buffer + begin, "HTTP/", 5) == 0) {
                        r->code = 505;
                        ok = 0;
                    } else {
                        r->code = 400;
                        ok = 0;
                    }
                } else {
                    r->code = 400;
                    ok = 0;
                }
            } else {
                r->code = 400;
                ok = 0;
            }
        } else {
            r->code = 400;
            ok = 0;
        }
    } else {
        r->code = 400;
        ok = 0;
    }

    return ok;
}

int
header(int fd, const char *buffer, int len, struct header *rq)
{
    if (strlen(buffer) >= 6 && strncmp(buffer, "Host: ", 6) == 0) {
        memset(rq->host, 0, sizeof(rq->host));
        strncpy(rq->host, buffer + 6, len - 6);
    } else if (strlen(buffer) >= 16 && strncmp(buffer, "Content-Length: ", 16) == 0) {
        rq->contentlen = atoi(buffer + 16);
    } else if (strlen(buffer) >= 14 && strncmp(buffer, "Content-Type: ", 14) == 0) {
        memset(rq->contenttype, 0, sizeof(rq->contenttype));
        strncpy(rq->contenttype, buffer + 14, len - 14);
    } else if (strlen(buffer) >= 8 && strncmp(buffer, "Cookie: ", 8) == 0) {
        memset(rq->cookie, 0, sizeof(rq->cookie));
        strncpy(rq->cookie, buffer + 8, len - 8);
    }
    return 1;
}

int
locateresource(const char *uri, char *res, int len, int *resourcelen)
{
    struct stat st;
    char buffer[BUFFER_SIZE];
    int i, pos;

    strcpy(res, root);
    pos = -1;
    for (i = 0; i < strlen(uri); ++i)
        if (uri[i] == '?') {
            pos = i;
            break;
        }
    if (pos == -1)
        strncat(res, uri, len - strlen(res) - 1);
    else
        strncat(res, uri, min(pos, len - strlen(res) - 1));

    if (stat(res, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            if (res[strlen(res) - 1] == '/') {
                for (i = 0; i < DEFAULT_FILE_COUNT; ++i) {
                    memset(buffer, 0, sizeof(buffer));
                    strncpy(buffer, uri, pos == -1 ? BUFFER_SIZE : min(BUFFER_SIZE, pos));
                    strncat(buffer, defaultfile[i], BUFFER_SIZE - strlen(buffer) - 1);
                    if (locateresource(buffer, res, len, resourcelen))
                        return 1;
                }
                return 3;
            } else {
                strncpy(res, uri, len);
                strncat(res, "/", len - strlen(res) - 1);
                return 2;
            }
        } else if (S_ISREG(st.st_mode)) {
            if (resourcelen)
                *resourcelen = st.st_size;
            return 1;
        } else
            return 0;
    } else
        return 0;
}

int
permissible(const char *uri)
{
    int i;
    int level = 0;
    for (i = 0; i + 2 < strlen(uri); ++i)
        if (uri[i] == '/' && uri[i + 1] == '.' && uri[i + 2] == '.') {
            --level;
            if (level < 0)
                return 0;
            i += 2;
        } else if (i != 0 && uri[i] == '/' && uri[i + 1] != '/')
            ++level;
    return 1;
}

int
postfix(const char *filename, char *postfix)
{
    int i, pos = -1;
    for (i = strlen(filename) - 1; i >= 0; --i) {
        if (filename[i] == '.') {
            pos = i;
            break;
        } else if (filename[i] == '/')
            break;
    }
    if (pos == -1)
        return 0;
    else {
        postfix[0] = 0;
        strcat(postfix, filename + i + 1);
        return 1;
    }
}

const char *
contenttype(const char *filename)
{
    int i;
    char pf[BUFFER_SIZE];
    if (!postfix(filename, pf))
        return DEFAULT_CONTENT_TYPE;
    else {
        for (i = 0; i < CONTENT_TYPE_COUNT; ++i)
            if (strcmp(contentmap[i][0], pf) == 0)
                return contentmap[i][1];

        return DEFAULT_CONTENT_TYPE;
    }
}

const char *
querystring(const char *uri)
{
    int i;
    for (i = 0; i < strlen(uri); ++i)
        if (uri[i] == '?')
            return uri + i + 1;
    return NULL;
}

void
php(int socket, const char *script, const char *addr, struct header *rq)
{
    int outfd[2];
    int infd[2];
    int pid;
    char strcontentlen[BUFFER_SIZE], strmethod[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];
    const char *qs;
    int p, r;
    
    pipe(outfd);
    pipe(infd);
    
    if (!(pid = fork())) {
        close(0);
        close(1);
        dup2(outfd[0], 0);
        dup2(infd[1], 1);

        snprintf(strcontentlen, BUFFER_SIZE, "%d", rq->contentlen);
        switch (rq->method) {
            case METHOD_GET:
                strncpy(strmethod, "GET", BUFFER_SIZE);
                break;

            case METHOD_POST:
                strncpy(strmethod, "POST", BUFFER_SIZE);
                break;

            case METHOD_HEAD:
                strncpy(strmethod, "HEAD", BUFFER_SIZE);
                break;

            default:
                strncpy(strmethod, "GET", BUFFER_SIZE);
                break;
        }
        qs = querystring(rq->uri);

        setenv("REDIRECT_STATUS", "1", 1);
        setenv("SERVER_SOFTWARE", SERVER_NAME, 1);
        setenv("CONTENT_LENGTH", strcontentlen, 1);
        setenv("REQUEST_METHOD", strmethod, 1);
        setenv("SCRIPT_FILENAME", script, 1);
        if (qs)
            setenv("QUERY_STRING", qs, 1);
        setenv("REQUEST_URI", rq->uri, 1);
        setenv("HTTP_HOST", rq->host, 1);
        setenv("REMOTE_ADDR", addr, 1);
        if (strlen(rq->contenttype) > 0)
            setenv("CONTENT_TYPE", rq->contenttype, 1);
        else
            setenv("CONTENT_TYPE", "application/x-www-form-urlencoded", 1);
        if (strlen(rq->cookie) > 0)
            setenv("HTTP_COOKIE", rq->cookie, 1);

        write(outfd[1], rq->payload, rq->contentlen);

        execl(PHP_CGI, PHP_CGI, NULL);
    } else {

        close(outfd[0]);
        close(outfd[1]);
        close(infd[1]);

        p = 0;
        do {
            r = read(infd[0], buffer + p, BUFFER_SIZE - p);
            if (r <= 0)
                break;
            p += r;
        } while (crlf(buffer, p) < 0);

        r = crlf(buffer, p);
        if (r >= 12 && strncmp(buffer, "Status: ", 8) == 0) {
            buffer[11] = 0;
            rq->code = atoi(buffer + 8);
            if (rq->code == 0)
                rq->code = 200;
            respond2(socket, rq->code, rq->protocol);
            writeall(socket, buffer + r + 2, p - r - 2);
        } else {
            respond2(socket, rq->code, rq->protocol);
            writeall(socket, buffer, p);
        }

        while ((r = read(infd[0], buffer, BUFFER_SIZE)) > 0) {
            writeall(socket, buffer, r);
        }

        waitpid(pid, 0, 0);
    }
}

void
handlerequest(int fd, const char *addr)
{
    char buffer[BUFFER_SIZE];
    char can_uri[BUFFER_SIZE];
    char filepath[BUFFER_SIZE];
    char headers[BUFFER_SIZE];
    char pf[BUFFER_SIZE];
    int len = 0, ret, begin = 0, p, pbegin = 0, plen = 0;
    int state = 0, filelen;

    int fduri;
    char *uribuffer;
    int tot;

    time_t now;
    
    struct header rq;
    rq.code = 500;
    rq.contentlen = 0;
    memset(rq.contenttype, 0, sizeof(rq.contenttype));
    memset(rq.host, 0, sizeof(rq.host));
    memset(rq.cookie, 0, sizeof(rq.cookie));

    do {
        ret = read(fd, buffer + len, BUFFER_SIZE - len);
        if (ret > 0) {
            len += ret;

            while ((state == 0 || state == 1) && begin < len
                    && (p = crlf(buffer + begin, len - begin)) >= 0) {
                p += begin;
                if (state == 0) {
                    if (statusline(fd, buffer + begin, p - begin, &rq))
                        state = 1;
                    else {
                        state = 3;
                        break;
                    }
                } else if (state == 1) {
                    if (p - begin == 0) {
                        if (rq.contentlen == 0)
                            state = 3;
                        else
                            state = 2;
                    } else if (!header(fd, buffer + begin, p - begin, &rq))
                        state = 3;
                }

                begin = p + 2;
                if (state == 2 || state == 3)
                    break;
            }

            if (state == 2) {
                memcpy(rq.payload + pbegin, buffer + begin, len - begin);
                pbegin += len - begin;
                plen += len - begin;
                begin += len - begin;
                
                if (rq.contentlen != 0 && pbegin >= rq.contentlen)
                    state = 3;
            }
        } else {
            state = 3;
            break;
        }
    } while (state <= 2);

    if (rq.contentlen == 0)
        rq.contentlen = plen;

    if (rq.code != 200) {
        respond(fd, rq.code, rq.protocol, NULL, 0, NULL);
    } else {
        if (rq.uri[0] == '/')
            strcpy(can_uri, rq.uri);
        else {
            strcpy(can_uri, "/");
            strcat(can_uri, rq.uri);
        }

        if (!permissible(can_uri)) {
            rq.code = 403;
            respond(fd, rq.code, rq.protocol, NULL, 0, NULL);
        } else {
            state = locateresource(can_uri, filepath, BUFFER_SIZE, &filelen);
            if (state == 0) {
                rq.code = 404;
                respond(fd, rq.code, rq.protocol, NULL, 0, NULL);
            } else if (state == 2) {
                strcpy(buffer, "Location: ");
                strcat(buffer, filepath);
                strcat(buffer, "\r\n");
                rq.code = 301;
                respond(fd, rq.code, rq.protocol, NULL, 0, buffer);
            } else if (state == 3) {
                rq.code = 403;
                respond(fd, rq.code ,rq.protocol, NULL, 0, NULL);
            } else if (state == 1) {
                if (postfix(filepath, pf) && strcmp(pf, "php") == 0) {
                    php(fd, filepath, addr, &rq);
                } else {
                    strcpy(headers, "Content-Type: ");
                    strcat(headers, contenttype(filepath));
                    strcat(headers, "\r\n");

                    if (rq.method == METHOD_HEAD)
                        respond(fd, rq.code, rq.protocol, NULL, filelen, headers);
                    else {
                        fduri = open(filepath, O_RDONLY);
                        if (fduri < 0) {
                            rq.code = 404;
                            respond(fd, rq.code, rq.protocol, NULL, 0, NULL);
                        } else {
                            uribuffer = malloc(filelen);
                            if (uribuffer == 0) {
                                rq.code = 500;
                                respond(fd, rq.code, rq.protocol, NULL, 0, NULL);
                            } else {
                                tot = 0;
                                while (tot < filelen)
                                    tot += read(fduri, uribuffer + tot, filelen - tot);

                                respond(fd, rq.code, rq.protocol, uribuffer, filelen, headers);
                                free(uribuffer);
                            }
                            close(fduri);
                        }
                    }
                }
            }
        }
    }


    now = time(NULL);
    len = strftime(buffer, BUFFER_SIZE, "%d/%b/%Y %H:%M:%S", gmtime(&now));
    fprintf(stdout, "%s - - [%s] \"%s\" %d\n", addr, buffer, rq.statusline, rq.code);
}

void
serve(int fd)
{
    int clfd, pid;
    socklen_t clilen;
    struct sockaddr_in cli_addr;
    char ipaddr[INET6_ADDRSTRLEN];
    const char *s;

    for (;;) {
        clilen = sizeof(struct sockaddr_in);
        clfd = accept(fd, (struct sockaddr *) &cli_addr, &clilen);
        if (clfd < 0) {
            perror("error accepting");
            exit(1);
        }

        pid = fork();
        if (pid < 0) {
            perror("error forking");
            exit(1);
        } else if (pid == 0) {
            /* we use the fork twice trick to eliminate zombie process */
            if ((pid = fork()) < 0) {
                perror("error forking");
                exit(1);
            } else if (pid > 0)
                exit(0);

            close(fd);

            s = inet_ntop(AF_INET, &(cli_addr.sin_addr), ipaddr, sizeof(ipaddr));
            if (!s) {
                perror("error inet_ntop");
                exit(1);
            }

            handlerequest(clfd, s);
            close(clfd);
            exit(0);
        } else {
            close(clfd);
            waitpid(pid, 0, 0);
        }
    }
}

int
parseargs(int argc, char *argv[])
{
    int i, t = 0;
    uint16_t n;
    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-p") == 0)
            t = 1;
        else if (strcmp(argv[i], "-d") == 0)
            t = 2;
        else if (strcmp(argv[i], "-b") == 0)
            t = 3;
        else {
            if (t == 0)
                return 0;
            switch (t) {
                case 0:
                    return 0;
                    break;

                case 1:
                    n = atoi(argv[i]);
                    if (n == 0)
                        return 0;
                    port = n;
                    break;

                case 2:
                    if (argv[i][strlen(argv[i]) - 1] == '/')
                        argv[i][strlen(argv[i]) - 1] = 0;
                    strncpy(root, argv[i], BUFFER_SIZE);
                    break;

                case 3:
                    n = atoi(argv[i]);
                    if (n == 0)
                        return 0;
                    qlen = n;
                    break;
                    
                default:
                    return 0;
            }
        }
    }
    return 1;
}

int
main(int argc, char *argv[])
{
    int fd;

    if (!parseargs(argc, argv))
        usage();
    else {
        fd = initserver(port, qlen);
        fprintf(stdout, "Server HTTP on port %d ...\n", port);
        serve(fd);
    }

    return 0;
}
