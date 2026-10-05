/* A deterministic, scratch-compatible readiness server. No filesystem/network clients. */
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0), yes = 1;
    struct sockaddr_in addr = {0};
    signal(SIGPIPE, SIG_IGN);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    addr.sin_family = AF_INET; addr.sin_port = htons(8080);
    if (fd < 0 || bind(fd, (struct sockaddr *)&addr, sizeof(addr)) || listen(fd, 16)) return 1;
    for (;;) {
        int client = accept(fd, 0, 0);
        char request[1024];
        const char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\nok\n";
        if (client < 0) continue;
        if (read(client, request, sizeof(request)) > 0) write(client, response, strlen(response));
        close(client);
    }
}
