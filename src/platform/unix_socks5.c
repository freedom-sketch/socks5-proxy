/*
 * socks5.c - Реализация протокола SOCKS5 (RFC 1928) для POSIX систем
 *
 * Cтандарт SOCKS5:
 * 
 * RFC1928: https://datatracker.ietf.org/doc/html/rfc1928
 * RFC1929: https://datatracker.ietf.org/doc/html/rfc1929
 * RFC1961: https://datatracker.ietf.org/doc/html/rfc1961
 * RFC3089: https://datatracker.ietf.org/doc/html/rfc3089
*/

#include "include/socks5.h"
#include "include/config.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Обрабатывает запрос с ATYPE = 0x01 */
static int process_ipv4_request(SOCKET client_fd);
/* Обрабатывает запрос с ATYPE = 0x03 */
static int process_domainname_request(SOCKET client_fd);
/* Запускает двустороннюю ретрансляцию данных между клиентом и целевым хостом*/
static void start_relay(SOCKET client_fd, SOCKET remote_fd);

/* Создает сокет, биндит его к local_addr и возвращает дескриптор */
static SOCKET init_socket(int af, int type, int protocol, int reuse_addr, struct sockaddr_in* local_addr);

/* Формирует пакет ответа на 10 байт: VER=0x05; REP=0x00; ATYPE=0x01; BND.ADDR и BND.PORT обнуляет */
static void form_default_reply(uint8_t *rpl);
/* Дожидается len байтов из сети и записывает их в buffer */
static int recv_all(SOCKET socket, char *buffer, int len);


SOCKET server_init(struct config_t *cfg)
{
    struct sockaddr_in server_addr = {
		.sin_family = AF_INET,
		.sin_addr = cfg->listen_addr,
		.sin_port = cfg->port
	};

    SOCKET server_socket_fd = init_socket(AF_INET, SOCK_STREAM, 0, 1, &server_addr);
	if (server_socket_fd == INVALID_SOCKET) {
		perror("Error initialization server socket");
		return -1;
	}
	LOG("Server socket initialization is OK\n");

    return server_socket_fd;
}

int server_run(SOCKET srv_sock)
{
    int err_stat = listen(srv_sock, SOMAXCONN);
	if (err_stat != 0) {
		perror("Can't start to listen");
		close(srv_sock);
		return -1;
	}
	printf("The server has started...");

    struct sockaddr_in client_addr = {0};
	socklen_t client_addr_len = sizeof(client_addr);

    signal(SIGCHLD, SIG_IGN);

    while(1) {
        int client_socket_fd = accept(srv_sock, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket_fd < 0) {
            perror("accept failed");
            continue;
        }

        char str_client_ip[47] = {0};
		inet_ntop(AF_INET, &client_addr.sin_addr, str_client_ip, sizeof(str_client_ip));
		LOG("Connection from %s:%d\n", str_client_ip, ntohs(client_addr.sin_port));

        /* создаем дочерний процесс. fork() вернет PID созданного процесса в родительский процесс и 0 в дочерний */
        if (fork() == 0) {
            /* закрываем для дочернего процесса сокет SOCKS сервера */
            close(srv_sock);

            if (handle_socks5_greeting(client_socket_fd) == 0)
                handle_socks5_request(client_socket_fd);
            
            /* закрываем для дочернего процесса сокет клиента после окончания ретрансляции и выходим из процесса */
            close(client_socket_fd);
            exit(0);
        }

        /* закрываем сокет клиента для родительского процесса. */
        close(client_socket_fd);
    }
}

int handle_socks5_greeting(int client_socket)
{
    uint8_t header[2];
    ssize_t n;

    n = recv(client_socket, header, sizeof(header), 0);
    if (n < 2) return -1;

    uint8_t ver = header[0];
    uint8_t n_methods = header[1];

    if (ver != 0x05) return -1;
    if (n_methods < 1) return -1;

    uint8_t methods[255];

    n = recv(client_socket, methods, 255, 0);
    if (n < n_methods) return -1;

    int auth_ok = 0;
    for (int i = 0; i < n_methods; i++) {
        if (methods[i] == METHOD_NO_AUTH_REQ) {
            auth_ok = 1;
            break;
        }
    }

    if (!auth_ok) {
        uint8_t resp[2] = {0x05, NO_ACCEPTABLE_METHODS};
        LOG("AUTH:\n\tVER: %#x\n\tMETHOD: %#x\n", resp[0], resp[1]);
        send(client_socket, resp, sizeof(resp), 0);
        return -1;
    }

    uint8_t resp[2] = {0x05, METHOD_NO_AUTH_REQ};
    if (send(client_socket, resp, 2, 0) < 2) {
        LOG("AUTH:\n\tVER: %#x\n\tMETHOD: %#x\n", resp[0], resp[1]);
        return -1;
    }

    return 0;
}

int handle_socks5_request(int client_socket)
{
    struct socks5_header hdr = {0};

    if (recv(client_socket, &hdr, sizeof(hdr), 0) < (ssize_t)(sizeof(hdr))) return -1;
    LOG("REQUEST:\n\t" "VER: %#x\n\tCMD: %#x\n\tRSV: %#x\n\tATYP: %#x\n", 
    hdr.ver, hdr.cmd, hdr.rsv, hdr.atyp);

    if (hdr.ver != 0x05 || hdr.cmd != CMD_CONNECT)
        return -1;
    
    if (hdr.atyp == ATYPE_IPv4) {
        if (process_ipv4_request(client_socket) < 0)
            return -1;

    } else if (hdr.atyp == ATYPE_DOMAINNAME) {
        if (process_domainname_request(client_socket) < 0)
            return -1;
    } else
        return -1;
    
    return 0;
}

static int process_ipv4_request(SOCKET client_socket)
{
    uint8_t ip[4]; /* создаем буфер на 4 байта под IP адрес */
    uint16_t port; /* буфер на 2 байта под порт */

    /* читаем из клиентского сокета первые 6 байт. 4 под IP и 2 под порт */
    recv(client_socket, ip, sizeof(ip), 0);
    recv(client_socket, &port, sizeof(port), 0);

    LOG("\tDST.ADDR: %d.%d.%d.%d\n\tDST.PORT: %d\n", ip[0], ip[1], ip[2], ip[3], ntohs(port));

    /* создаем сокет с полножуплексной передачей семейства IPv4 для целевого хоста */
    int remote_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_fd < 0) {
        perror("Error initialization socket #%d\n");
        return -1;
    }
    LOG("Remote socket (#%d) initialization is OK\n", remote_fd);

    /* создаем и заполняем структуру информации об IPv4 сокете */
    struct sockaddr_in target_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = *(uint32_t *)ip,
        .sin_port = port
    };

    uint8_t reply[10] = {0};
    form_default_reply(reply);

    /* пытаемся установить соединение */
    if (connect(remote_fd, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
        /* в случае неудачи, меняем REP */
        reply[1] = REP_HOST_UNREACHABLE;
        /* отправляем ответ и закрываем сокет целевого хоста */
        send(client_socket, reply, sizeof(reply), 0);
        LOG("REPLY: \n\tREP: %#x\n\tRSV: %#x\n\tATYPE: %#x\n", reply[1], reply[2], reply[3]);

        close(remote_fd);
        return -1;            
    }

    /* в случае удачи отправляем ответ и начинаем проксировать трафик */
    send(client_socket, reply, sizeof(reply), 0);

    LOG("REPLY: \n\tREP: %#x\n\tRSV: %#x\n\tATYPE: %#x\n", reply[1], reply[2], reply[3]);

    start_relay(client_socket, remote_fd);
    close(remote_fd);
    return 0;
}

static int process_domainname_request(SOCKET client_socket)
{
    uint8_t len;
    recv(client_socket, &len, sizeof(len), 0);
    if (len == 0) return -1;

    char domain[256];
    recv(client_socket, domain, (size_t)len, 0);
    domain[len] = '\0';

    uint16_t port_net;
    recv(client_socket, &port_net, sizeof(port_net), 0);

    char s_port[7] = {0};
    snprintf(s_port, sizeof(s_port), "%hu", ntohs(port_net));

    LOG("\tDST.ADDR: %s\n\tDST.PORT: %d\n", domain, ntohs(port_net));

    SOCKET remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_socket < 0) {
        perror("Error initialization socket #%d");
        return -1;
    }
    LOG("Remote socket (#%d) initialization is OK\n", remote_socket);

    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM
    }, *res;

    uint8_t reply[10] = { 0 };
    form_default_reply(reply);

    /* обращаемся к DNS серверу и пытаемся получить IP */
    int status = getaddrinfo(domain, s_port, &hints, &res);
    if (status != 0) {
        reply[1] = REP_HOST_UNREACHABLE;
        send(client_socket, reply, sizeof(reply), 0);
        fprintf(stderr, "getaddrinfo: %s\n",gai_strerror(status));
        close(remote_socket);
        return -1;
    }

    struct sockaddr_in target_addr = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);

    /* пытаемся установить соединение */
    if (connect(remote_socket, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
        /* в случае неудачи, меняем REP */
        reply[1] = REP_HOST_UNREACHABLE;
        /* отправляем ответ и закрываем сокет целевого хоста */
        send(client_socket, reply, sizeof(reply), 0);
        LOG("REPLY: \n\tREP: %#x\n\tRSV: %#x\n\tATYPE: %#x\n", reply[1], reply[2], reply[3]);

        close(remote_socket);
        return -1;            
    }

    /* в случае удачи отправляем ответ и начинаем проксировать трафик */
    send(client_socket, reply, sizeof(reply), 0);

    LOG("REPLY: \n\tREP: %#x\n\tRSV: %#x\n\tATYPE: %#x\n", reply[1], reply[2], reply[3]);

    start_relay(client_socket, remote_socket);
    close(remote_socket);
    return 0;
}

static void start_relay(SOCKET client_socket, SOCKET remote_socket)
{
    struct pollfd fds[2];

    /* устанавливаем ожидать событие появления данных на чтение  */
    fds[0].fd = client_socket;
    fds[0].events = POLLIN;
    fds[1].fd = remote_socket;
    fds[1].events = POLLIN;

    uint8_t buffer[5120]; /* буфер на 5 кб */

    while (1) {
        int ret = poll(fds, 2, -1); /* ждем событие POLLIN */
        if (ret < 0) {
            perror("poll error");
            break;
        }

        for (int i=0; i < 2; i++) {
            if (fds[i].revents & POLLIN) {
                int source_fd = fds[i].fd;
                int dest_fd = (i == 0) ? fds[1].fd : fds[0].fd;

                ssize_t n = recv(source_fd, buffer, sizeof(buffer), 0);
                if (n <= 0) return;

                if (send(dest_fd, buffer, n, 0) <= 0) return;
            }
        }
    }
}

static SOCKET init_socket(int af, int type, int protocol, int reuse_addr, struct sockaddr_in* local_addr)
{
    int new_socket_fd = socket(af, type, protocol);
    if (new_socket_fd < 0)
        return -1;

    if (reuse_addr) {
        int socket_opt = 1;
        if (setsockopt(new_socket_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&socket_opt, sizeof(socket_opt)) != 0) {
            close(new_socket_fd);
            return -1;
        }
    }

    if (bind(new_socket_fd, (struct sockaddr*)local_addr, sizeof(struct sockaddr)) != 0) {
        close(new_socket_fd);
        return -1;
    }

    return new_socket_fd;
}

static void form_default_reply(uint8_t *rpl)
{
    memset(rpl, 0, 10);
    rpl[0] = 0x05;
    rpl[1] = REP_SUCCEEDED;
    rpl[2] = RSV;
    rpl[3] = ATYPE_IPv4;
}

static int recv_all(SOCKET socket, char *buffer, int len) {
	int total_received = 0;
	while (total_received < len) {
		int n = recv(socket, buffer + total_received, len - total_received, 0);
		if (n <= 0) {
			return -1;
		}
		total_received += n;
	}
	return total_received;
}
