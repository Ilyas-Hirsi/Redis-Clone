#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
// system
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
// C++
#include <string>
#include <vector>
#include <map>

// Print a message to stderr
static void msg(const char *msg) {
    fprintf(stderr, "%s\n", msg);
}

// Print an error message with errno
static void msg_errno(const char *msg) {
    fprintf(stderr, "[errno:%d] %s\n", errno, msg);
}

// Print an error and abort the program
static void die(const char *msg) {
    fprintf(stderr, "[%d] %s\n", errno, msg);
    abort();
}

// Set a file descriptor (socket) to non-blocking mode
static void fd_set_nb(int fd) {
    errno = 0;
    int flags = fcntl(fd, F_GETFL, 0);
    if (errno) {
        die("fcntl error");
        return;
    }
    flags |= O_NONBLOCK;
    errno = 0;
    (void)fcntl(fd, F_SETFL, flags);
    if (errno) {
        die("fcntl error");
    }
}

// Maximum allowed message size
const size_t k_max_msg = 32 << 20;  // 32 MB

// Structure to represent a client connection
struct Conn {
    int fd = -1; // Socket file descriptor
    // Flags for the event loop
    bool want_read = false;
    bool want_write = false;
    bool want_close = false;
    // Buffers for incoming and outgoing data
    std::vector<uint8_t> incoming;  // Data received from client
    std::vector<uint8_t> outgoing;  // Data to send to client
};

// Append data to a buffer
static void buf_append(std::vector<uint8_t> &buf, const uint8_t *data, size_t len) {
    buf.insert(buf.end(), data, data + len);
}

// Remove n bytes from the front of a buffer
static void buf_consume(std::vector<uint8_t> &buf, size_t n) {
    buf.erase(buf.begin(), buf.begin() + n);
}

// Accept a new client connection
static Conn *handle_accept(int fd) {
    struct sockaddr_in client_addr = {};
    socklen_t addrlen = sizeof(client_addr);
    int connfd = accept(fd, (struct sockaddr *)&client_addr, &addrlen);
    if (connfd < 0) {
        msg_errno("accept() error");
        return NULL;
    }
    uint32_t ip = client_addr.sin_addr.s_addr;
    fprintf(stderr, "new client from %u.%u.%u.%u:%u\n",
        ip & 255, (ip >> 8) & 255, (ip >> 16) & 255, ip >> 24,
        ntohs(client_addr.sin_port)
    );
    // Set the new socket to non-blocking mode
    fd_set_nb(connfd);
    // Create a new Conn object for this client
    Conn *conn = new Conn();
    conn->fd = connfd;
    conn->want_read = true;
    return conn;
}

const size_t k_max_args = 200 * 1000; // Safety limit for number of arguments

// Read a 4-byte unsigned integer from a buffer
static bool read_u32(const uint8_t *&cur, const uint8_t *end, uint32_t &out) {
    if (cur + 4 > end) {
        return false;
    }
    memcpy(&out, cur, 4);
    cur += 4;
    return true;
}

// Read a string of length n from a buffer
static bool read_str(const uint8_t *&cur, const uint8_t *end, size_t n, std::string &out) {
    if (cur + n > end) {
        return false;
    }
    out.assign(cur, cur + n);
    cur += n;
    return true;
}

// Parse a request from the client
// Protocol: [nstr][len][str1][len][str2]...[len][strn]
static int32_t parse_req(const uint8_t *data, size_t size, std::vector<std::string> &out) {
    const uint8_t *end = data + size;
    uint32_t nstr = 0;
    if (!read_u32(data, end, nstr)) {
        return -1;
    }
    if (nstr > k_max_args) {
        return -1;  // Too many arguments
    }
    while (out.size() < nstr) {
        uint32_t len = 0;
        if (!read_u32(data, end, len)) {
            return -1;
        }
        out.push_back(std::string());
        if (!read_str(data, end, len, out.back())) {
            return -1;
        }
    }
    if (data != end) {
        return -1;  // Extra data at the end
    }
    return 0;
}

// Response status codes
enum {
    RES_OK = 0,    // Success
    RES_ERR = 1,   // Error
    RES_NX = 2,    // Key not found
};

// Structure for a server response
// Protocol: [status][data...]
struct Response {
    uint32_t status = 0;
    std::vector<uint8_t> data;
};

// In-memory key-value store
static std::map<std::string, std::string> g_data;

// Handle a parsed command and prepare a response
static void do_request(std::vector<std::string> &cmd, Response &out) {
    if (cmd.size() == 2 && cmd[0] == "get") {
        auto it = g_data.find(cmd[1]);
        if (it == g_data.end()) {
            out.status = RES_NX;    // Key not found
            return;
        }
        const std::string &val = it->second;
        out.data.assign(val.begin(), val.end());
    } else if (cmd.size() == 3 && cmd[0] == "set") {
        g_data[cmd[1]].swap(cmd[2]); // Set key to value
    } else if (cmd.size() == 2 && cmd[0] == "del") {
        g_data.erase(cmd[1]);        // Delete key
    } else {
        out.status = RES_ERR;        // Unrecognized command
    }
}

// Build a response message to send to the client
static void make_response(const Response &resp, std::vector<uint8_t> &out) {
    uint32_t resp_len = 4 + (uint32_t)resp.data.size();
    buf_append(out, (const uint8_t *)&resp_len, 4);      // Message length
    buf_append(out, (const uint8_t *)&resp.status, 4);   // Status code
    buf_append(out, resp.data.data(), resp.data.size()); // Data
}

// Try to process one complete request from the client
static bool try_one_request(Conn *conn) {
    // Check if we have enough data for the message header
    if (conn->incoming.size() < 4) {
        return false;   // Need more data
    }
    uint32_t len = 0;
    memcpy(&len, conn->incoming.data(), 4);
    if (len > k_max_msg) {
        msg("too long");
        conn->want_close = true;
        return false;   // Close connection
    }
    // Check if we have the full message body
    if (4 + len > conn->incoming.size()) {
        return false;   // Need more data
    }
    const uint8_t *request = &conn->incoming[4];
    // Parse the request
    std::vector<std::string> cmd;
    if (parse_req(request, len, cmd) < 0) {
        msg("bad request");
        conn->want_close = true;
        return false;   // Close connection
    }
    // Handle the command and prepare a response
    Response resp;
    do_request(cmd, resp);
    make_response(resp, conn->outgoing);
    // Remove the processed request from the buffer
    buf_consume(conn->incoming, 4 + len);
    // Note: We don't clear the buffer in case of pipelined requests
    return true;        // Processed one request
}

// Handle writing data to a client socket
static void handle_write(Conn *conn) {
    assert(conn->outgoing.size() > 0);
    ssize_t rv = write(conn->fd, &conn->outgoing[0], conn->outgoing.size());
    if (rv < 0 && errno == EAGAIN) {
        return; // Not ready to write
    }
    if (rv < 0) {
        msg_errno("write() error");
        conn->want_close = true;    // Error, close connection
        return;
    }
    // Remove written data from outgoing buffer
    buf_consume(conn->outgoing, (size_t)rv);
    // Update event loop flags
    if (conn->outgoing.size() == 0) {   // All data sent
        conn->want_read = true;
        conn->want_write = false;
    } // else: still have data to write
}

// Handle reading data from a client socket
static void handle_read(Conn *conn) {
    // Temporary buffer for reading
    uint8_t buf[64 * 1024];
    ssize_t rv = read(conn->fd, buf, sizeof(buf));
    if (rv < 0 && errno == EAGAIN) {
        return; // Not ready to read
    }
    // Handle IO error
    if (rv < 0) {
        msg_errno("read() error");
        conn->want_close = true;
        return;
    }
    // Handle EOF (client closed connection)
    if (rv == 0) {
        if (conn->incoming.size() == 0) {
            msg("client closed");
        } else {
            msg("unexpected EOF");
        }
        conn->want_close = true;
        return;
    }
    // Append received data to incoming buffer
    buf_append(conn->incoming, buf, (size_t)rv);
    // Try to process as many requests as possible (pipelining)
    while (try_one_request(conn)) {}
    // If we have a response, switch to write mode
    if (conn->outgoing.size() > 0) {
        conn->want_read = false;
        conn->want_write = true;
        // Try to write immediately
        return handle_write(conn);
    }   // else: keep reading
}

int main() {
    // Create a TCP socket for listening
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        die("socket()");
    }
    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    // Bind the socket to port 1234 on all interfaces
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = ntohs(1234);
    addr.sin_addr.s_addr = ntohl(0);    // 0.0.0.0 (all interfaces)
    int rv = bind(fd, (const sockaddr *)&addr, sizeof(addr));
    if (rv) {
        die("bind()");
    }
    // Set the listening socket to non-blocking mode
    fd_set_nb(fd);
    // Start listening for incoming connections
    rv = listen(fd, SOMAXCONN);
    if (rv) {
        die("listen()");
    }
    // Vector to keep track of all client connections
    std::vector<Conn *> fd2conn;
    // Event loop using poll()
    std::vector<struct pollfd> poll_args;
    while (true) {
        // Prepare poll() arguments
        poll_args.clear();
        // Add the listening socket
        struct pollfd pfd = {fd, POLLIN, 0};
        poll_args.push_back(pfd);
        // Add all client sockets
        for (Conn *conn : fd2conn) {
            if (!conn) {
                continue;
            }
            // Always poll for errors
            struct pollfd pfd = {conn->fd, POLLERR, 0};
            // Set poll flags based on what the connection wants
            if (conn->want_read) {
                pfd.events |= POLLIN;
            }
            if (conn->want_write) {
                pfd.events |= POLLOUT;
            }
            poll_args.push_back(pfd);
        }
        // Wait for events
        int rv = poll(poll_args.data(), (nfds_t)poll_args.size(), -1);
        if (rv < 0 && errno == EINTR) {
            continue;   // Interrupted, try again
        }
        if (rv < 0) {
            die("poll");
        }
        // Handle new incoming connections
        if (poll_args[0].revents) {
            if (Conn *conn = handle_accept(fd)) {
                // Add new connection to the vector
                if (fd2conn.size() <= (size_t)conn->fd) {
                    fd2conn.resize(conn->fd + 1);
                }
                assert(!fd2conn[conn->fd]);
                fd2conn[conn->fd] = conn;
            }
        }
        // Handle events for client connections
        for (size_t i = 1; i < poll_args.size(); ++i) { // Skip the listening socket
            uint32_t ready = poll_args[i].revents;
            if (ready == 0) {
                continue;
            }
            Conn *conn = fd2conn[poll_args[i].fd];
            if (ready & POLLIN) {
                assert(conn->want_read);
                handle_read(conn);  // Read data from client
            }
            if (ready & POLLOUT) {
                assert(conn->want_write);
                handle_write(conn); // Write data to client
            }
            // Close the connection if needed
            if ((ready & POLLERR) || conn->want_close) {
                (void)close(conn->fd);
                fd2conn[conn->fd] = NULL;
                delete conn;
            }
        }   // for each connection socket
    }   // the event loop
    return 0;
}