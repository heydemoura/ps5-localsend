#include "json.h"
#include "sha256.h"
#include "sender.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PORT 53317
#define GROUP "224.0.0.167"
#define MAX_FILES 32
#define MAX_METADATA 65536
#define HEADER_CAP 16384
#define CHUNK 16384

typedef struct {
  char id[128];
  char name[256];
  char token[33];
  char sha256[65];
  uint64_t size;
  int done;
} transfer_file;
typedef struct {
  char id[33];
  struct in_addr peer;
  transfer_file files[MAX_FILES];
  int count;
  time_t expires;
} transfer_session;

static transfer_session session;
static char fingerprint[33];
static char alias_name[96] = "PS5 LocalSend";
static char output_dir[512] = "/data/localsend";
static unsigned port = DEFAULT_PORT;

static void random_hex(char *out, size_t bytes) {
  static const char hex[] = "0123456789abcdef";
  unsigned char buf[32];
  if (bytes > sizeof(buf)) bytes = sizeof(buf);
  arc4random_buf(buf, bytes);
  for (size_t i = 0; i < bytes; ++i) {
    out[2*i] = hex[buf[i] >> 4];
    out[2*i+1] = hex[buf[i] & 15];
  }
  out[2*bytes] = 0;
}

static int send_all(int fd, const void *buf, size_t len) {
  const char *p = buf;
  while (len) {
    ssize_t n = send(fd, p, len, 0);
    if (n <= 0) return -1;
    p += n; len -= (size_t)n;
  }
  return 0;
}

static void reply(int fd, int code, const char *body) {
  const char *reason = code == 200 ? "OK" : code == 204 ? "No Content" :
    code == 400 ? "Bad Request" : code == 403 ? "Forbidden" :
    code == 404 ? "Not Found" : code == 409 ? "Conflict" :
    code == 413 ? "Content Too Large" : code == 422 ? "Unprocessable Content" :
    code == 500 ? "Internal Server Error" : "Error";
  if (!body) body = "";
  char hdr[256];
  int n = snprintf(hdr, sizeof(hdr),
    "HTTP/1.1 %d %s\r\nContent-Type: application/json; charset=utf-8\r\n"
    "Content-Length: %zu\r\nConnection: close\r\n\r\n", code, reason, strlen(body));
  if (n > 0 && (size_t)n < sizeof(hdr)) {
    send_all(fd, hdr, (size_t)n);
    send_all(fd, body, strlen(body));
  }
}

static int info(char *out, size_t cap, int announce) {
  char name[256];
  if (json_escape(alias_name, name, sizeof(name)) < 0) return -1;
  int n = snprintf(out, cap,
    "{\"alias\":\"%s\",\"version\":\"2.0\",\"deviceModel\":\"PlayStation 5\","
    "\"deviceType\":\"headless\",\"fingerprint\":\"%s\",\"port\":%u,"
    "\"protocol\":\"http\",\"download\":false%s}",
    name, fingerprint, port, announce < 0 ? "" : announce ? ",\"announce\":true" : ",\"announce\":false");
  return n < 0 || (size_t)n >= cap ? -1 : n;
}

static int parse_content_length(const char *headers, uint64_t *length) {
  const char *p = strstr(headers, "\r\n") ;
  if (!p) return -1;
  p += 2;
  int seen = 0;
  while (*p && !(p[0] == '\r' && p[1] == '\n')) {
    const char *end = strstr(p, "\r\n");
    if (!end) return -1;
    const char *colon = memchr(p, ':', (size_t)(end-p));
    if (!colon) return -1;
    if ((size_t)(colon-p) == 14 && !strncasecmp(p, "Content-Length", 14)) {
      if (seen++) return -1;
      const char *v = colon + 1;
      while (v < end && (*v == ' ' || *v == '\t')) ++v;
      if (v == end) return -1;
      uint64_t n = 0;
      while (v < end && *v >= '0' && *v <= '9') {
        if (n > (UINT64_MAX - (unsigned)(*v-'0')) / 10) return -1;
        n = n * 10 + (unsigned)(*v++-'0');
      }
      while (v < end && (*v == ' ' || *v == '\t')) ++v;
      if (v != end) return -1;
      *length = n;
    } else if ((size_t)(colon-p) == 17 && !strncasecmp(p, "Transfer-Encoding", 17)) {
      return -1;
    }
    p = end + 2;
  }
  return seen ? 0 : -1;
}

static int query_value(const char *query, const char *key, char *out, size_t cap) {
  size_t klen = strlen(key), w = 0;
  const char *p = query;
  while (p && *p) {
    if (!strncmp(p, key, klen) && p[klen] == '=') {
      p += klen + 1;
      while (*p && *p != '&') {
        unsigned char c = (unsigned char)*p++;
        if (c == '%') {
          if (!p[0] || !p[1]) return -1;
          char h[3] = {p[0], p[1], 0};
          char *end;
          unsigned long x = strtoul(h, &end, 16);
          if (*end || x == 0) return -1;
          c = (unsigned char)x; p += 2;
        } else if (c == '+') c = ' ';
        if (w + 1 >= cap) return -1;
        out[w++] = (char)c;
      }
      out[w] = 0;
      return 0;
    }
    p = strchr(p, '&');
    if (p) ++p;
  }
  return -1;
}

static int safe_name(const char *input, char *out, size_t cap) {
  const char *base = input;
  for (const char *p = input; *p; ++p) if (*p == '/' || *p == '\\') base = p + 1;
  if (!*base || !strcmp(base, ".") || !strcmp(base, "..")) return -1;
  size_t w = 0;
  for (const unsigned char *p = (const unsigned char *)base; *p; ++p) {
    if (w + 1 >= cap) return -1;
    out[w++] = *p < 0x20 || *p == 0x7f || *p == ':' ? '_' : (char)*p;
  }
  out[w] = 0;
  return 0;
}

static int prepare(const char *body, size_t len, struct in_addr peer, char *response, size_t cap) {
  json_doc *d = malloc(sizeof(*d));
  if (!d) return 500;
  if (json_parse(d, body, len) < 0 || d->tokens[0].type != '{') { free(d); return 400; }
  int files = json_field(d, 0, "files");
  int from = json_field(d, 0, "info");
  if (files < 0 || d->tokens[files].type != '{' ||
      from < 0 || d->tokens[from].type != '{') { free(d); return 400; }
  if (session.count && time(NULL) < session.expires) { free(d); return 409; }
  transfer_session fresh = {0};
  fresh.peer = peer;
  fresh.expires = time(NULL) + 600;
  random_hex(fresh.id, 16);
  int i = files + 1;
  while (i < d->tokens[files].next) {
    if (fresh.count == MAX_FILES) { free(d); return 413; }
    transfer_file *f = &fresh.files[fresh.count];
    int object = i + 1;
    char key[sizeof(f->id)];
    char id[sizeof(f->id)];
    char original[sizeof(f->name)];
    uint64_t size;
    int id_t = json_field(d, object, "id");
    int name_t = json_field(d, object, "fileName");
    int size_t = json_field(d, object, "size");
    if (d->tokens[object].type != '{' || json_string(d, i, key, sizeof(key)) < 0 ||
        json_string(d, id_t, id, sizeof(id)) < 0 || strcmp(key, id) ||
        json_string(d, name_t, original, sizeof(original)) < 0 ||
        safe_name(original, f->name, sizeof(f->name)) < 0 ||
        json_u64(d, size_t, &size) < 0) { free(d); return 400; }
    for (int j = 0; j < fresh.count; ++j) if (!strcmp(fresh.files[j].id, id)) { free(d); return 400; }
    memcpy(f->id, id, strlen(id)+1);
    f->size = size;
    int hash_t = json_field(d, object, "sha256");
    if (hash_t >= 0 && d->tokens[hash_t].type == '"') {
      if (json_string(d, hash_t, f->sha256, sizeof(f->sha256)) < 0 || strlen(f->sha256) != 64) {
        free(d); return 400;
      }
      for (int j = 0; j < 64; ++j) if (!strchr("0123456789abcdefABCDEF", f->sha256[j])) {
        free(d); return 400;
      }
    }
    random_hex(f->token, 16);
    ++fresh.count;
    i = d->tokens[object].next;
  }
  free(d);
  if (!fresh.count) return 400;
  int n = snprintf(response, cap, "{\"sessionId\":\"%s\",\"files\":{", fresh.id);
  if (n < 0 || (size_t)n >= cap) return 500;
  size_t used = (size_t)n;
  for (int j = 0; j < fresh.count; ++j) {
    char id_escaped[512];
    if (json_escape(fresh.files[j].id, id_escaped, sizeof(id_escaped)) < 0) return 500;
    n = snprintf(response + used, cap - used, "%s\"%s\":\"%s\"",
                 j ? "," : "", id_escaped, fresh.files[j].token);
    if (n < 0 || (size_t)n >= cap-used) return 500;
    used += (size_t)n;
  }
  if (used + 3 > cap) return 500;
  memcpy(response + used, "}}", 3);
  session = fresh;
  return 200;
}

static int write_file(int fd, const char *initial, size_t initial_len, uint64_t length,
                      transfer_file *f) {
  if (length != f->size) return 400;
  char temp[1024], final[1024], suffix[17];
  random_hex(suffix, 8);
  if (snprintf(temp, sizeof(temp), "%s/.%s.part", output_dir, suffix) >= (int)sizeof(temp) ||
      snprintf(final, sizeof(final), "%s/%s-%s", output_dir, suffix, f->name) >= (int)sizeof(final)) return 500;
  int out = open(temp, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (out < 0) return 500;
  sha256_ctx hash;
  sha256_init(&hash);
  uint64_t total = 0;
  int status = 200;
  char buf[CHUNK];
  while (total < length) {
    const char *data = buf;
    size_t n;
    if (initial_len) {
      n = initial_len;
      if ((uint64_t)n > length-total) n = (size_t)(length-total);
      data = initial;
      initial += n;
      initial_len -= n;
    } else {
      n = length-total < CHUNK ? (size_t)(length-total) : CHUNK;
      ssize_t r = recv(fd, buf, n, 0);
      if (r <= 0) { status = 400; break; }
      n = (size_t)r;
    }
    sha256_update(&hash, data, n);
    size_t sent = 0;
    while (sent < n) {
      ssize_t w = write(out, data + sent, n - sent);
      if (w <= 0) { status = 500; break; }
      sent += (size_t)w;
    }
    if (status != 200) break;
    total += n;
  }
  if (close(out) != 0) status = 500;
  if (status == 200 && f->sha256[0]) {
    unsigned char digest[32];
    char hex[65];
    static const char digits[] = "0123456789abcdef";
    sha256_final(&hash, digest);
    for (int j = 0; j < 32; ++j) { hex[2*j] = digits[digest[j] >> 4]; hex[2*j+1] = digits[digest[j] & 15]; }
    hex[64] = 0;
    if (strcasecmp(hex, f->sha256)) status = 422;
  }
  if (status == 200 && rename(temp, final) != 0) status = 500;
  if (status != 200) unlink(temp);
  if (status == 200) {
    f->done = 1;
    printf("LocalSend: received %s (%" PRIu64 " bytes)\n", final, length);
  }
  return status;
}

static void handle_http(int fd, struct in_addr peer) {
  struct timeval timeout = {.tv_sec = 15};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  char header[HEADER_CAP+1];
  size_t used = 0;
  char *boundary = NULL;
  while (used < HEADER_CAP) {
    ssize_t n = recv(fd, header+used, HEADER_CAP-used, 0);
    if (n <= 0) return;
    used += (size_t)n;
    header[used] = 0;
    boundary = strstr(header, "\r\n\r\n");
    if (boundary) break;
  }
  if (!boundary) { reply(fd, 413, NULL); return; }
  size_t header_len = (size_t)(boundary-header)+4;
  char *line = strstr(header, "\r\n");
  if (!line || line-header > 1024) { reply(fd, 400, NULL); return; }
  *line = 0;
  char method[8], target[1024], version[16];
  if (sscanf(header, "%7s %1023s %15s", method, target, version) != 3 ||
      strncmp(version, "HTTP/1.", 7)) { reply(fd, 400, NULL); return; }
  *line = '\r';
  char *query = strchr(target, '?');
  if (query) *query++ = 0;
  if (!strcmp(method, "GET") && !strcmp(target, "/api/localsend/v2/info")) {
    char body[512];
    if (info(body, sizeof(body), -1) >= 0) reply(fd, 200, body);
    return;
  }
  if (!strcmp(method, "POST") && !strcmp(target, "/api/localsend/v2/register")) {
    char body[512];
    if (info(body, sizeof(body), -1) >= 0) reply(fd, 200, body);
    return;
  }
  if (!strcmp(method, "POST") && !strcmp(target, "/api/localsend/v2/cancel")) {
    char sid[64];
    if (!query || query_value(query, "sessionId", sid, sizeof(sid)) < 0) { reply(fd, 400, NULL); return; }
    if (!strcmp(sid, session.id) && peer.s_addr == session.peer.s_addr) memset(&session, 0, sizeof(session));
    reply(fd, 200, NULL);
    return;
  }
  if (!strcmp(method, "POST") && !strcmp(target, "/api/localsend/v2/prepare-upload")) {
    uint64_t length;
    if (parse_content_length(header, &length) < 0) { reply(fd, 400, NULL); return; }
    if (length > MAX_METADATA) { reply(fd, 413, NULL); return; }
    char *body = malloc((size_t)length+1);
    if (!body) { reply(fd, 500, NULL); return; }
    size_t have = used-header_len;
    if (have > length) have = (size_t)length;
    memcpy(body, header+header_len, have);
    while (have < length) {
      ssize_t n = recv(fd, body+have, (size_t)length-have, 0);
      if (n <= 0) { free(body); reply(fd, 400, NULL); return; }
      have += (size_t)n;
    }
    body[length] = 0;
    char response[8192];
    int status = prepare(body, (size_t)length, peer, response, sizeof(response));
    free(body);
    reply(fd, status, status == 200 ? response : NULL);
    return;
  }
  if (!strcmp(method, "POST") && !strcmp(target, "/api/localsend/v2/upload")) {
    char sid[64], id[128], token[64];
    uint64_t length;
    if (!query || query_value(query, "sessionId", sid, sizeof(sid)) < 0 ||
        query_value(query, "fileId", id, sizeof(id)) < 0 ||
        query_value(query, "token", token, sizeof(token)) < 0 ||
        parse_content_length(header, &length) < 0) { reply(fd, 400, NULL); return; }
    if (!session.count || time(NULL) > session.expires || strcmp(sid, session.id) ||
        peer.s_addr != session.peer.s_addr) { reply(fd, 403, NULL); return; }
    transfer_file *f = NULL;
    for (int i = 0; i < session.count; ++i)
      if (!strcmp(id, session.files[i].id) && !strcmp(token, session.files[i].token)) f = &session.files[i];
    if (!f || f->done) { reply(fd, 403, NULL); return; }
    int status = write_file(fd, header+header_len, used-header_len, length, f);
    reply(fd, status, NULL);
    int all_done = 1;
    for (int i = 0; i < session.count; ++i) if (!session.files[i].done) all_done = 0;
    if (all_done) memset(&session, 0, sizeof(session));
    return;
  }
  reply(fd, 404, NULL);
}

static void announce(int udp, const struct sockaddr_in *destination, int mode) {
  char body[512];
  int n = info(body, sizeof(body), mode);
  if (n > 0) sendto(udp, body, (size_t)n, 0,
                    (const struct sockaddr *)destination, sizeof(*destination));
}

int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  const char *v = getenv("LOCALSEND_DIR");
  if (v && *v && strlen(v) < sizeof(output_dir)) strcpy(output_dir, v);
  v = getenv("LOCALSEND_ALIAS");
  if (v && *v && strlen(v) < sizeof(alias_name)) strcpy(alias_name, v);
  v = getenv("LOCALSEND_PORT");
  if (v && *v) {
    char *end; unsigned long n = strtoul(v, &end, 10);
    if (*end || n == 0 || n > 65535) { fprintf(stderr, "Invalid LOCALSEND_PORT\n"); return 1; }
    port = (unsigned)n;
  }
  random_hex(fingerprint, 16);
  if (argc > 1) {
    if (argc != 4 && argc != 5) {
      fprintf(stderr, "Usage: %s --send FILE PEER_IPV4 [PORT]\n", argv[0]);
      return 1;
    }
    if (strcmp(argv[1], "--send")) return 1;
    unsigned remote_port = DEFAULT_PORT;
    if (argc == 5) {
      char *end; unsigned long n = strtoul(argv[4], &end, 10);
      if (*end || n == 0 || n > 65535) return 1;
      remote_port = (unsigned)n;
    }
    return send_file_to_peer(argv[2], argv[3], remote_port, alias_name, fingerprint, port);
  }
  if (mkdir(output_dir, 0700) < 0 && errno != EEXIST) {
    perror("LocalSend output directory"); return 1;
  }
  int tcp = socket(AF_INET, SOCK_STREAM, 0);
  int udp = socket(AF_INET, SOCK_DGRAM, 0);
  if (tcp < 0 || udp < 0) { perror("socket"); return 1; }
  int one = 1;
  setsockopt(tcp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  setsockopt(udp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in bind_addr = {.sin_family=AF_INET, .sin_port=htons((uint16_t)port)};
  bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(tcp, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0 ||
      listen(tcp, 8) < 0 ||
      bind(udp, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
    perror("bind/listen"); return 1;
  }
  struct ip_mreq group = {0};
  inet_pton(AF_INET, GROUP, &group.imr_multiaddr);
  group.imr_interface.s_addr = htonl(INADDR_ANY);
  if (setsockopt(udp, IPPROTO_IP, IP_ADD_MEMBERSHIP, &group, sizeof(group)) < 0)
    perror("multicast membership");
  struct sockaddr_in multicast = {.sin_family=AF_INET, .sin_port=htons((uint16_t)port)};
  inet_pton(AF_INET, GROUP, &multicast.sin_addr);
  printf("PS5 LocalSend listening on port %u, saving to %s\n", port, output_dir);
  time_t last = 0;
  for (;;) {
    time_t now = time(NULL);
    if (now - last >= 30) { announce(udp, &multicast, 1); last = now; }
    fd_set readfds;
    FD_ZERO(&readfds); FD_SET(tcp, &readfds); FD_SET(udp, &readfds);
    struct timeval timeout = {.tv_sec=1};
    int rc = select((tcp > udp ? tcp : udp)+1, &readfds, NULL, NULL, &timeout);
    if (rc < 0) { if (errno == EINTR) continue; perror("select"); break; }
    if (FD_ISSET(udp, &readfds)) {
      char data[1024];
      struct sockaddr_in from; socklen_t fromlen = sizeof(from);
      ssize_t n = recvfrom(udp, data, sizeof(data), 0, (struct sockaddr *)&from, &fromlen);
      if (n > 0) {
        json_doc *d = malloc(sizeof(*d));
        if (d && json_parse(d, data, (size_t)n) == 0) {
          char fp[64]; int is_announce = 0;
          int f = json_field(d, 0, "fingerprint");
          int a = json_field(d, 0, "announce");
          if (json_string(d, f, fp, sizeof(fp)) == 0 && strcmp(fp, fingerprint) &&
              json_bool(d, a, &is_announce) == 0 && is_announce)
            announce(udp, &multicast, 0);
        }
        free(d);
      }
    }
    if (FD_ISSET(tcp, &readfds)) {
      struct sockaddr_in peer; socklen_t peerlen = sizeof(peer);
      int client = accept(tcp, (struct sockaddr *)&peer, &peerlen);
      if (client >= 0) { handle_http(client, peer.sin_addr); close(client); }
    }
  }
  close(tcp); close(udp);
  return 1;
}
