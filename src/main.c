/* SPDX-License-Identifier: GPL-3.0-only */
/* Copyright (C) 2026 heydemoura */
#include "json.h"
#include "sha256.h"
#include "sender.h"
#include "webui.inc"
#ifndef HOST_BUILD
#include "launcher.h"
#endif
#include <arpa/inet.h>
#include <dirent.h>
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

#ifndef DEFAULT_PORT
#define DEFAULT_PORT 53317
#endif
#ifndef DISCOVERY_PORT
#define DISCOVERY_PORT 53317
#endif
#define GROUP "224.0.0.167"
#define MAX_FILES 32
#define MAX_PEERS 32
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

typedef struct {
  char id[33];
  struct in_addr peer;
  transfer_file files[MAX_FILES];
  int count;
  time_t expires;
} download_session;

typedef struct {
  char alias[96];
  char fingerprint[128];
  struct in_addr address;
  unsigned port;
  int secure;
  time_t seen;
} discovered_peer;

static transfer_session session;
static download_session downloads;
static discovered_peer peers[MAX_PEERS];
static char fingerprint[33];
static char download_pin[7];
static int pin_configured;
static int pin_failures;
static time_t pin_window;
static char alias_name[96];
static char output_dir[512] = "/data/localsend";
static unsigned port = DEFAULT_PORT;

static void remember_peer(const json_doc *d, struct in_addr address) {
  char fp[128], name[96], protocol[16];
  uint64_t peer_port;
  if (d->tokens[0].type != '{' ||
      json_string(d, json_field(d, 0, "fingerprint"), fp, sizeof(fp)) < 0 ||
      !*fp || !strcmp(fp, fingerprint) ||
      json_string(d, json_field(d, 0, "alias"), name, sizeof(name)) < 0 ||
      json_string(d, json_field(d, 0, "protocol"), protocol, sizeof(protocol)) < 0 ||
      json_u64(d, json_field(d, 0, "port"), &peer_port) < 0 ||
      peer_port == 0 || peer_port > 65535 ||
      (strcmp(protocol, "http") && strcmp(protocol, "https"))) return;
  int slot = 0;
  time_t oldest = peers[0].seen;
  for (int i = 0; i < MAX_PEERS; ++i) {
    if (!peers[i].fingerprint[0] || !strcmp(peers[i].fingerprint, fp)) { slot = i; break; }
    if (peers[i].seen < oldest) { oldest = peers[i].seen; slot = i; }
  }
  if (slot < 0) return;
  discovered_peer *p = &peers[slot];
  strcpy(p->alias, name);
  strcpy(p->fingerprint, fp);
  p->address = address;
  p->port = (unsigned)peer_port;
  p->secure = !strcmp(protocol, "https");
  p->seen = time(NULL);
}

#ifndef HOST_BUILD
typedef struct {
  char reserved[45];
  char message[3075];
} notify_request;
int sceKernelSendNotificationRequest(int, notify_request *, size_t, int);
int sceSystemServiceParamGetString(int, char *, size_t);
#endif

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

static void reply_type(int fd, int code, const char *type, const char *body) {
  const char *reason = code == 200 ? "OK" : code == 204 ? "No Content" :
    code == 400 ? "Bad Request" : code == 403 ? "Forbidden" :
    code == 401 ? "Unauthorized" : code == 404 ? "Not Found" :
    code == 409 ? "Conflict" : code == 429 ? "Too Many Requests" :
    code == 413 ? "Content Too Large" : code == 422 ? "Unprocessable Content" :
    code == 500 ? "Internal Server Error" : "Error";
  if (!body) body = "";
  char hdr[256];
  int n = snprintf(hdr, sizeof(hdr),
    "HTTP/1.1 %d %s\r\nContent-Type: %s\r\n"
    "Content-Length: %zu\r\nConnection: close\r\n\r\n", code, reason, type, strlen(body));
  if (n > 0 && (size_t)n < sizeof(hdr)) {
    send_all(fd, hdr, (size_t)n);
    send_all(fd, body, strlen(body));
  }
}

static void reply(int fd, int code, const char *body) {
  reply_type(fd, code, "application/json; charset=utf-8", body);
}

static int info(char *out, size_t cap, int announce) {
  char name[256];
  if (json_escape(alias_name, name, sizeof(name)) < 0) return -1;
  int n = snprintf(out, cap,
    "{\"alias\":\"%s\",\"version\":\"2.0\",\"deviceModel\":\"PlayStation 5\","
    "\"deviceType\":\"headless\",\"fingerprint\":\"%s\",\"port\":%u,"
    "\"protocol\":\"http\",\"download\":%s%s}",
    name, fingerprint, port, pin_configured ? "true" : "false",
    announce < 0 ? "" : announce ? ",\"announce\":true" : ",\"announce\":false");
  return n < 0 || (size_t)n >= cap ? -1 : n;
}

static int parse_framing(const char *headers, uint64_t *length, int *chunked) {
  const char *p = strstr(headers, "\r\n") ;
  if (!p) return -1;
  p += 2;
  int seen_length = 0, seen_chunked = 0;
  while (*p && !(p[0] == '\r' && p[1] == '\n')) {
    const char *end = strstr(p, "\r\n");
    if (!end) return -1;
    const char *colon = memchr(p, ':', (size_t)(end-p));
    if (!colon) return -1;
    if ((size_t)(colon-p) == 14 && !strncasecmp(p, "Content-Length", 14)) {
      if (seen_length++) return -1;
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
      if (seen_chunked++) return -1;
      const char *v = colon + 1;
      while (v < end && (*v == ' ' || *v == '\t')) ++v;
      while (end > v && (end[-1] == ' ' || end[-1] == '\t')) --end;
      if (end-v != 7 || strncasecmp(v, "chunked", 7)) return -1;
      end = strstr(p, "\r\n");
    }
    p = end + 2;
  }
  if (seen_length == seen_chunked) return -1;
  *chunked = seen_chunked;
  return 0;
}

static int parse_content_length(const char *headers, uint64_t *length) {
  int chunked;
  return parse_framing(headers, length, &chunked) < 0 || chunked ? -1 : 0;
}

static int header_is(const char *headers, const char *name, const char *value) {
  const char *p = strstr(headers, "\r\n");
  if (!p) return 0;
  p += 2;
  size_t name_len = strlen(name), value_len = strlen(value);
  while (*p && !(p[0] == '\r' && p[1] == '\n')) {
    const char *end = strstr(p, "\r\n");
    if (!end) break;
    const char *colon = memchr(p, ':', (size_t)(end-p));
    if (colon && (size_t)(colon-p) == name_len &&
        !strncasecmp(p, name, name_len)) {
      const char *v = colon + 1;
      while (v < end && (*v == ' ' || *v == '\t')) ++v;
      while (end > v && (end[-1] == ' ' || end[-1] == '\t')) --end;
      if ((size_t)(end-v) == value_len && !memcmp(v, value, value_len)) return 1;
    }
    p = strstr(p, "\r\n");
    if (!p) break;
    p += 2;
  }
  return 0;
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

typedef struct {
  int fd;
  const char *initial;
  size_t initial_len;
} body_reader;

static ssize_t body_read(body_reader *r, void *buf, size_t len) {
  if (r->initial_len) {
    if (len > r->initial_len) len = r->initial_len;
    memcpy(buf, r->initial, len);
    r->initial += len;
    r->initial_len -= len;
    return (ssize_t)len;
  }
  return recv(r->fd, buf, len, 0);
}

static int body_exact(body_reader *r, void *buf, size_t len) {
  char *p = buf;
  while (len) {
    ssize_t n = body_read(r, p, len);
    if (n <= 0) return -1;
    p += n;
    len -= (size_t)n;
  }
  return 0;
}

static int body_line(body_reader *r, char *line, size_t cap) {
  size_t n = 0;
  for (;;) {
    char c;
    if (body_exact(r, &c, 1) < 0 || n + 1 >= cap) return -1;
    line[n++] = c;
    if (c == '\n') {
      if (n < 2 || line[n-2] != '\r') return -1;
      line[n-2] = 0;
      return 0;
    }
  }
}

static int chunk_size(const char *line, uint64_t *size) {
  uint64_t n = 0;
  int digits = 0;
  for (; *line && *line != ';'; ++line) {
    unsigned v;
    if (*line >= '0' && *line <= '9') v = (unsigned)(*line - '0');
    else if (*line >= 'a' && *line <= 'f') v = (unsigned)(*line - 'a' + 10);
    else if (*line >= 'A' && *line <= 'F') v = (unsigned)(*line - 'A' + 10);
    else return -1;
    if (n > (UINT64_MAX - v) / 16) return -1;
    n = n * 16 + v;
    ++digits;
  }
  if (!digits) return -1;
  *size = n;
  return 0;
}

static int write_file(int fd, const char *initial, size_t initial_len, uint64_t length,
                      int chunked, transfer_file *f) {
  if (!chunked && length != f->size) return 400;
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
  body_reader reader = {fd, initial, initial_len};
  uint64_t remaining = chunked ? 0 : length;
  for (;;) {
    if (chunked && !remaining) {
      char line[1024];
      if (body_line(&reader, line, sizeof(line)) < 0 || chunk_size(line, &remaining) < 0 ||
          remaining > f->size-total) { status = 400; break; }
      if (!remaining) {
        do {
          if (body_line(&reader, line, sizeof(line)) < 0) { status = 400; break; }
        } while (line[0]);
        break;
      }
    }
    if (!chunked && !remaining) break;
    size_t want = remaining < CHUNK ? (size_t)remaining : CHUNK;
    ssize_t n = body_read(&reader, buf, want);
    if (n <= 0) { status = 400; break; }
    sha256_update(&hash, buf, (size_t)n);
    size_t sent = 0;
    while (sent < (size_t)n) {
      ssize_t w = write(out, buf + sent, (size_t)n - sent);
      if (w <= 0) { status = 500; break; }
      sent += (size_t)w;
    }
    if (status != 200) break;
    total += (size_t)n;
    remaining -= (size_t)n;
    if (chunked && !remaining) {
      char crlf[2];
      if (body_exact(&reader, crlf, 2) < 0 || memcmp(crlf, "\r\n", 2)) {
        status = 400; break;
      }
    }
  }
  if (status == 200 && total != f->size) status = 400;
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
    printf("LocalSend: received %s (%" PRIu64 " bytes)\n", final, total);
  }
  return status;
}

static int check_pin(const char *query) {
  if (!pin_configured) return 403;
  time_t now = time(NULL);
  if (now - pin_window >= 60) { pin_window = now; pin_failures = 0; }
  if (pin_failures >= 5) return 429;
  char entered[32];
  if (!query || query_value(query, "pin", entered, sizeof(entered)) < 0 ||
      strcmp(entered, download_pin)) {
    ++pin_failures;
    return 401;
  }
  pin_failures = 0;
  return 200;
}

static int pin_file_path(char *path, size_t cap) {
  int n = snprintf(path, cap, "%s/.pin", output_dir);
  return n < 0 || (size_t)n >= cap ? -1 : 0;
}

static int load_pin(void) {
  char path[sizeof(output_dir) + 8];
  if (pin_file_path(path, sizeof(path)) < 0) return -1;
  int fd = open(path, O_RDONLY | O_NOFOLLOW);
  if (fd < 0) return errno == ENOENT ? 0 : -1;
  char value[8] = {0};
  ssize_t n = read(fd, value, sizeof(value));
  close(fd);
  if (n != 6 || strspn(value, "0123456789") != 6) return -1;
  memcpy(download_pin, value, 6);
  download_pin[6] = 0;
  pin_configured = 1;
  return 0;
}

static int save_pin(const char *value) {
  char path[sizeof(output_dir) + 8];
  if (pin_file_path(path, sizeof(path)) < 0) return -1;
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  if (fd < 0) return -1;
  int ok = write(fd, value, 6) == 6 && fsync(fd) == 0;
  if (close(fd) != 0) ok = 0;
  if (!ok) { unlink(path); return -1; }
  memcpy(download_pin, value, 6);
  download_pin[6] = 0;
  pin_configured = 1;
  return 0;
}

static int create_download_session(struct in_addr peer, const char *requested_id) {
  if (downloads.count && time(NULL) < downloads.expires) {
    if (downloads.peer.s_addr != peer.s_addr) return 409;
    if (requested_id && !strcmp(downloads.id, requested_id)) return 200;
  }
  memset(&downloads, 0, sizeof(downloads));
  downloads.peer = peer;
  downloads.expires = time(NULL) + 600;
  random_hex(downloads.id, 16);
  DIR *dir = opendir(output_dir);
  if (!dir) return 500;
  struct dirent *entry;
  while (downloads.count < MAX_FILES && (entry = readdir(dir))) {
    if (entry->d_name[0] == '.') continue;
    transfer_file *f = &downloads.files[downloads.count];
    size_t name_len = strlen(entry->d_name);
    if (name_len >= sizeof(f->name)) continue;
    char path[1024];
    if (snprintf(path, sizeof(path), "%s/%s", output_dir, entry->d_name) >= (int)sizeof(path)) continue;
    struct stat st;
    if (lstat(path, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 0) continue;
    memcpy(f->name, entry->d_name, name_len + 1);
    f->size = (uint64_t)st.st_size;
    random_hex(f->id, 16);
    ++downloads.count;
  }
  closedir(dir);
  return 200;
}

static int download_metadata(char *out, size_t cap) {
  char device[512];
  if (info(device, sizeof(device), -1) < 0) return -1;
  int n = snprintf(out, cap, "{\"info\":%s,\"sessionId\":\"%s\",\"files\":{",
                   device, downloads.id);
  if (n < 0 || (size_t)n >= cap) return -1;
  size_t used = (size_t)n;
  for (int i = 0; i < downloads.count; ++i) {
    char name[768];
    transfer_file *f = &downloads.files[i];
    if (json_escape(f->name, name, sizeof(name)) < 0) return -1;
    n = snprintf(out + used, cap - used,
      "%s\"%s\":{\"id\":\"%s\",\"fileName\":\"%s\",\"size\":%" PRIu64
      ",\"fileType\":\"application/octet-stream\"}",
      i ? "," : "", f->id, f->id, name, f->size);
    if (n < 0 || (size_t)n >= cap - used) return -1;
    used += (size_t)n;
  }
  if (used + 3 > cap) return -1;
  memcpy(out + used, "}}", 3);
  return 0;
}

static void ui_list(int fd, const char *pin, struct in_addr peer) {
  int status = check_pin(pin);
  if (status == 200) status = create_download_session(peer, NULL);
  if (status != 200) { reply(fd, status, NULL); return; }
  static char body[65536];
  if (download_metadata(body, sizeof(body)) < 0) { reply(fd, 500, NULL); return; }
  size_t used = strlen(body);
  if (!used || body[used-1] != '}') { reply(fd, 500, NULL); return; }
  --used;
  int n = snprintf(body + used, sizeof(body) - used, ",\"peers\":[");
  if (n < 0 || (size_t)n >= sizeof(body) - used) { reply(fd, 500, NULL); return; }
  used += (size_t)n;
  int listed = 0;
  for (int i = 0; i < MAX_PEERS; ++i) {
    discovered_peer *p = &peers[i];
    if (!p->fingerprint[0] || time(NULL) - p->seen > 120) continue;
    char name[384], id[512], ip[INET_ADDRSTRLEN];
    if (json_escape(p->alias, name, sizeof(name)) < 0 ||
        json_escape(p->fingerprint, id, sizeof(id)) < 0 ||
        !inet_ntop(AF_INET, &p->address, ip, sizeof(ip))) continue;
    n = snprintf(body + used, sizeof(body) - used,
      "%s{\"id\":\"%s\",\"alias\":\"%s\",\"address\":\"%s\",\"port\":%u,\"secure\":%s}",
      listed++ ? "," : "", id, name, ip, p->port, p->secure ? "true" : "false");
    if (n < 0 || (size_t)n >= sizeof(body) - used) { reply(fd, 500, NULL); return; }
    used += (size_t)n;
  }
  if (used + 3 > sizeof(body)) { reply(fd, 500, NULL); return; }
  memcpy(body + used, "]}", 3);
  reply(fd, 200, body);
}

static void serve_download(int fd, const char *query, struct in_addr peer) {
  char sid[64], id[64];
  if (!query || query_value(query, "sessionId", sid, sizeof(sid)) < 0 ||
      query_value(query, "fileId", id, sizeof(id)) < 0) { reply(fd, 400, NULL); return; }
  if (!downloads.count || time(NULL) > downloads.expires ||
      peer.s_addr != downloads.peer.s_addr || strcmp(sid, downloads.id)) {
    reply(fd, 403, NULL); return;
  }
  transfer_file *f = NULL;
  for (int i = 0; i < downloads.count; ++i)
    if (!strcmp(id, downloads.files[i].id)) f = &downloads.files[i];
  if (!f) { reply(fd, 404, NULL); return; }
  char path[1024];
  if (snprintf(path, sizeof(path), "%s/%s", output_dir, f->name) >= (int)sizeof(path)) {
    reply(fd, 500, NULL); return;
  }
  int file = open(path, O_RDONLY | O_NOFOLLOW);
  struct stat st;
  if (file < 0 || fstat(file, &st) < 0 || !S_ISREG(st.st_mode) ||
      st.st_size < 0 || (uint64_t)st.st_size != f->size) {
    if (file >= 0) close(file);
    reply(fd, 409, NULL); return;
  }
  char hdr[256];
  int n = snprintf(hdr, sizeof(hdr),
    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
    "Content-Length: %" PRIu64 "\r\nConnection: close\r\n\r\n", f->size);
  if (n > 0 && (size_t)n < sizeof(hdr) && send_all(fd, hdr, (size_t)n) == 0) {
    char chunk[CHUNK];
    for (;;) {
      ssize_t got = read(file, chunk, sizeof(chunk));
      if (got <= 0 || send_all(fd, chunk, (size_t)got) < 0) break;
    }
  }
  close(file);
}

static void browser_send(int fd, const char *query, struct in_addr peer,
                         const char *initial, size_t initial_len, uint64_t length) {
  char sid[64], id[64];
  if (!query || query_value(query, "sessionId", sid, sizeof(sid)) < 0 ||
      query_value(query, "fileId", id, sizeof(id)) < 0 || length > 1024) {
    reply(fd, 400, NULL); return;
  }
  if (!downloads.count || time(NULL) > downloads.expires ||
      peer.s_addr != downloads.peer.s_addr || strcmp(sid, downloads.id)) {
    reply(fd, 403, NULL); return;
  }
  transfer_file *f = NULL;
  for (int i = 0; i < downloads.count; ++i)
    if (!strcmp(id, downloads.files[i].id)) f = &downloads.files[i];
  if (!f) { reply(fd, 404, NULL); return; }
  char form[1025];
  size_t have = initial_len > length ? (size_t)length : initial_len;
  memcpy(form, initial, have);
  while (have < length) {
    ssize_t n = recv(fd, form + have, (size_t)length - have, 0);
    if (n <= 0) { reply(fd, 400, NULL); return; }
    have += (size_t)n;
  }
  form[have] = 0;
  char address[64] = {0}, port_text[16], secure_text[8], target[128] = {0};
  unsigned remote_port = DEFAULT_PORT;
  int secure = 0;
  query_value(form, "target", target, sizeof(target));
  if (*target) {
    discovered_peer *selected = NULL;
    for (int i = 0; i < MAX_PEERS; ++i)
      if (!strcmp(peers[i].fingerprint, target) && time(NULL) - peers[i].seen <= 120)
        selected = &peers[i];
    if (!selected || !inet_ntop(AF_INET, &selected->address, address, sizeof(address))) {
      reply(fd, 400, NULL); return;
    }
    remote_port = selected->port;
    secure = selected->secure;
  } else {
    if (query_value(form, "peer", address, sizeof(address)) < 0 ||
        query_value(form, "port", port_text, sizeof(port_text)) < 0) {
      reply(fd, 400, NULL); return;
    }
    char *end;
    unsigned long parsed_port = strtoul(port_text, &end, 10);
    if (*end || parsed_port == 0 || parsed_port > 65535) { reply(fd, 400, NULL); return; }
    remote_port = (unsigned)parsed_port;
    secure = query_value(form, "secure", secure_text, sizeof(secure_text)) == 0 &&
             !strcmp(secure_text, "1");
  }
  char path[1024];
  if (snprintf(path, sizeof(path), "%s/%s", output_dir, f->name) >= (int)sizeof(path)) {
    reply(fd, 500, NULL); return;
  }
  struct stat st;
  if (lstat(path, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
      (uint64_t)st.st_size != f->size) { reply(fd, 409, NULL); return; }
  int sent = send_file_to_peer(path, address, remote_port,
                               alias_name, fingerprint, port, secure);
  reply_type(fd, sent ? 500 : 200, "text/html; charset=utf-8",
             sent ? "<!doctype html><h1>Send failed</h1><p>Check the loader log.</p>" :
                    "<!doctype html><h1>File sent</h1>");
}

static int read_form(int fd, const char *headers, const char *initial,
                     size_t initial_len, char *form, size_t cap) {
  uint64_t length;
  if (parse_content_length(headers, &length) < 0 || length >= cap) return -1;
  size_t have = initial_len > length ? (size_t)length : initial_len;
  memcpy(form, initial, have);
  while (have < length) {
    ssize_t n = recv(fd, form + have, (size_t)length - have, 0);
    if (n <= 0) return -1;
    have += (size_t)n;
  }
  form[have] = 0;
  return 0;
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
  if (!strcmp(method, "GET") && !strcmp(target, "/")) {
    reply_type(fd, 200, "text/html; charset=utf-8", webui_html);
    return;
  }
  if (!strcmp(method, "GET") && !strcmp(target, "/api/ui/status")) {
    char name[384], body[512];
    if (json_escape(alias_name, name, sizeof(name)) < 0) { reply(fd, 500, NULL); return; }
    snprintf(body, sizeof(body), "{\"alias\":\"%s\",\"pinSet\":%s,\"setupLocalOnly\":true}",
             name, pin_configured ? "true" : "false");
    reply(fd, 200, body);
    return;
  }
  if (!strcmp(method, "POST") && !strcmp(target, "/api/ui/pin")) {
    if (pin_configured) { reply(fd, 409, NULL); return; }
    if ((ntohl(peer.s_addr) & 0xff000000u) != 0x7f000000u) { reply(fd, 403, NULL); return; }
    if (!header_is(header, "X-PS5-LocalSend", "1")) { reply(fd, 403, NULL); return; }
    char form[64], value[16];
    if (read_form(fd, header, header + header_len, used - header_len,
                  form, sizeof(form)) < 0 ||
        query_value(form, "pin", value, sizeof(value)) < 0 ||
        strlen(value) != 6 || strspn(value, "0123456789") != 6) {
      reply(fd, 400, NULL); return;
    }
    if (save_pin(value) < 0) { reply(fd, 500, NULL); return; }
    reply(fd, 200, "{\"pinSet\":true}");
    return;
  }
  if (!strcmp(method, "POST") && !strcmp(target, "/api/ui/list")) {
    char form[64];
    if (read_form(fd, header, header + header_len, used - header_len,
                  form, sizeof(form)) < 0) { reply(fd, 400, NULL); return; }
    ui_list(fd, form, peer);
    return;
  }
  if (!pin_configured &&
      ((!strncmp(target, "/api/localsend/v2/", 18) &&
        strcmp(target, "/api/localsend/v2/info") &&
        strcmp(target, "/api/localsend/v2/register")) || !strcmp(target, "/send"))) {
    reply(fd, 403, "{\"error\":\"Set a PIN from the PS5 Media tile before transferring files\"}");
    return;
  }
  if (!strcmp(method, "POST") && !strcmp(target, "/api/localsend/v2/prepare-download")) {
    int status = check_pin(query);
    char requested[64];
    const char *requested_id = query && query_value(query, "sessionId", requested, sizeof(requested)) == 0
      ? requested : NULL;
    if (status == 200) status = create_download_session(peer, requested_id);
    if (status != 200) { reply(fd, status, NULL); return; }
    char body[32768];
    if (download_metadata(body, sizeof(body)) < 0) { reply(fd, 500, NULL); return; }
    reply(fd, 200, body);
    return;
  }
  if (!strcmp(method, "GET") && !strcmp(target, "/api/localsend/v2/download")) {
    serve_download(fd, query, peer);
    return;
  }
  if (!strcmp(method, "POST") && !strcmp(target, "/send")) {
    uint64_t length;
    if (parse_content_length(header, &length) < 0) { reply(fd, 400, NULL); return; }
    browser_send(fd, query, peer, header + header_len, used - header_len, length);
    return;
  }
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
    int chunked;
    if (!query || query_value(query, "sessionId", sid, sizeof(sid)) < 0 ||
        query_value(query, "fileId", id, sizeof(id)) < 0 ||
        query_value(query, "token", token, sizeof(token)) < 0 ||
        parse_framing(header, &length, &chunked) < 0) { reply(fd, 400, NULL); return; }
    if (!session.count || time(NULL) > session.expires || strcmp(sid, session.id) ||
        peer.s_addr != session.peer.s_addr) { reply(fd, 403, NULL); return; }
    transfer_file *f = NULL;
    for (int i = 0; i < session.count; ++i)
      if (!strcmp(id, session.files[i].id) && !strcmp(token, session.files[i].token)) f = &session.files[i];
    if (!f || f->done) { reply(fd, 403, NULL); return; }
    int status = write_file(fd, header+header_len, used-header_len, length, chunked, f);
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
  int name_ok = 0;
#ifndef HOST_BUILD
  name_ok = sceSystemServiceParamGetString(6, alias_name, sizeof(alias_name)) == 0 && alias_name[0];
#endif
  if (!name_ok) name_ok = gethostname(alias_name, sizeof(alias_name)) == 0 && alias_name[0];
  if (!name_ok)
    strcpy(alias_name, "PlayStation 5");
  alias_name[sizeof(alias_name)-1] = 0;
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
  if (mkdir(output_dir, 0700) < 0 && errno != EEXIST) {
    perror("LocalSend output directory"); return 1;
  }
  v = getenv("LOCALSEND_PIN");
  if (v && *v) {
    if (strlen(v) != 6 || strspn(v, "0123456789") != 6) {
      fprintf(stderr, "LOCALSEND_PIN must be six digits\n"); return 1;
    }
    strcpy(download_pin, v);
    pin_configured = 1;
  } else if (load_pin() < 0) {
    fprintf(stderr, "Could not read LocalSend PIN file\n"); return 1;
  }
  if (argc > 1) {
    if (argc < 4 || argc > 6) {
      fprintf(stderr, "Usage: %s --send FILE PEER_IPV4 [PORT] [--https]\n", argv[0]);
      return 1;
    }
    if (strcmp(argv[1], "--send")) return 1;
    if (!pin_configured) {
      fprintf(stderr, "Set a LocalSend PIN from the PS5 Media tile before sending\n");
      return 1;
    }
    unsigned remote_port = DEFAULT_PORT;
    int secure = (argc >= 5 && !strcmp(argv[argc-1], "--https"));
    if (argc == 6 && !secure) return 1;
    if (argc >= 5 && strcmp(argv[4], "--https")) {
      char *end; unsigned long n = strtoul(argv[4], &end, 10);
      if (*end || n == 0 || n > 65535) return 1;
      remote_port = (unsigned)n;
    }
    return send_file_to_peer(argv[2], argv[3], remote_port, alias_name, fingerprint, port, secure);
  }
  int tcp = socket(AF_INET, SOCK_STREAM, 0);
  int udp = socket(AF_INET, SOCK_DGRAM, 0);
  if (tcp < 0 || udp < 0) { perror("socket"); return 1; }
  int one = 1;
  setsockopt(tcp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  setsockopt(udp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in bind_addr = {.sin_family=AF_INET, .sin_port=htons((uint16_t)port)};
  bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  struct sockaddr_in udp_addr = bind_addr;
#ifdef HOST_BUILD
  unsigned discovery_port = port;
#else
  unsigned discovery_port = DISCOVERY_PORT;
#endif
  udp_addr.sin_port = htons((uint16_t)discovery_port);
  if (bind(tcp, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0 ||
      listen(tcp, 8) < 0 ||
      bind(udp, (struct sockaddr *)&udp_addr, sizeof(udp_addr)) < 0) {
    perror("bind/listen"); return 1;
  }
  struct ip_mreq group = {0};
  inet_pton(AF_INET, GROUP, &group.imr_multiaddr);
  group.imr_interface.s_addr = htonl(INADDR_ANY);
  if (setsockopt(udp, IPPROTO_IP, IP_ADD_MEMBERSHIP, &group, sizeof(group)) < 0)
    perror("multicast membership");
  struct sockaddr_in multicast = {.sin_family=AF_INET, .sin_port=htons((uint16_t)discovery_port)};
  inet_pton(AF_INET, GROUP, &multicast.sin_addr);
  printf("PS5 LocalSend listening on port %u, saving to %s\n", port, output_dir);
  printf("PS5 LocalSend PIN: %s\n", pin_configured ? "configured" : "setup required in Media tile");
#ifndef HOST_BUILD
  notify_request notice = {0};
  snprintf(notice.message, sizeof(notice.message), "%s",
           pin_configured ? "PS5 LocalSend ready" : "Open LocalSend in Media to set a PIN");
  sceKernelSendNotificationRequest(0, &notice, sizeof(notice), 0);
  if (launcher_install_if_needed(port) < 0)
    fprintf(stderr, "LocalSend Media launcher installation failed\n");
#endif
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
          remember_peer(d, from.sin_addr);
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
