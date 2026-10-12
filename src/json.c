#include "json.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

static void space(json_doc *d, size_t *p) {
  while (*p < d->length && (d->data[*p] == ' ' || d->data[*p] == '\n' ||
                            d->data[*p] == '\r' || d->data[*p] == '\t')) ++*p;
}

static int value(json_doc *d, size_t *p, int depth) {
  if (depth > 16 || d->count >= JSON_MAX_TOKENS) return -1;
  space(d, p);
  if (*p >= d->length) return -1;
  int n = d->count++;
  json_token *t = &d->tokens[n];
  t->start = (int)*p;
  char c = d->data[*p];
  t->type = c;
  if (c == '{' || c == '[') {
    ++*p;
    space(d, p);
    char close = c == '{' ? '}' : ']';
    while (*p < d->length && d->data[*p] != close) {
      int key = value(d, p, depth + 1);
      if (key < 0) return -1;
      space(d, p);
      if (c == '{') {
        if (d->tokens[key].type != '"' || *p >= d->length || d->data[*p] != ':') return -1;
        ++*p;
        if (value(d, p, depth + 1) < 0) return -1;
        space(d, p);
      }
      if (*p < d->length && d->data[*p] == ',') {
        ++*p;
        space(d, p);
        if (*p < d->length && d->data[*p] == close) return -1;
      } else if (*p < d->length && d->data[*p] != close) return -1;
    }
    if (*p >= d->length) return -1;
    ++*p;
  } else if (c == '"') {
    ++*p;
    int closed = 0;
    while (*p < d->length) {
      unsigned char ch = (unsigned char)d->data[(*p)++];
      if (ch == '"') { closed = 1; break; }
      if (ch < 0x20) return -1;
      if (ch == '\\') {
        if (*p >= d->length) return -1;
        ch = (unsigned char)d->data[(*p)++];
        if (ch == 'u') {
          for (int i = 0; i < 4; ++i) {
            if (*p >= d->length || !isxdigit((unsigned char)d->data[(*p)++])) return -1;
          }
        } else if (!strchr("\"\\/bfnrt", ch)) return -1;
      }
    }
    if (!closed) return -1;
  } else {
    while (*p < d->length && !strchr(",]} \r\n\t", d->data[*p])) ++*p;
    size_t len = *p - (size_t)t->start;
    if (!len || (c != '-' && !isdigit((unsigned char)c) &&
                 !(len == 4 && !memcmp(d->data + t->start, "true", 4)) &&
                 !(len == 5 && !memcmp(d->data + t->start, "false", 5)) &&
                 !(len == 4 && !memcmp(d->data + t->start, "null", 4)))) return -1;
  }
  t->end = (int)*p;
  t->next = d->count;
  return n;
}

int json_parse(json_doc *d, const char *data, size_t len) {
  memset(d, 0, sizeof(*d));
  d->data = data;
  d->length = len;
  size_t p = 0;
  if (value(d, &p, 0) != 0) return -1;
  space(d, &p);
  return p == len ? 0 : -1;
}

int json_string(const json_doc *d, int i, char *out, size_t cap) {
  if (i < 0 || i >= d->count || d->tokens[i].type != '"' || !cap) return -1;
  size_t w = 0;
  for (int p = d->tokens[i].start + 1; p < d->tokens[i].end - 1; ++p) {
    unsigned char ch = (unsigned char)d->data[p];
    if (ch == '\\') {
      ch = (unsigned char)d->data[++p];
      switch (ch) {
        case 'n': ch = '\n'; break; case 'r': ch = '\r'; break;
        case 't': ch = '\t'; break; case 'b': ch = '\b'; break;
        case 'f': ch = '\f'; break;
        case 'u': {
          unsigned code = 0;
          for (int j = 0; j < 4; ++j) {
            unsigned char x = (unsigned char)d->data[++p];
            code = code * 16 + (x <= '9' ? x - '0' : (x | 32) - 'a' + 10);
          }
          if (code >= 0xd800 && code <= 0xdbff) {
            if (p + 6 >= d->tokens[i].end || d->data[p+1] != '\\' || d->data[p+2] != 'u') return -1;
            p += 2;
            unsigned low = 0;
            for (int j = 0; j < 4; ++j) {
              unsigned char x = (unsigned char)d->data[++p];
              if (!isxdigit(x)) return -1;
              low = low * 16 + (x <= '9' ? x - '0' : (x | 32) - 'a' + 10);
            }
            if (low < 0xdc00 || low > 0xdfff) return -1;
            code = 0x10000 + ((code - 0xd800) << 10) + low - 0xdc00;
          } else if (code >= 0xdc00 && code <= 0xdfff) return -1;
          if (code < 0x80) ch = (unsigned char)code;
          else {
            int bytes = code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
            if (w + (size_t)bytes >= cap) return -1;
            if (bytes == 2) { out[w++] = (char)(0xc0 | (code >> 6)); }
            else if (bytes == 3) { out[w++] = (char)(0xe0 | (code >> 12)); out[w++] = (char)(0x80 | ((code >> 6) & 63)); }
            else { out[w++] = (char)(0xf0 | (code >> 18)); out[w++] = (char)(0x80 | ((code >> 12) & 63)); out[w++] = (char)(0x80 | ((code >> 6) & 63)); }
            ch = (unsigned char)(0x80 | (code & 63));
          }
          break;
        }
        default: break;
      }
    }
    if (ch == 0 || w + 1 >= cap) return -1;
    out[w++] = (char)ch;
  }
  out[w] = 0;
  return 0;
}

int json_field(const json_doc *d, int object, const char *name) {
  if (object < 0 || object >= d->count || d->tokens[object].type != '{') return -1;
  int i = object + 1;
  while (i < d->tokens[object].next) {
    char key[128];
    if (json_string(d, i, key, sizeof(key)) < 0) return -1;
    int v = i + 1;
    if (!strcmp(key, name)) return v;
    i = d->tokens[v].next;
  }
  return -1;
}

int json_u64(const json_doc *d, int i, uint64_t *out) {
  if (i < 0 || i >= d->count) return -1;
  const json_token *t = &d->tokens[i];
  if (t->type < '0' || t->type > '9') return -1;
  uint64_t n = 0;
  for (int p = t->start; p < t->end; ++p) {
    unsigned char c = (unsigned char)d->data[p];
    if (c < '0' || c > '9' || n > (UINT64_MAX - (c - '0')) / 10) return -1;
    n = n * 10 + c - '0';
  }
  *out = n;
  return 0;
}

int json_bool(const json_doc *d, int i, int *out) {
  if (i < 0 || i >= d->count) return -1;
  const json_token *t = &d->tokens[i];
  if (t->end - t->start == 4 && !memcmp(d->data + t->start, "true", 4)) *out = 1;
  else if (t->end - t->start == 5 && !memcmp(d->data + t->start, "false", 5)) *out = 0;
  else return -1;
  return 0;
}

int json_escape(const char *in, char *out, size_t cap) {
  size_t w = 0;
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; in[i]; ++i) {
    unsigned char c = (unsigned char)in[i];
    if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') {
      if (w + 6 >= cap) return -1;
      out[w++]='\\'; out[w++]='u'; out[w++]='0'; out[w++]='0';
      out[w++]=hex[c >> 4]; out[w++]=hex[c & 15];
    } else if (c == '\n' || c == '\r' || c == '\t' || c == '"' || c == '\\') {
      if (w + 2 >= cap) return -1;
      out[w++] = '\\';
      out[w++] = c == '\n' ? 'n' : c == '\r' ? 'r' : c == '\t' ? 't' : c;
    } else {
      if (w + 1 >= cap) return -1;
      out[w++] = (char)c;
    }
  }
  if (w >= cap) return -1;
  out[w] = 0;
  return (int)w;
}
