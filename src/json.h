/* SPDX-License-Identifier: GPL-3.0-only */
/* Copyright (C) 2026 heydemoura */
#ifndef LS_JSON_H
#define LS_JSON_H
#include <stddef.h>
#include <stdint.h>

#define JSON_MAX_TOKENS 512
typedef struct {
  int start;
  int end;
  int next;
  char type;
} json_token;
typedef struct {
  const char *data;
  size_t length;
  json_token tokens[JSON_MAX_TOKENS];
  int count;
} json_doc;

int json_parse(json_doc *doc, const char *data, size_t length);
int json_field(const json_doc *doc, int object, const char *name);
int json_string(const json_doc *doc, int token, char *out, size_t cap);
int json_u64(const json_doc *doc, int token, uint64_t *out);
int json_bool(const json_doc *doc, int token, int *out);
int json_escape(const char *in, char *out, size_t cap);
#endif
