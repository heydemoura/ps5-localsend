/* SPDX-License-Identifier: GPL-3.0-only */
/* Copyright (C) 2026 heydemoura */
/* Media launcher adapted from kvnhrt/ps5-browser-app and
 * owendswang/ps5-web-file-manager; see THIRD_PARTY_NOTICES.md. */
#include "launcher.h"
#include <errno.h>
#include <ps5/kernel.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define TITLE_ID "LSND53317"
#define APP_DIR "/user/app/" TITLE_ID
#define SYS_DIR APP_DIR "/sce_sys"

__asm__(".section .rodata\n"
        ".global localsend_icon\n"
        ".global localsend_icon_end\n"
        ".align 16\n"
        "localsend_icon:\n"
        ".incbin \"assets/icon0.png\"\n"
        "localsend_icon_end:\n"
        ".previous\n");
extern const unsigned char localsend_icon[];
extern const unsigned char localsend_icon_end[];

int sceAppInstUtilInitialize(void);
int sceAppInstUtilTerminate(void);
int sceAppInstUtilAppInstallAll(void *);

static int file_matches(const char *path, const void *data, size_t len) {
  struct stat st;
  if (stat(path, &st) < 0 || st.st_size != (off_t)len) return 0;
  FILE *fp = fopen(path, "rb");
  if (!fp) return 0;
  unsigned char *buffer = malloc(len);
  if (!buffer) { fclose(fp); return 0; }
  int matches = fread(buffer, 1, len, fp) == len && !memcmp(buffer, data, len);
  free(buffer);
  fclose(fp);
  return matches;
}

static int write_asset(const char *path, const void *data, size_t len) {
  FILE *fp = fopen(path, "wb");
  if (!fp) return -1;
  int okay = fwrite(data, 1, len, fp) == len;
  if (fclose(fp) != 0) okay = 0;
  return okay ? 0 : -1;
}

static int install_title(void) {
  int (*install_one)(const char *, const char *, void *) = NULL;
  uint32_t handle;
  if (!kernel_dynlib_handle(-1, "libSceAppInstUtil.sprx", &handle))
    install_one = (void *)kernel_dynlib_resolve(-1, handle, "Wudg3Xe3heE");
  return install_one ? install_one(TITLE_ID, "/user/app/", NULL) :
                       sceAppInstUtilAppInstallAll(NULL);
}

int launcher_install_if_needed(unsigned port) {
  char param[512];
  int n = snprintf(param, sizeof(param),
    "{\"applicationCategoryType\":65536,\"titleId\":\"%s\","
    "\"deeplinkUri\":\"http://127.0.0.1:%u/\","
    "\"localizedParameters\":{\"defaultLanguage\":\"en-US\","
    "\"en-US\":{\"titleName\":\"LocalSend\"}}}", TITLE_ID, port);
  if (n < 0 || (size_t)n >= sizeof(param)) return -1;
  size_t icon_size = (size_t)((uintptr_t)localsend_icon_end - (uintptr_t)localsend_icon);
  if (file_matches(SYS_DIR "/param.json", param, (size_t)n) &&
      file_matches(SYS_DIR "/icon0.png", localsend_icon, icon_size)) return 0;

  int rc = sceAppInstUtilInitialize();
  if (rc) { fprintf(stderr, "launcher init: 0x%08x\n", rc); return -1; }
  int result = -1;
  if ((mkdir(APP_DIR, 0755) == 0 || errno == EEXIST) &&
      (mkdir(SYS_DIR, 0755) == 0 || errno == EEXIST) &&
      write_asset(SYS_DIR "/param.json", param, (size_t)n) == 0 &&
      write_asset(SYS_DIR "/icon0.png", localsend_icon, icon_size) == 0) {
    rc = install_title();
    if (!rc) result = 0;
    else fprintf(stderr, "launcher install: 0x%08x\n", rc);
  } else perror("launcher files");
  sceAppInstUtilTerminate();
  return result;
}
