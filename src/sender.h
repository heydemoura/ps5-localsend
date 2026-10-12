#ifndef LS_SENDER_H
#define LS_SENDER_H
int send_file_to_peer(const char *path, const char *address, unsigned port,
                      const char *alias, const char *fingerprint, unsigned local_port);
#endif
