#include "sender.h"
#include "json.h"
#include "sha256.h"
#ifndef HOST_BUILD
#include "sce_http.h"
#include <sys/mman.h>
#endif
#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

static int send_all(int fd, const void *data, size_t len) {
  const char *p=data;
  while(len) {
    ssize_t n=send(fd,p,len,0);
    if(n<=0)return -1;
    p+=n; len-=(size_t)n;
  }
  return 0;
}

static int open_peer(const char *address, unsigned port) {
  struct sockaddr_in peer={.sin_family=AF_INET,.sin_port=htons((uint16_t)port)};
  if(inet_pton(AF_INET,address,&peer.sin_addr)!=1)return -1;
  int fd=socket(AF_INET,SOCK_STREAM,0);
  if(fd<0)return -1;
  struct timeval timeout={.tv_sec=15};
  setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
  setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
  if(connect(fd,(struct sockaddr*)&peer,sizeof(peer))<0){close(fd);return -1;}
  return fd;
}

static int url_encode(const char *input, char *out, size_t cap) {
  static const char hex[]="0123456789ABCDEF";
  size_t w=0;
  for(const unsigned char *p=(const unsigned char*)input;*p;++p) {
    unsigned char c=*p;
    int simple=(c>='a'&&c<='z')||(c>='A'&&c<='Z')||
               (c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'||c=='~';
    if(w+(simple?1:3)>=cap)return -1;
    if(simple)out[w++]=(char)c;
    else {out[w++]='%';out[w++]=hex[c>>4];out[w++]=hex[c&15];}
  }
  out[w]=0;
  return 0;
}

static int response(int fd, char *body, size_t cap) {
  char headers[16385]; size_t used=0;
  char *end=NULL;
  while(used<sizeof(headers)-1) {
    ssize_t n=recv(fd,headers+used,sizeof(headers)-1-used,0);
    if(n<=0)return -1;
    used+=(size_t)n; headers[used]=0;
    end=strstr(headers,"\r\n\r\n");
    if(end)break;
  }
  if(!end)return -1;
  int code=0;
  if(sscanf(headers,"HTTP/1.%*u %d",&code)!=1)return -1;
  size_t header_len=(size_t)(end-headers)+4;
  uint64_t expected=0;
  int has_length=0;
  const char *line=strstr(headers,"\r\n");
  if(!line)return -1;
  line+=2;
  while(line<end) {
    const char *next=strstr(line,"\r\n");
    if(!next || next>end)return -1;
    if(next-line>=15 && !strncasecmp(line,"Content-Length:",15)) {
      const char *value=line+15;
      while(value<next && (*value==' ' || *value=='\t'))++value;
      if(value==next)return -1;
      expected=0;
      for(;value<next;++value) {
        if(*value<'0' || *value>'9' || expected>(UINT64_MAX-(unsigned)(*value-'0'))/10)return -1;
        expected=expected*10+(unsigned)(*value-'0');
      }
      has_length=1;
    }
    line=next+2;
  }
  size_t n=used-header_len;
  if(has_length && expected>=cap)return -1;
  if(has_length && n>expected)n=(size_t)expected;
  if(n>=cap)return -1;
  memcpy(body,headers+header_len,n);
  while(has_length && n<expected) {
    ssize_t r=recv(fd,body+n,(size_t)expected-n,0);
    if(r==0)return -1;
    if(r<0)return -1;
    n+=(size_t)r;
  }
  body[n]=0;
  return code;
}

int send_file_to_peer(const char *path, const char *address, unsigned port,
                      const char *alias, const char *fingerprint, unsigned local_port,
                      int secure) {
#ifdef HOST_BUILD
  if(secure) {
    fprintf(stderr,"LocalSend: HTTPS sending requires a PS5 payload build\n");
    return 1;
  }
#endif
  struct in_addr parsed_address;
  if(inet_pton(AF_INET,address,&parsed_address)!=1) {
    fprintf(stderr,"LocalSend: peer must be an IPv4 address\n");
    return 1;
  }
  struct stat st;
  if(stat(path,&st)<0 || !S_ISREG(st.st_mode) || st.st_size<0) {
    fprintf(stderr,"LocalSend: file is not readable or regular: %s\n",path);
    return 1;
  }
  FILE *file=fopen(path,"rb");
  if(!file){perror(path);return 1;}
  sha256_ctx hash; sha256_init(&hash);
  char chunk[16384]; size_t n;
  while((n=fread(chunk,1,sizeof(chunk),file))>0)sha256_update(&hash,chunk,n);
  if(ferror(file)){perror("read");fclose(file);return 1;}
  unsigned char digest[32]; char hex[65];
  static const char digits[]="0123456789abcdef";
  sha256_final(&hash,digest);
  for(int i=0;i<32;++i){hex[2*i]=digits[digest[i]>>4];hex[2*i+1]=digits[digest[i]&15];}
  hex[64]=0;
  rewind(file);
  const char *base=strrchr(path,'/'); base=base?base+1:path;
  char filename[1024], alias_json[256];
  if(json_escape(base,filename,sizeof(filename))<0 ||
     json_escape(alias,alias_json,sizeof(alias_json))<0) {
    fprintf(stderr,"LocalSend: file name or alias too long\n");fclose(file);return 1;
  }
  char id[33];
  unsigned char bytes[16]; arc4random_buf(bytes,sizeof(bytes));
  for(int i=0;i<16;++i){id[2*i]=digits[bytes[i]>>4];id[2*i+1]=digits[bytes[i]&15];}
  id[32]=0;
  char metadata[4096];
  int metadata_len=snprintf(metadata,sizeof(metadata),
    "{\"info\":{\"alias\":\"%s\",\"version\":\"2.0\",\"deviceModel\":\"PlayStation 5\","
    "\"deviceType\":\"headless\",\"fingerprint\":\"%s\",\"port\":%u,\"protocol\":\"http\","
    "\"download\":false},\"files\":{\"%s\":{\"id\":\"%s\",\"fileName\":\"%s\","
    "\"size\":%" PRIu64 ",\"fileType\":\"application/octet-stream\",\"sha256\":\"%s\"}}}",
    alias_json,fingerprint,local_port,id,id,filename,(uint64_t)st.st_size,hex);
  if(metadata_len<0 || (size_t)metadata_len>=sizeof(metadata)){fclose(file);return 1;}
  int fd=-1;
  char headers[512];
  int header_len=snprintf(headers,sizeof(headers),
    "POST /api/localsend/v2/prepare-upload HTTP/1.1\r\nHost: %s:%u\r\n"
    "Content-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
    address,port,metadata_len);
  char body[8192];
  int status=-1;
  if(secure) {
#ifndef HOST_BUILD
    char url[512];
    if(snprintf(url,sizeof(url),"https://%s:%u/api/localsend/v2/prepare-upload",address,port)>=(int)sizeof(url)) {
      fclose(file);return 1;
    }
    status=sce_post(url,"application/json",metadata,(size_t)metadata_len,body,sizeof(body));
#endif
  } else {
    fd=open_peer(address,port);
    if(fd<0){fprintf(stderr,"LocalSend: cannot connect to %s:%u\n",address,port);fclose(file);return 1;}
    if(header_len>0 && (size_t)header_len<sizeof(headers) &&
       send_all(fd,headers,(size_t)header_len)==0 &&
       send_all(fd,metadata,(size_t)metadata_len)==0)
      status=response(fd,body,sizeof(body));
    close(fd);
  }
  if(status!=200){fprintf(stderr,"LocalSend: prepare-upload returned %d\n",status);fclose(file);return 1;}
  json_doc *doc=malloc(sizeof(*doc));
  if(!doc){fclose(file);return 1;}
  char session[128], token[128];
  int valid=json_parse(doc,body,strlen(body))==0 &&
    json_string(doc,json_field(doc,0,"sessionId"),session,sizeof(session))==0 &&
    json_string(doc,json_field(doc,json_field(doc,0,"files"),id),token,sizeof(token))==0;
  free(doc);
  if(!valid){fprintf(stderr,"LocalSend: invalid prepare-upload response\n");fclose(file);return 1;}
  char session_url[384], token_url[384];
  if(url_encode(session,session_url,sizeof(session_url))<0 ||
     url_encode(token,token_url,sizeof(token_url))<0) {fclose(file);return 1;}
  header_len=snprintf(headers,sizeof(headers),
    "POST /api/localsend/v2/upload?sessionId=%s&fileId=%s&token=%s HTTP/1.1\r\n"
    "Host: %s:%u\r\nContent-Type: application/octet-stream\r\n"
    "Content-Length: %" PRIu64 "\r\nConnection: close\r\n\r\n",
    session_url,id,token_url,address,port,(uint64_t)st.st_size);
  if(secure) {
#ifndef HOST_BUILD
    char url[1024];
    if(snprintf(url,sizeof(url),"https://%s:%u/api/localsend/v2/upload?sessionId=%s&fileId=%s&token=%s",
                address,port,session_url,id,token_url)>=(int)sizeof(url)) {fclose(file);return 1;}
    void *mapped=NULL;
    if(st.st_size) {
      mapped=mmap(NULL,(size_t)st.st_size,PROT_READ,MAP_PRIVATE,fileno(file),0);
      if(mapped==MAP_FAILED){perror("mmap");fclose(file);return 1;}
    }
    status=sce_post(url,"application/octet-stream",mapped?mapped:"",(size_t)st.st_size,NULL,0);
    if(mapped)munmap(mapped,(size_t)st.st_size);
#endif
  } else {
    fd=open_peer(address,port);
    if(fd<0){fclose(file);return 1;}
    int okay=header_len>0 && (size_t)header_len<sizeof(headers) &&
             send_all(fd,headers,(size_t)header_len)==0;
    uint64_t remaining=(uint64_t)st.st_size;
    while(okay && remaining) {
      size_t want=remaining<sizeof(chunk)?(size_t)remaining:sizeof(chunk);
      n=fread(chunk,1,want,file);
      if(!n || send_all(fd,chunk,n)<0){okay=0;break;}
      remaining-=n;
    }
    status=okay?response(fd,body,sizeof(body)):-1;
    close(fd);
  }
  fclose(file);
  if(status!=200 && status!=204){fprintf(stderr,"LocalSend: upload returned %d\n",status);return 1;}
  printf("LocalSend: sent %s to %s:%u\n",path,address,port);
  return 0;
}
