#include "sce_http.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* These imports are supplied by the PS5 payload SDK's SceNet/SceSsl/SceHttp stubs. */
int sceNetInit(void);
int sceNetPoolCreate(const char *, int, int);
int sceNetPoolDestroy(int);
int sceSslInit(size_t);
int sceSslTerm(int);
int sceHttpInit(int, int, size_t);
int sceHttpTerm(int);
int sceHttpCreateTemplate(int, const char *, int, int);
int sceHttpsSetSslCallback(int, void *, void *);
int sceHttpDeleteTemplate(int);
int sceHttpCreateConnectionWithURL(int, const char *, int);
int sceHttpDeleteConnection(int);
int sceHttpCreateRequestWithURL(int, int, const char *, uint64_t);
int sceHttpAddRequestHeader(int, const char *, const char *, int);
int sceHttpSendRequest(int, const void *, size_t);
int sceHttpGetStatusCode(int, int *);
int sceHttpReadData(int, void *, size_t);
int sceHttpDeleteRequest(int);

static int ssl_callback(int ssl_context, uint32_t errors, void *const certificates[],
                        int certificate_count, void *user) {
  (void)ssl_context; (void)errors; (void)certificates;
  (void)certificate_count; (void)user;
  /* LocalSend peers use self-signed certificates. Their identity is the
     certificate fingerprint; this transport accepts that certificate. */
  return 0;
}

static int net_pool=-1, ssl_context=-1, http_context=-1;

static int initialize(void) {
  if(http_context>=0)return 0;
  int rc=sceNetInit();
  if(rc<0)return rc;
  net_pool=sceNetPoolCreate("localsend",64*1024,0);
  if(net_pool<0)return net_pool;
  ssl_context=sceSslInit(256*1024);
  if(ssl_context<0)return ssl_context;
  http_context=sceHttpInit(net_pool,ssl_context,512*1024);
  return http_context<0?http_context:0;
}

int sce_post(const char *url, const char *content_type, const void *data,
             size_t size, char *response, size_t response_cap) {
  if(initialize()<0)return -1;
  int template=sceHttpCreateTemplate(http_context,"ps5-localsend/0.1",2,1);
  int connection=-1, request=-1, status=-1;
  if(template<0)return -1;
  if(sceHttpsSetSslCallback(template,(void *)ssl_callback,NULL)<0)goto cleanup;
  connection=sceHttpCreateConnectionWithURL(template,url,0);
  if(connection<0)goto cleanup;
  request=sceHttpCreateRequestWithURL(connection,1,url,(uint64_t)size);
  if(request<0)goto cleanup;
  if(sceHttpAddRequestHeader(request,"Content-Type",content_type,0)<0)goto cleanup;
  if(sceHttpSendRequest(request,data,size)<0)goto cleanup;
  if(sceHttpGetStatusCode(request,&status)<0){status=-1;goto cleanup;}
  if(response && response_cap) {
    size_t used=0;
    while(used+1<response_cap) {
      int n=sceHttpReadData(request,response+used,response_cap-1-used);
      if(n<0){status=-1;break;}
      if(n==0)break;
      used+=(size_t)n;
    }
    response[used]=0;
    if(used+1==response_cap)status=-1;
  }
cleanup:
  if(request>=0)sceHttpDeleteRequest(request);
  if(connection>=0)sceHttpDeleteConnection(connection);
  sceHttpDeleteTemplate(template);
  return status;
}
