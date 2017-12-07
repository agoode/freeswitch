#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <stdint.h>
#include <re.h>

int exit_code = 2;
struct mqueue *mq = NULL;
#define ID_CANCEL 1

void mqueue_handler(int id, void *data, void *arg);
void stop_remain(void);
void timeout_handler(void *arg);
int re_main_timeout(uint32_t timeout);
int sip_noop_send_handler(enum sip_transp tp, const struct sa *src, const struct sa *dst, struct mbuf *mb, void *arg);
void sip_480_response_handler(int err, const struct sip_msg *msg, void *arg);
void sip_400_response_handler(int err, const struct sip_msg *msg, void *arg);
void sip_415_response_handler(int err, const struct sip_msg *msg, void *arg);

int main()
{
  char local_ip[64] = {0}, *registrar = NULL, *tmp_buf = NULL, *callid_prefix = "autotest-invite-invalid-headers-";
  int err = 0, c = 0, callid = 0;
  struct sip_request *sip_req = NULL;
  char to_uri[1024] = {0};
  struct uri re_route = {{0}};
  struct pl pl_route = {0};
  char to_route[1024] = {0};
  struct sip *sip_stack = NULL;
  struct sa local = {{{0}}};
  struct mbuf *sdp_mbuf = mbuf_alloc(1024), *invite_mbuf = mbuf_alloc(2048);


  libre_init();
  mqueue_alloc(&mq, mqueue_handler, NULL);

  net_default_source_addr_get(AF_INET, &local);
  sa_ntop(&local, local_ip, sizeof(local_ip));
  fprintf(stderr, "Local ip is %s\n", local_ip);

  snprintf(to_uri, sizeof(to_uri), "sip:rejection@%s:5090", local_ip);
  snprintf(to_route, sizeof(to_route), "sip:%s:5090;transport=tcp", local_ip);
  pl_set_str(&pl_route, to_route);
  err = uri_decode(&re_route, &pl_route);

  if (err) {
    fprintf(stderr, "uri_decode failed [%d]\n", err);
    exit_code = 1;
    goto done;
  }

  err = sip_alloc(&sip_stack, NULL, 8,8,8, "FreeSWITCH automated call tests", NULL, NULL);

  if (err){
    fprintf(stderr, "Failed to allocate a sip stack\n");
    exit_code = 1;
    goto done;
  }

  err = sip_transp_add(sip_stack, SIP_TRANSP_TCP, &local);


  /* Test call missing Contact header with valid SDP */
  mbuf_rewind(sdp_mbuf);
  mbuf_printf(sdp_mbuf, "v=0\n");
  mbuf_printf(sdp_mbuf, "o=autotest 822 590 IN IP4 %s\n", local_ip);
  mbuf_printf(sdp_mbuf, "s=AutoTest\n");
  mbuf_printf(sdp_mbuf, "c=IN IP4 %s\n", local_ip);
  mbuf_printf(sdp_mbuf, "t=0 0\n");
  mbuf_printf(sdp_mbuf, "a=sendrecv\n");
  mbuf_printf(sdp_mbuf, "m=audio 2268 RTP/AVP 0 127\n");
  mbuf_printf(sdp_mbuf, "a=rtpmap:0 PCMU/8000\n");
  mbuf_printf(sdp_mbuf, "a=rtpmap:127 telephone-event/8000\n");
  mbuf_printf(sdp_mbuf, "a=fmtp:127 0-11\n");

  mbuf_rewind(invite_mbuf);
  mbuf_printf(invite_mbuf, "Content-Type: application/sdp\n");
  mbuf_printf(invite_mbuf, "Call-ID: %s%d\n", callid_prefix, callid++);
  mbuf_printf(invite_mbuf, "From: <sip:autotest@%s>;tag=1\n", local_ip);
  mbuf_printf(invite_mbuf, "To: <sip:rejection@%s>\n", local_ip);
  mbuf_printf(invite_mbuf, "CSeq: 1 INVITE\n");
  mbuf_printf(invite_mbuf, "Content-Length: %d\n\n", sdp_mbuf->pos);
  mbuf_printf(invite_mbuf, "%s", sdp_mbuf->buf);
  
  err = sip_requestf(&sip_req, sip_stack, 1, "INVITE", to_uri, &re_route, NULL,
		     sip_noop_send_handler, sip_400_response_handler, NULL, invite_mbuf->buf);

  fprintf(stderr, "Completed test %s%d\n", callid_prefix, callid);

  if (err) {
    fprintf(stderr, "Tried to send sip_request, but got an error:%d %s\n", err, strerror(err));
    exit_code = 1;
    goto done;
  }

  err = re_main_timeout(5);

  /* Test call wrong Content-Type header with valid SDP */
  mbuf_rewind(sdp_mbuf);
  mbuf_printf(sdp_mbuf, "v=0\n");
  mbuf_printf(sdp_mbuf, "o=autotest 822 590 IN IP4 %s\n", local_ip);
  mbuf_printf(sdp_mbuf, "s=AutoTest\n");
  mbuf_printf(sdp_mbuf, "c=IN IP4 %s\n", local_ip);
  mbuf_printf(sdp_mbuf, "t=0 0\n");
  mbuf_printf(sdp_mbuf, "a=sendrecv\n");
  mbuf_printf(sdp_mbuf, "m=audio 2268 RTP/AVP 0 127\n");
  mbuf_printf(sdp_mbuf, "a=rtpmap:0 PCMU/8000\n");
  mbuf_printf(sdp_mbuf, "a=rtpmap:127 telephone-event/8000\n");
  mbuf_printf(sdp_mbuf, "a=fmtp:127 0-11\n");

  mbuf_rewind(invite_mbuf);
  mbuf_printf(invite_mbuf, "Content-Type: text/plain\n");
  mbuf_printf(invite_mbuf, "Call-ID: %s%d\n", callid_prefix, callid++);
  mbuf_printf(invite_mbuf, "From: <sip:autotest@%s>;tag=1\n", local_ip);
  mbuf_printf(invite_mbuf, "To: <sip:rejection@%s>\n", local_ip);
  mbuf_printf(invite_mbuf, "CSeq: 1 INVITE\n");
  mbuf_printf(invite_mbuf, "Contact: <sip:autotest@%s>\n", local_ip);
  mbuf_printf(invite_mbuf, "Content-Length: %d\n\n", sdp_mbuf->pos);
  mbuf_printf(invite_mbuf, "%s", sdp_mbuf->buf);
  
  err = sip_requestf(&sip_req, sip_stack, 1, "INVITE", to_uri, &re_route, NULL,
		     sip_noop_send_handler, sip_415_response_handler, NULL, invite_mbuf->buf);

  fprintf(stderr, "Completed test %s%d\n", callid_prefix, callid);

  if (err) {
    fprintf(stderr, "Tried to send sip_request, but got an error:%d %s\n", err, strerror(err));
    exit_code = 1;
    goto done;
  }

  err = re_main_timeout(5);

  /* Test call wrong Content-Type header with no SDP */
  mbuf_rewind(invite_mbuf);
  mbuf_printf(invite_mbuf, "Content-Type: application/sdp\n");
  mbuf_printf(invite_mbuf, "Call-ID: %s%d\n", callid_prefix, callid++);
  mbuf_printf(invite_mbuf, "From: <sip:autotest@%s>;tag=1\n", local_ip);
  mbuf_printf(invite_mbuf, "To: <sip:rejection@%s>\n", local_ip);
  mbuf_printf(invite_mbuf, "CSeq: 1 INVITE\n");
  mbuf_printf(invite_mbuf, "Contact: <sip:autotest@%s>\n", local_ip);
  mbuf_printf(invite_mbuf, "Content-Length: 0\n\n");
  
  err = sip_requestf(&sip_req, sip_stack, 1, "INVITE", to_uri, &re_route, NULL,
		     sip_noop_send_handler, sip_480_response_handler, NULL, invite_mbuf->buf);

  fprintf(stderr, "Completed test %s%d\n", callid_prefix, callid);

  if (err) {
    fprintf(stderr, "Tried to send sip_request, but got an error:%d %s\n", err, strerror(err));
    exit_code = 1;
    goto done;
  }

  err = re_main_timeout(5);


 done:
  sip_close(sip_stack, 1);
  return exit_code;
}

void mqueue_handler(int id, void *data, void *arg)
{
  switch (id) {
  case ID_CANCEL:
    re_cancel();
    break;
  }
}

void stop_remain(void)
{
  mqueue_push(mq, ID_CANCEL, NULL);
}

void timeout_handler(void *arg)
{
  int *err = arg;

  *err = ETIMEDOUT;

  re_cancel();
}

int re_main_timeout(uint32_t timeout)
{
  struct tmr tmr;
  int err = 0;

  tmr_init(&tmr);

  tmr_start(&tmr, timeout * 1000, timeout_handler, &err);
  re_main(NULL);

  tmr_cancel(&tmr);
  return err;
}

int sip_noop_send_handler(enum sip_transp tp, const struct sa *src, const struct sa *dst, struct mbuf *mb, void *arg)
{
  return 0;
}

void sip_480_response_handler(int err, const struct sip_msg *msg, void *arg)
{
  if (!msg) {
    return;
  }
  
  switch(msg->scode) {
  case 100:
    break;
  case 480:
    exit_code = 0;
    stop_remain();
    break;
  default:
    fprintf(stderr, "Unexpected response code\n\n%s\n", msg->mb->buf);
    exit_code = 3;
    stop_remain();
  }
}

void sip_400_response_handler(int err, const struct sip_msg *msg, void *arg)
{
  if (!msg) {
    return;
  }
  
  switch(msg->scode) {
  case 100:
    break;
  case 400:
    exit_code = 0;
    stop_remain();
    break;
  default:
    fprintf(stderr, "Unexpected response code\n\n%s\n", msg->mb->buf);
    exit_code = 3;
    stop_remain();
  }
}

void sip_415_response_handler(int err, const struct sip_msg *msg, void *arg)
{
  if (!msg) {
    return;
  }
  
  switch(msg->scode) {
  case 100:
    break;
  case 415:
    exit_code = 0;
    stop_remain();
    break;
  default:
    fprintf(stderr, "Unexpected response code\n\n%s\n", msg->mb->buf);
    exit_code = 3;
    stop_remain();
  }
}



