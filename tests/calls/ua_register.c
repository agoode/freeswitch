#include <stdio.h>
#include <stdint.h>
#include "re.h"
#include "baresip.h"
#include "tap.h"

struct mqueue *mq = NULL;
#define ID_CANCEL 1

int print_handler(const char *p, size_t size, void *arg);
void mqueue_handler(int id, void *data, void *arg);
void stop_remain(void);

typedef struct {
  struct ua *ua1;
  struct ua *ua2;
  
} ua_register_test_data_t;
  
static void ua_event_handler(struct ua *ua, enum ua_event ev, struct call *call, const char *prm, void *arg)
{
  int err = 0;
  ua_register_test_data_t *data = arg;
  
  if (ev == UA_EVENT_REGISTER_OK) {
    if ( ua_isregistered(data->ua1) && ua_isregistered(data->ua2)) {
      stop_remain();
    }
  } else if (ev == UA_EVENT_REGISTERING) {
    printf("Sending register\n");
  } else if (ev == UA_EVENT_UNREGISTERING) {
    printf("Sending unregister\n");
    if ( !ua_isregistered(data->ua1) && !ua_isregistered(data->ua2)) {
      stop_remain();
    }
  } else if (ev == UA_EVENT_CALL_ESTABLISHED) {
    printf("Call Established\n");
    if ( ua_call(data->ua1) && ua_call(data->ua2)) {
      stop_remain();
    }
  } else if (ev == UA_EVENT_CALL_INCOMING) {
    printf("Call Recieved\n");
    err = ua_answer(ua, call);
    ok(!err, "Call answered");
  } else if (ev == UA_EVENT_CALL_RINGING) {
    printf("Call Ringing\n");
  } else if (ev == UA_EVENT_CALL_CLOSED) {
    printf("Call Ended\n");
    stop_remain();
  } else {
    printf("Recieved an unknown event[%u](%s)\n", ev, uag_event_str(ev));
  }

}

int main()
{
  int err = 0;
  ua_register_test_data_t *data = calloc(1,sizeof(ua_register_test_data_t));
  char to_uri[1024] = {0}, aor1[1024] = {0}, aor2[1024] = {0}, local_ip[64] = {0};
  struct re_printf pf = {print_handler, NULL};
  struct sa local = {{{0}}};
  struct mod *module = NULL;
  char *mod_path = NULL;

  err = libre_init();
  ok(!err, "Libre initialization");

  net_default_source_addr_get(AF_INET, &local);
  sa_ntop(&local, local_ip, sizeof(local_ip));

  if ( access ( "/usr/local/lib/baresip/modules/g711.so", F_OK) != -1 ) {
    mod_path = "/usr/local/lib/baresip/modules/g711.so";
  } else if (access ( "/usr/lib/baresip/modules/g711.so", F_OK) != -1 ) {
    mod_path = "/usr/lib/baresip/modules/g711.so";
  }

  if ( !mod_path ) {
    return 1;
  }
  
  err = mod_load(&module, mod_path);
  ok(!err, "Load g711");

  mqueue_alloc(&mq, mqueue_handler, NULL);
  ok(!err, "Created mqueue");

  err = ua_init("FreeSWITCH auto test", true, true, true, false);
  ok(!err, "Baresip UA initialization");

  err = uag_event_register(ua_event_handler, data);
  ok(!err, "Registered Global User Agent event handler");

  /* Register first User Agent */
  snprintf(aor1, sizeof(aor1), "sip:%s:%s@%s:5080;transport=udp",
	   "1001",
	   "1234",
	   local_ip
	   );

  fprintf(stderr, "user agent1 aor1: %s\n", aor1);
  
  err = ua_alloc(&(data->ua1), aor1);
  ok(!err, "Allocation of User Agent1");

  printf("aor from ua[%s]\n", ua_aor(data->ua1));

  err = ua_register(data->ua1);
  ok(!err, "Register User Agent1");

  /* Register second User Agent */
  snprintf(aor2, sizeof(aor2), "sip:%s:%s@%s:5080;transport=udp",
	   "1002",
	   "1234",
	   local_ip
	   );

  fprintf(stderr, "user agent2 aor2: %s\n", aor2);

  err = ua_alloc(&(data->ua2), aor2);
  ok(!err, "Allocation of User Agent2");

  printf("aor from ua[%s]\n", ua_aor(data->ua2));

  err = ua_register(data->ua2);
  ok(!err, "Register User Agent2");

  err = re_main_timeout(5);
  ok(!err, "Event handled");

  snprintf(to_uri, sizeof(to_uri), "sip:%s@%s:5080", "1001", local_ip);

  err = ua_connect(data->ua2, /* originating user agent */
		   NULL, /* preallocated call struct to use(optional) */
		   NULL, /* Optional from uri, default to aor for UA */
		   to_uri, /* to uri */
		   NULL, /* optional uri params */
		   VIDMODE_OFF
		   );

  ok(!err, "Call from ua2 to ua1");

  err = re_main_timeout(15);
  ok(!err, "Event handled");

  ua_hangup(data->ua2, ua_call(data->ua2), 0, NULL);

  ua_unregister(data->ua1);

  ua_unregister(data->ua2);
  err = re_main_timeout(5);
  ok(!err, "Event handled");

  ok(!ua_isregistered(data->ua1), "Unregistered the User Agent1");
  ok(!ua_isregistered(data->ua2), "Unregistered the User Agent2");

  done_testing();

  return 0;
}


/* this code is executed in RE-MAIN context */
void mqueue_handler(int id, void *data, void *arg)
{
  switch (id) {
  case ID_CANCEL:
    re_cancel();
    break;
  }
}

/* This function can be called from ANY thread */
void stop_remain(void)
{
  /* mq is allocated with mqueue_alloc(), elsewhere */

  mqueue_push(mq, ID_CANCEL, NULL);
}


void timeout_handler(void *arg)
{
  int *err = arg;

  printf("selftest: re_main() loop timed out -- test hung..\n");

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

void message_handler(const struct pl *peer, const struct pl *ctype, struct mbuf *body, void *arg)
{
  (void)re_fprintf(stderr, "\r%r: \"%b\"\n", peer,
		   mbuf_buf(body), mbuf_get_left(body));
}

int test_print_handler(const char *p, size_t size, void *arg)
{
  (void)arg;

  if (1 != fwrite(p, size, 1, stdout))
    return ENOMEM;

  return 0;
}

