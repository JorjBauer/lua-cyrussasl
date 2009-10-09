#ifndef __CYRUSSASL_H
#define __CYRUSSASL_H

#include <sasl/sasl.h>
#include <time.h>

#define CYRUSSASL_MAGIC 0x53415376

struct _sasl_ctx {
  unsigned long magic;
  sasl_conn_t *conn;
  char *last_message;
  char *user;
  char *authname;
  time_t timestamp;
  struct _sasl_ctx *next;
};

#endif
