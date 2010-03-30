#ifndef __CONTEXT_H
#define __CONTEXT_H

#include <lua.h>
#include <lauxlib.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "luaabstract.h"

#define CYRUSSASL_MAGIC 0x53415376
#define MODULENAME      "cyrussasl"

struct _sasl_ctx {
  unsigned long   magic;
  lua_State       *L;
  sasl_conn_t     *conn;
  sasl_callback_t callbacks[3];
  char            *last_message;
  char            *user;
  unsigned        ulen;
  char            *authname;
  int             canon_cb_ref;
};

struct _sasl_ctx **new_context(lua_State *L);
struct _sasl_ctx  *get_context(lua_State *l, int idx);

int  gc_context  (lua_State *L);
void free_context(struct _sasl_ctx *ctx);

void set_context_conn    (struct _sasl_ctx *ctx, sasl_conn_t *conn);
void set_context_message (struct _sasl_ctx *ctx, const char *msg);
void set_context_user    (struct _sasl_ctx *ctx, const char *usr, unsigned ulen);
void set_context_authname(struct _sasl_ctx *ctx, const char *usr);

const char *get_context_message (struct _sasl_ctx *ctx);
const char *get_context_user    (struct _sasl_ctx *ctx, unsigned *ulen_out);
const char *get_context_authname(struct _sasl_ctx *ctx);

#endif
