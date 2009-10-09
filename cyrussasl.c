#include <lua.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cyrussasl.h"
#include "luaabstract.h"

struct _sasl_ctx *g_contexts = NULL;

/* _find_context is a temporary hack to walk the linked list of contexts; they 
 * should be removed, and treated as Lua userdata instead. */

struct _sasl_ctx *_find_context(sasl_conn_t *conn)
{
  struct _sasl_ctx *ptr = g_contexts;

  while (1) {
    if (!ptr)
      return NULL;

    if (ptr->magic != CYRUSSASL_MAGIC)
      return NULL;

    if (ptr->conn == conn)
      return ptr;

    ptr = ptr->next;
  }

  /* NOTREACHED */
}

struct _sasl_ctx *_new_context()
{
  struct _sasl_ctx *ret = NULL;

  ret = malloc(sizeof(struct _sasl_ctx));
  if (!ret)
    return NULL;

  ret->magic        = CYRUSSASL_MAGIC;
  ret->conn         = NULL;
  ret->last_message = NULL;
  ret->user         = NULL;
  ret->timestamp    = time(NULL);
  ret->next         = NULL;

  /* This is a temporary hack, placing it on g_contexts. The entire notion
   * of keeping this in a linked list needs to be removed; this should be Lua
   * table metadata.
   */
  ret->next = g_contexts;
  g_contexts = ret;

  return ret;
}

void _free_context(struct _sasl_ctx *ctx)
{
  if (!ctx || ctx->magic != CYRUSSASL_MAGIC) 
    return;

  if (ctx->last_message)
    free(ctx->last_message);
  if (ctx->user)
    free(ctx->user);

  free(ctx);
}

void _set_context_conn(struct _sasl_ctx *ctx, sasl_conn_t *conn)
{
  if (!ctx || ctx->magic != CYRUSSASL_MAGIC)
    return;

  ctx->conn = conn;
  ctx->timestamp = time(NULL);
}

void _set_context_message(struct _sasl_ctx *ctx, const char *msg)
{
  if (!ctx || ctx->magic != CYRUSSASL_MAGIC)
    return;
  if (!msg)
    return;

  if (ctx->last_message)
    free(ctx->last_message);
  ctx->last_message = malloc(strlen(msg)+1);
  if (!ctx->last_message)
    return;

  strcpy(ctx->last_message, msg); // only as safe as the strlen() was...

  ctx->timestamp = time(NULL);
}

void _set_context_user(struct _sasl_ctx *ctx, const char *usr)
{
  if (!ctx || ctx->magic != CYRUSSASL_MAGIC)
    return;
  if (!usr)
    return;

  if (ctx->user)
    free(ctx->user);
  ctx->user = malloc(strlen(usr)+1);
  if (!ctx->user)
    return;

  strcpy(ctx->user, usr); // only as safe as the strlen() was...

  ctx->timestamp = time(NULL);
}

const char *_username(sasl_conn_t *conn)
{
  struct _sasl_ctx *p = _find_context(conn);
  if (!p)
    return NULL;

  return p->user;
}

const char *_authname(sasl_conn_t *conn)
{
  struct _sasl_ctx *p = _find_context(conn);
  if (!p)
    return NULL;

  return p->authname;
}

const char *_message(sasl_conn_t *conn)
{
  struct _sasl_ctx *p = _find_context(conn);
  if (!p)
    return NULL;

  return p->last_message;
}

static int _sasl_log(void *context,
		     int priority,
		     const char *message)
{
  if (! message)
    return SASL_BADPARAM;

  _set_context_message(context, message);

  return SASL_OK;
}

int _sasl_canon_user(sasl_conn_t *conn,
		     void *context,
		     const char *user, unsigned ulen,
		     unsigned flags,
		     const char *user_realm,
		     char *out_user, unsigned out_umax,
		     unsigned *out_ulen)
{
  if (strlen(user) >= out_umax) {
      return SASL_BUFOVER;
  }

  strcpy(out_user, user);
  *out_ulen = strlen(user);

  _set_context_user(context, out_user);

  return SASL_OK;
}

// cyrussasl:server_init("appname")
static int _cyrussasl_sasl_server_init(lua_State *l)
{
  const char *appname;
  int numargs = lua_gettop(l);
  int err;

  if (numargs != 1) {
    lua_pushstring(l, "usage: cyrussasl:server_init(appname)");
    lua_error(l);
    return 0;
  }

  appname = tostring(l, 1);
  lua_pop(l, 1);

  err = sasl_server_init( NULL, // callbacks
			  appname ); 

  if (err != SASL_OK) {
    lua_pushstring(l, "sasl_server_init failed");
    lua_error(l);
    return 0;
  }

  return 0;
}


// conn = cyrussasl:server_new()
static int _cyrussasl_sasl_server_new(lua_State *l)
{
  const char *service_name;
  int numargs = lua_gettop(l);
  int err;
  sasl_conn_t *conn = NULL;
  struct _sasl_ctx *ctx = NULL;

  if (numargs != 1) {
    lua_pushstring(l, "usage: cyrussasl:server_new(service_name)");
    lua_error(l);
    return 0;
  }

  service_name = tostring(l, 1);
  lua_pop(l, 1);

  ctx = _new_context();
  if (!ctx) {
    lua_pushstring(l, "Unable to allocate a new context");
    lua_error(l);
    return 0;
  }

  ctx->callbacks[0].id = SASL_CB_LOG;
  ctx->callbacks[0].proc = &_sasl_log;
  ctx->callbacks[0].context = ctx;
  ctx->callbacks[1].id = SASL_CB_CANON_USER;
  ctx->callbacks[1].proc = &_sasl_canon_user;
  ctx->callbacks[1].context = ctx;
  ctx->callbacks[2].id = SASL_CB_LIST_END;
  ctx->callbacks[2].proc = NULL;
  ctx->callbacks[2].context = NULL;

  err = sasl_server_new( service_name, // service
			 NULL,   // localdomain
			 NULL,   // userdomain
			 NULL,   // iplocal
			 NULL,   // ipremote
			 ctx->callbacks, // callbacks
			 0,      // flags
			 &conn ); // connection ptr (returned on success)

  ctx->conn = conn;

  if ( err != SASL_OK ) {
    lua_pushstring(l, "sasl_server_new failed");
    lua_error(l);
    return 0;
  }

  // push the pointer on the lua stack as a return result
  lua_pushlightuserdata(l, conn);

  // this '1' indicates we're returning one item on the stack
  return 1;
}

// (err, data, datalen) = cyrussasl:server_start(conn, mech, data, datalen)
static int _cyrussasl_sasl_server_start(lua_State *l)
{
  int numargs = lua_gettop(l);
  int err;
  sasl_conn_t *conn = NULL;
  const char *mech = NULL;
  const char *data = NULL;
  size_t len;
  unsigned outlen;

  if (numargs != 4) {
    lua_pushstring(l, "usage: conn = cyrussasl:server_start(conn,mech,data,len)");
    lua_error(l);
    return 0;
  }

  // pull arguments off of the lua stack.
  conn = (sasl_conn_t *)tolightuserdata(l, 1);
  mech = tostring(l, 2);
  // data may be nil, or a pointer to data...
  if ( lua_type(l, 3) == LUA_TNIL ) {
    data = NULL;
    len = 0;
  } else {
    data = (char *)tolstring(l, 3, &len);
  }
  // FIXME: not using arg 4
  //  len = tointeger(l, 4);
  lua_pop(l, 4);

  //  outlen = len;

  err = sasl_server_start( conn,
			   mech,
			   data,
			   len,
			   &data,
			   &outlen );

  // push the result code, data and len
  lua_pushinteger(l, err); // might be SASL_CONTINUE or SASL_OK
  lua_pushlstring(l, data, outlen);
  lua_pushinteger(l, outlen);
  return 3;
}

// (err, data, datalen) = cyrussasl:server_step(conn, data, datalen)
static int _cyrussasl_sasl_server_step(lua_State *l)
{
  int numargs = lua_gettop(l);
  int err;
  sasl_conn_t *conn = NULL;
  const char *data = NULL;
  size_t len;
  unsigned outlen;

  if (numargs != 3) {
    lua_pushstring(l, "usage: conn = cyrussasl:server_step(conn,data,len)");
    lua_error(l);
    return 0;
  }

  conn = (sasl_conn_t *)tolightuserdata(l, 1);
  data = tolstring(l, 2, &len);
  // FIXME: not using arg 3
  //  len = tointeger(l, 3);
  lua_pop(l, 3);

  err = sasl_server_step( conn,
			  data,
			  len,
			  &data,
			  &outlen );
  /*
    -- same as sasl_server_start: no need to explicitly catch the error here,
    -- as the caller can check the error code
  if ( err != SASL_OK && err != SASL_CONTINUE) {
    lua_pushstring(l, "sasl_server_step failed");
    lua_error(l);
    return 0;
  }
  */

  // push the result code, data and len
  lua_pushinteger(l, err); // might be SASL_CONTINUE or SASL_OK
  lua_pushlstring(l, data, outlen);
  lua_pushinteger(l, outlen);

  return 3;
}

// cyrussasl:setprop(conn)
static int _cyrussasl_sasl_setprop(lua_State *l)
{
  sasl_security_properties_t secprops;
  int err;
  sasl_conn_t *conn = NULL;

  int numargs = lua_gettop(l);
  if (numargs != 1) {
    lua_pushstring(l, "usage: cyrussasl:setprop(conn)");
    lua_error(l);
    return 0;
  }

  conn = (sasl_conn_t *)tolightuserdata(l, -1);
  lua_pop(l, 1);

  memset(&secprops, 0L, sizeof(secprops));
  secprops.max_ssf = UINT_MAX;
  
  err = sasl_setprop(conn, SASL_SEC_PROPS, &secprops);
  if ( err != SASL_OK ) {
    lua_pushstring(l, "sasl_setprop failed");
    lua_error(l);
    return 0;
  }

  return 0;
}

// b64data=cyrussasl:encode64(data, len)
static int _cyrussasl_sasl_encode64(lua_State *l)
{
  unsigned len_out;
  int alloclen;
  char *buf = NULL;
  const char *data = NULL;
  size_t len;
  int err;

  int numargs = lua_gettop(l);
  if (numargs != 2) {
    lua_pushstring(l, "usage: cyrussasl:encode64(data, len)");
    lua_error(l);
    return 0;
  }

  len = 0;
  data = tolstring(l, 1, &len);
  // fixme: ignoring the length argument.
  //len = tointeger(l, 2);
  lua_pop(l, 2);

  // pack up the list of <count> mechanisms stored in <buf/len> as a base64
  // encoded buffer

  alloclen = ((len / 3) + 1) * 4 + 1;
  buf = malloc(alloclen);
  if (!buf) {
    lua_pushstring(l, "malloc failed");
    lua_error(l);
    return 0;
  }

  err = sasl_encode64(data, len, buf, alloclen, &len_out);
  if ( err != SASL_OK ) {
    lua_pushstring(l, "sasl_encode64 failed");
    lua_error(l);
    return 0;
  }

  lua_pushlstring(l, buf, len_out);
  free(buf);
  return 1;
}

// data, len = cyrussasl:decode64(b64data)
static int _cyrussasl_sasl_decode64(lua_State *l)
{
  const char *data = NULL;
  char *outdata = NULL;
  size_t len;
  unsigned outlen;
  int err;

  int numargs = lua_gettop(l);
  if (numargs != 1) {
    lua_pushstring(l, "usage: cyrussasl:decode64(b64data)");
    lua_error(l);
    return 0;
  }

  data = tostring(l, 1);
  lua_pop(l, 1);
  len = strlen(data);

  outdata = malloc(len);
  if (!outdata) {
    lua_pushstring(l, "failed to malloc in decode64");
    lua_error(l);
    return 0;
  }

  // perform a decode-in-place. According to docs, this is kosher.
  err = sasl_decode64(data, len, outdata, len, &outlen);
  if ( err != SASL_OK ) {
    free(outdata);
    lua_pushstring(l, "sasl_decode64 failed");
    lua_error(l);
    return 0;
  }

  lua_pushlstring(l, outdata, outlen);
  lua_pushinteger(l, outlen);
  free(outdata);

  return 2;
}

// mechsdata, len = cyrussasl:listmech(conn)
static int _cyrussasl_sasl_listmech(lua_State *l)
{
  int err;
  sasl_conn_t *conn = NULL;
  const char *ext_authid = NULL;
  const char *data = NULL;
  unsigned len;
  int count;

  int numargs = lua_gettop(l);
  if (numargs != 1) {
    lua_pushstring(l, "usage: cyrussasl:listmech(conn)");
    lua_error(l);
    return 0;
  }

  conn = (sasl_conn_t *)tolightuserdata(l, -1);
  lua_pop(l, 1);

  err = sasl_listmech(conn,
		      ext_authid,
		      NULL,
		      " ",
		      NULL,
		      &data,
		      &len,
		      &count);
  if ( err != SASL_OK ) {
    lua_pushstring(l, "sasl_listmech failed");
    lua_error(l);
    return 0;
  }

  lua_pushlstring(l, data, len);
  lua_pushinteger(l, len);

  return 2;
}

// cyrussasl:get_username(conn)
// may return an empty string if the negotiation hasn't yet finished
static int _cyrussasl_get_username(lua_State *l)
{
  sasl_conn_t *conn;

  int numargs = lua_gettop(l);
  if (numargs != 1) {
    lua_pushstring(l, "usage: cyrussasl:get_username(conn)");
    lua_error(l);
    return 0;
  }

  conn = (sasl_conn_t *)tolightuserdata(l, -1);
  lua_pop(l, 1);

  if (_username(conn))
    lua_pushstring(l, _username(conn));
  else
    lua_pushstring(l, "");

  return 1;
}

// cyrussasl:get_authname(conn)
// may return an empty string if the negotiation hasn't yet finished
static int _cyrussasl_get_authname(lua_State *l)
{
  sasl_conn_t *conn;
  int numargs = lua_gettop(l);
  if (numargs != 1) {
    lua_pushstring(l, "usage: cyrussasl:get_authname(conn)");
    lua_error(l);
    return 0;
  }

  conn = (sasl_conn_t *)tolightuserdata(l, -1);
  lua_pop(l, 1);

  if (_authname(conn))
    lua_pushstring(l, _authname(conn));
  else
    lua_pushstring(l, "");

  return 1;
}

// cyrussasl:get_message(conn)
// may return an empty string if the negotiation hasn't logged anything
static int _cyrussasl_get_message(lua_State *l)
{
  sasl_conn_t *conn;
  int numargs = lua_gettop(l);
  if (numargs != 1) {
    lua_pushstring(l, "usage: cyrussasl:get_message(conn)");
    lua_error(l);
    return 0;
  }

  conn = (sasl_conn_t *)tolightuserdata(l, -1);
  lua_pop(l, 1);

  if (_message(conn))
    lua_pushstring(l, _message(conn));
  else
    lua_pushstring(l, "");

  return 1;
}

// module initializer
int luaopen_cyrussasl(lua_State *l)
{
  // Construct a new namespace table for Lua, and register it as the global 
  // named "cyrussasl".

  // put new table on the stack
  lua_newtable(l);

  // 
  declfunc(l, "setprop", _cyrussasl_sasl_setprop);
  declfunc(l, "listmech", _cyrussasl_sasl_listmech);
  declfunc(l, "encode64", _cyrussasl_sasl_encode64);
  declfunc(l, "decode64", _cyrussasl_sasl_decode64);
  declfunc(l, "server_init", _cyrussasl_sasl_server_init);
  declfunc(l, "server_new", _cyrussasl_sasl_server_new);
  declfunc(l, "server_start", _cyrussasl_sasl_server_start);
  declfunc(l, "server_step", _cyrussasl_sasl_server_step);
  declfunc(l, "get_username", _cyrussasl_get_username);
  declfunc(l, "get_authname", _cyrussasl_get_authname);
  declfunc(l, "get_message", _cyrussasl_get_message);

  lua_setglobal(l, "cyrussasl");

  // ... and leaving a copy on the stack, too.
  lua_newtable(l);
  declfunc(l, "setprop", _cyrussasl_sasl_setprop);
  declfunc(l, "listmech", _cyrussasl_sasl_listmech);
  declfunc(l, "encode64", _cyrussasl_sasl_encode64);
  declfunc(l, "decode64", _cyrussasl_sasl_decode64);
  declfunc(l, "server_init", _cyrussasl_sasl_server_init);
  declfunc(l, "server_new", _cyrussasl_sasl_server_new);
  declfunc(l, "server_start", _cyrussasl_sasl_server_start);
  declfunc(l, "server_step", _cyrussasl_sasl_server_step);
  declfunc(l, "get_username", _cyrussasl_get_username);
  declfunc(l, "get_authname", _cyrussasl_get_authname);
  declfunc(l, "get_message", _cyrussasl_get_message);

  //SASL_CB_AUTHNAME

  return 1;
}

