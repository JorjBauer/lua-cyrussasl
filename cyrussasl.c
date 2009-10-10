#include <lua.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cyrussasl.h"
#include "luaabstract.h"

/* g_contexts is a hack, and should be replaced by using Lua userdata to 
 * track the contexts instead (and attaching them to the appropriate 
 * Lua objects). */

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

/* 
 * cyrussasl.server_init("appname")
 *
 * appname: the name of this application, from SASL's perspective.
 * 
 * This function does not return any values. On failure, it will throw an 
 * error.
 */
static int cyrussasl_sasl_server_init(lua_State *l)
{
  const char *appname;
  int numargs = lua_gettop(l);
  int err;

  if (numargs != 1) {
    lua_pushstring(l, "usage: cyrussasl.server_init(appname)");
    lua_error(l);
    return 0;
  }

  appname = tostring(l, 1);
  lua_pop(l, 1);

  err = sasl_server_init( NULL, /* Global callbacks */
			  appname ); 

  if (err != SASL_OK) {
    lua_pushstring(l, "sasl_server_init failed");
    lua_error(l);
    return 0;
  }

  return 0;
}

/* conn = cyrussasl.server_new("serice_name")
 *
 * conn: an opaque data structure (from Lua's perspective) related to this 
 *       specific authentication attempt.
 * service_name: the name of the service that's being protected by SASL (e.g.
 *               xmpp, smtp, ...)
 *
 * On error, this throws Lua error exceptions. (It is not the typical
 * case that this method might cause an error, except when attempting
 * to set up SASL initially during development.)
 */
static int cyrussasl_sasl_server_new(lua_State *l)
{
  const char *service_name;
  int numargs = lua_gettop(l);
  int err;
  sasl_conn_t *conn = NULL;
  struct _sasl_ctx *ctx = NULL;

  if (numargs != 1) {
    lua_pushstring(l, "usage: conn = cyrussasl.server_new(service_name)");
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

  ctx->callbacks[0].id      = SASL_CB_LOG;         /* Callback for error msg */
  ctx->callbacks[0].proc    = &_sasl_log;
  ctx->callbacks[0].context = ctx;
  ctx->callbacks[1].id      = SASL_CB_CANON_USER;  /* Callback for username */
  ctx->callbacks[1].proc    = &_sasl_canon_user;
  ctx->callbacks[1].context = ctx;
  ctx->callbacks[2].id      = SASL_CB_LIST_END;    /* Terminator */
  ctx->callbacks[2].proc    = NULL;
  ctx->callbacks[2].context = NULL;

  err = sasl_server_new( service_name,   /* service name (passed in) */
			 NULL,           /* localdomain              */
			 NULL,           /* userdomain               */
			 NULL,           /* iplocal                  */
			 NULL,           /* ipremote                 */
			 ctx->callbacks, /* per-connection callbacks */
			 0,              /* flags                    */
			 &conn );        /* returned connection ptr  */

  ctx->conn = conn;

  if ( err != SASL_OK ) {
    lua_pushstring(l, "sasl_server_new failed");
    lua_error(l);
    return 0;
  }

  /* Return 1 item on the stack (a lightuserdata pointer to the connection) */
  lua_pushlightuserdata(l, conn);
  return 1; /* return # of arguments returned on stack */
}

/* (err, data) = cyrussasl.server_start(conn, mech, data)
 *
 * Arguments:
 *   conn: the return result from a previous call to server_new
 *   mech: the mechanism to use during this attempt (e.g. "PLAIN" or "GSSAPI")
 *   data: any data that the client might have sent with its 
 *         mech choice. Data may be an empty string or nil. Note that 
 *         the non-nil case is specifically a Lua string object
 *         (which, by definition, is allowed to contain '\0' bytes).
 * Return values:
 *   err: the (integer) SASL error code reflecting the state of the attempt 
 *        (e.g. SASL_OK, SASL_CONTINUE, SASL_BADMECH, ...)
 *   data: data that the server wants to send to the client in order 
 *         to continue the authN attempt. Returned as a Lua string object.
 */

static int cyrussasl_sasl_server_start(lua_State *l)
{
  int numargs = lua_gettop(l);
  int err;
  sasl_conn_t *conn = NULL;
  const char *mech = NULL;
  const char *data = NULL;
  size_t len;
  unsigned outlen;

  if (numargs != 3) {
    lua_pushstring(l, 
		   "usage: "
		   "(err, data) = cyrussasl.server_start(conn, mech, data)");
    lua_error(l);
    return 0;
  }

  /* Pull arguments off of the stack... */
  conn = (sasl_conn_t *)tolightuserdata(l, 1);
  mech = tostring(l, 2);
  /* Allow the 'data' param to be nil, or an empty string. */
  if ( lua_type(l, 3) == LUA_TNIL ) {
    data = NULL;
    len = 0;
  } else {
    data = (char *)tolstring(l, 3, &len);
  }
  lua_pop(l, 3);

  err = sasl_server_start( conn,   /* returned pointer from sasl_server_new */
			   mech,   /* mech, which the client chose          */
			   data,   /* data that the client sent             */
			   len,    /* length of the client's data           */
			   &data,  /* data with which the server will reply */
			   &outlen /* size of the server's reply            */
			   );

  /* Form the reply and push onto the stack */
  lua_pushinteger(l, err);          /* SASL_CONTINUE, SASL_OK, et al  */
  lua_pushlstring(l, data, outlen); /* server's reply to the client   */
  return 2;                         /* returning 2 items on Lua stack */
}

/* (err, data) = cyrussasl.server_step(conn, data)
 *
 * Arguments:
 *   conn: the return result from a previous call to server_new
 *   data: any data that the client might have sent from the previous step.
 *         Note that data may still be an empty string or nil. (Like the 
 *         argument of the same name to server_start.)
 *
 * Return values:
 *   err: the (integer) SASL error code reflecting the state of the attempt 
 *        (e.g. SASL_OK, SASL_CONTINUE, SASL_BADMECH, ...)
 *   data: data that the server wants to send to the client in order 
 *         to continue the authN attempt. Returned as a Lua string object.
 */
static int cyrussasl_sasl_server_step(lua_State *l)
{
  int numargs = lua_gettop(l);
  int err;
  sasl_conn_t *conn = NULL;
  const char *data = NULL;
  size_t len;
  unsigned outlen;

  if (numargs != 2) {
    lua_pushstring(l, 
		   "usage: (err, data) = cyrussasl.server_step(conn, data)");
    lua_error(l);
    return 0;
  }

  conn = (sasl_conn_t *)tolightuserdata(l, 1);
  data = tolstring(l, 2, &len);
  lua_pop(l, 2);

  err = sasl_server_step( conn,
			  data,
			  len,
			  &data,
			  &outlen );

  /* Form the reply and push onto the stack */
  lua_pushinteger(l, err);          /* SASL_CONTINUE, SASL_OK, et al  */
  lua_pushlstring(l, data, outlen); /* server's reply to the client   */
  return 2;                         /* returning 2 items on Lua stack */
}

/* cyrussasl.setprop(conn)
 *
 * conn: the conn pointer from cyrussasl.server_new().
 *
 * Throws Lua errors if it fails (as it should not typically fail).
 * Does not return any value.
 */
static int cyrussasl_sasl_setprop(lua_State *l)
{
  sasl_security_properties_t secprops;
  int err;
  sasl_conn_t *conn = NULL;

  int numargs = lua_gettop(l);
  if (numargs != 1) {
    lua_pushstring(l, "usage: cyrussasl.setprop(conn)");
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

/* b64data = cyrussasl.encode64(data)
 *
 * A convenience method to use the Cyrus SASL library implementation of base64
 * encoding data. Takes, and returns, a Lua string object. Since Lua strings 
 * may contain true 8-bit data (including '\0'), the length of the data is 
 * obtained by examining the length of the string.
 */
static int cyrussasl_sasl_encode64(lua_State *l)
{
  unsigned len_out;
  int alloclen;
  char *buf = NULL;
  const char *data = NULL;
  size_t len;
  int err;

  int numargs = lua_gettop(l);
  if (numargs != 2) {
    lua_pushstring(l, "usage: b64data = cyrussasl.encode64(data, len)");
    lua_error(l);
    return 0;
  }

  len = 0;
  data = tolstring(l, 1, &len);
  lua_pop(l, 1);

  /* Allocate a new buffer that will accommodate the data in its most-possibly-
   * expanded state. */
  alloclen = ((len / 3) + 1) * 4 + 1;
  buf = malloc(alloclen);
  if (!buf) {
    lua_pushstring(l, "malloc failed");
    lua_error(l);
    return 0;
  }

  err = sasl_encode64(data, len, buf, alloclen, &len_out);
  if ( err != SASL_OK ) {
    free(buf);
    lua_pushstring(l, "sasl_encode64 failed");
    lua_error(l);
    return 0;
  }

  lua_pushlstring(l, buf, len_out);
  free(buf);
  return 1;
}

/* data = cyrussasl.decode64(b64data)
 *
 * Partner function to encode64().
 */
static int cyrussasl_sasl_decode64(lua_State *l)
{
  const char *data = NULL;
  char *outdata = NULL;
  size_t len;
  unsigned outlen;
  int err;

  int numargs = lua_gettop(l);
  if (numargs != 1) {
    lua_pushstring(l, "usage: data = cyrussasl:decode64(b64data)");
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

  /* Perform a decode-in-place, which is kosher according to docs. */
  err = sasl_decode64(data, len, outdata, len, &outlen);
  if ( err != SASL_OK ) {
    free(outdata);
    lua_pushstring(l, "sasl_decode64 failed");
    lua_error(l);
    return 0;
  }

  lua_pushlstring(l, outdata, outlen);
  free(outdata);
  return 1;
}

/* mechslist = cyrussasl.listmech(conn)
 *
 * Return all of the available mechanisms to the Cyrus SASL library.
 *
 * conn: the conn pointer from cyrussasl.server_new().
 *
 * mechslist: a Lua string object containing the mechanisms (GSSAPI, et al)
 */
static int cyrussasl_sasl_listmech(lua_State *l)
{
  int err;
  sasl_conn_t *conn = NULL;
  const char *ext_authid = NULL;
  const char *data = NULL;
  unsigned len;
  int count;

  int numargs = lua_gettop(l);
  if (numargs != 1) {
    lua_pushstring(l, "usage: mechslist = cyrussasl.listmech(conn)");
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
  return 1;
}

/* user = cyrussasl.get_username(conn)
 *
 * conn: the conn pointer from cyrussasl.server_new().
 * user: the username decoded from user data as part of the negotiation.
 *
 * Note that 'user' may be an empty string if the negotiation hasn't 
 * extracted a username for any reason (e.g. incomplete negotiation).
 * 
 * Typically used after negotation is successful to find the username 
 * associated with the authentication that just took place.
 */
static int cyrussasl_get_username(lua_State *l)
{
  sasl_conn_t *conn;

  int numargs = lua_gettop(l);
  if (numargs != 1) {
    lua_pushstring(l, "usage: user = cyrussasl.get_username(conn)");
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

/* user = cyrussasl.get_authname(conn)
 *
 * conn: the conn pointer from cyrussasl.server_new().
 * user: the authname decoded from user data as part of the negotiation.
 */
static int cyrussasl_get_authname(lua_State *l)
{
  sasl_conn_t *conn;
  int numargs = lua_gettop(l);
  if (numargs != 1) {
    lua_pushstring(l, "usage: user = cyrussasl.get_authname(conn)");
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

/* message = cyrussasl.get_message(conn)
 *
 * conn: the conn pointer from cyrussasl.server_new().
 * message: the last message emitted by the SASL library during the 
 *          negotiation. May be an empty string.
 *
 * Typically used to find the specifics about a failed negotation.
 */
static int cyrussasl_get_message(lua_State *l)
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

/* Module initializer, called from Lua when the module is loaded. */
int luaopen_cyrussasl(lua_State *l)
{
  /* Construct a new namespace table for Lua, and register it as the global 
   * named "cyrussasl".
   */

  lua_newtable(l);
  declfunc(l, "setprop", cyrussasl_sasl_setprop);
  declfunc(l, "listmech", cyrussasl_sasl_listmech);
  declfunc(l, "encode64", cyrussasl_sasl_encode64);
  declfunc(l, "decode64", cyrussasl_sasl_decode64);
  declfunc(l, "server_init", cyrussasl_sasl_server_init);
  declfunc(l, "server_new", cyrussasl_sasl_server_new);
  declfunc(l, "server_start", cyrussasl_sasl_server_start);
  declfunc(l, "server_step", cyrussasl_sasl_server_step);
  declfunc(l, "get_username", cyrussasl_get_username);
  declfunc(l, "get_authname", cyrussasl_get_authname);
  declfunc(l, "get_message", cyrussasl_get_message);
  lua_setglobal(l, "cyrussasl");

  /* ... would be nice to be able to return a second copy of that table on 
   * the stack, so that the caller can refer to it directly. Not sure what 
   * the best method is to perform the setup, but it seems that both of these
   * mechanisms are common (in the few modules I've examined).
   * For now, I'll just make a second copy and return it - but this needs
   * to be fixed later.
   *
   * hmm... if this just does a "return 1", what's on the top of the stack
   * after having called lua_setglobal? Might just be the table we're
   * looking for...
   */

  lua_newtable(l);
  declfunc(l, "setprop", cyrussasl_sasl_setprop);
  declfunc(l, "listmech", cyrussasl_sasl_listmech);
  declfunc(l, "encode64", cyrussasl_sasl_encode64);
  declfunc(l, "decode64", cyrussasl_sasl_decode64);
  declfunc(l, "server_init", cyrussasl_sasl_server_init);
  declfunc(l, "server_new", cyrussasl_sasl_server_new);
  declfunc(l, "server_start", cyrussasl_sasl_server_start);
  declfunc(l, "server_step", cyrussasl_sasl_server_step);
  declfunc(l, "get_username", cyrussasl_get_username);
  declfunc(l, "get_authname", cyrussasl_get_authname);
  declfunc(l, "get_message", cyrussasl_get_message);
  return 1;
}

