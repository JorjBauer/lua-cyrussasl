#include <lua.h>
#include <lauxlib.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "context.h"
#include "luaabstract.h"

#ifndef VERSION
#define VERSION "undefined"
#endif

/* It's unfortunate that Cyrus SASL doesn't export these strings itself; it 
 * only exports constants that refer to them. We could go crazy and 
 * dynamically build this list but that seems like a lot of overhead for 
 * something that they're unlikely to change.
 * Of course, now that I've written this, they'll certainly reorder the 
 * error levels and these strings will no longer reflect reality :P
 */
static const char * const level_strings[] = {
	"none",
	"error",
	"fail",
	"warn",
	"note",
	"debug",
	"trace",
	"pass",
	NULL
};

static int log_cb_ref = LUA_REFNIL;
static int minimum_log_prio = SASL_LOG_NONE;

static int _sasl_s_log(void *context,
		       int priority,
		       const char *message)
{
  struct _sasl_ctx *ctxp = context;

  if (!message || !context || ctxp->magic != CYRUSSASL_MAGIC)
    return SASL_BADPARAM;

  if (priority < 0 || priority >= sizeof(level_strings) - 1)
    return SASL_BADPARAM;

  set_context_message(context, message);

  if (priority != SASL_LOG_NONE && priority <= minimum_log_prio &&
	log_cb_ref != LUA_REFNIL) {
    /* Function to call */
    lua_rawgeti(ctxp->L, LUA_REGISTRYINDEX, log_cb_ref);

    /* Message */
    lua_pushstring(ctxp->L, message);

    /* Priority */
    lua_pushstring(ctxp->L, level_strings[priority]);

    /* Perform: cb(message, priority) */
    lua_call(ctxp->L, 2, 0);
  }

  return SASL_OK;
}

static int _sasl_s_canon_user(sasl_conn_t *conn,
			      void *context,
			      const char *user, unsigned ulen,
			      unsigned flags,
			      const char *user_realm,
			      char *out_user, unsigned out_umax,
			      unsigned *out_ulen)
{
  struct _sasl_ctx *ctxp = context;

  if (!conn || !context || !user || ctxp->magic != CYRUSSASL_MAGIC)
    return SASL_BADPARAM;

  if (!(flags & SASL_CU_AUTHID) && !(flags & SASL_CU_AUTHZID))
    return SASL_BADPARAM;

  if (!out_user || !out_ulen || out_umax == 0)
    return SASL_BADPARAM;

  if (ctxp->canon_cb_ref == LUA_REFNIL) {
    if (ulen >= out_umax)
      return SASL_BUFOVER;

    /* out_user may be the same as user, so memmove, not memcpy */
    memmove(out_user, user, ulen);
    out_user[ulen] = '\0';
    *out_ulen = ulen;

    set_context_user(context, user, ulen);
    return SASL_OK;
  }

  /* We have a callback to deal with. */

  int ret = SASL_OK;
  const char *str = NULL;
  size_t len = 0;
  
  /* Function to call */
  lua_rawgeti(ctxp->L, LUA_REGISTRYINDEX, ctxp->canon_cb_ref);
  
  /* Username */
  lua_pushlstring(ctxp->L, user, ulen);
  /* Realm */
  lua_pushstring(ctxp->L, user_realm);
  /* flags (the type of username) */
  if ((flags & SASL_CU_AUTHID) && (flags & SASL_CU_AUTHZID))
    lua_pushliteral(ctxp->L, "both");
  else if (flags & SASL_CU_AUTHID)
    lua_pushliteral(ctxp->L, "authcid");
  else
    lua_pushliteral(ctxp->L, "authzid");
  /* Perform: str = cb(user, user_realm, "both|authcid|authzid") */
  lua_call(ctxp->L, 3, 1);
  
  /* Get the result */
  str = lua_tolstring(ctxp->L, -1, &len);
  if (str == NULL)
    ret = SASL_BADPROT;
  else if (len >= out_umax)
    ret = SASL_BUFOVER;
  else {
    memcpy(out_user, str, len + 1);
    *out_ulen = len;
  }
  
  /* Pop the result of the call off the stack */
  lua_pop(ctxp->L, 1);

  if (ret == SASL_OK)
    set_context_user(context, out_user, *out_ulen);
  else
    set_context_user(context, NULL, 0);

  return ret;
}

/* version = cyrussasl.get_version()
 *
 * Returns a string of the lua_cyrussasl library version.
 */
static int cyrussasl_get_version(lua_State *l)
{
  int numargs = lua_gettop(l);
  if (numargs != 0) {
    lua_pushstring(l, "usage: cyrussasl.get_version()");
    lua_error(l);
    return 0;
  }

  lua_pushstring(l, VERSION);

  return 1;
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

  err = sasl_server_init( NULL, /* Global callbacks */
			  appname ); 

  if (err != SASL_OK) {
    lua_pushstring(l, "sasl_server_init failed");
    lua_error(l);
    return 0;
  }

  return 0;
}

static void _init_server_callbacks(struct _sasl_ctx *ctx)
{
  ctx->callbacks[0].id      = SASL_CB_LOG;         /* Callback for error msg */
  ctx->callbacks[0].proc    = (void *) &_sasl_s_log;
  ctx->callbacks[0].context = ctx;
  ctx->callbacks[1].id      = SASL_CB_CANON_USER;  /* Callback for username */
  ctx->callbacks[1].proc    = (void *)&_sasl_s_canon_user;
  ctx->callbacks[1].context = ctx;
  ctx->callbacks[2].id      = SASL_CB_LIST_END;    /* Terminator */
  ctx->callbacks[2].proc    = NULL;
  ctx->callbacks[2].context = NULL;
}

static int _sasl_c_simple(void *context, 
			  int id,
			  const char **result,
			  unsigned *len)
{
  struct _sasl_ctx *ctxp = context;

  if (!context || ctxp->magic != CYRUSSASL_MAGIC || !result)
    return SASL_BADPARAM;

  switch (id) {
  case SASL_CB_USER:
    *result = get_context_user(ctxp, len);
    break;
  case SASL_CB_AUTHNAME:
    *result = get_context_authname(ctxp);
    if (len) {
      *len = strlen(*result);
    }
    break;
  default:
    return SASL_BADPARAM;
  }

  return SASL_OK;
}


static void _init_client_callbacks(struct _sasl_ctx *ctx)
{
  ctx->callbacks[0].id      = SASL_CB_USER; 
  ctx->callbacks[0].proc    = (void *)&_sasl_c_simple;
  ctx->callbacks[0].context = ctx;
  ctx->callbacks[0].id      = SASL_CB_AUTHNAME;
  ctx->callbacks[0].proc    = (void *)&_sasl_c_simple;
  ctx->callbacks[0].context = ctx;
  ctx->callbacks[1].id      = SASL_CB_LIST_END;
  ctx->callbacks[1].proc    = NULL;
  ctx->callbacks[1].context = NULL;
}

/* conn = cyrussasl.server_new("serice_name", "host FQDN", "user realm",
 *                             "iplocal", "ipremote")
 *
 * conn: an opaque data structure (from Lua's perspective) related to this 
 *       specific authentication attempt.
 * service_name: the name of the service that's being protected by SASL (e.g.
 *               xmpp, smtp, ...)
 * host FQDN: the fully-qualified domain name of the server that users 
 *            are connecting to. May be nil.
 * user realm: the authentication user realm to use for AuthN purposes. 
 *             May be nil.
 * iplocal: Either nil or a string of the form "a.b.c.d;port" (for IPv4). 
 *          Used to tell the SASL library what the local side of the connection
 *          is using.
 * ipremote: Either nil or a string denoting the remote side of the connection.
 *
 * On error, this throws Lua error exceptions. (It is not the typical
 * case that this method might cause an error, except when attempting
 * to set up SASL initially during development.)
 */
static int cyrussasl_sasl_server_new(lua_State *l)
{
  const char *service_name, *fqdn, *realm, *iplocal, *ipremote;
  int numargs = lua_gettop(l);
  int err;
  sasl_conn_t *conn = NULL;
  struct _sasl_ctx **ctxp = NULL;

  if (numargs != 5) {
    lua_pushstring(l, 
		   "usage: "
		   "conn = "
		   "cyrussasl.server_new(service_name, fqdn, realm, "
		   "iplocal, ipremote)");
    lua_error(l);
    return 0;
  }

  service_name = tostring(l, 1);
  fqdn = tostring(l, 2);
  realm = tostring(l, 3);
  iplocal = tostring(l, 4);
  ipremote = tostring(l, 5);

  ctxp = new_context(l);
  if (!ctxp) {
    lua_pushstring(l, "Unable to allocate a new context");
    lua_error(l);
    return 0;
  }

  _init_server_callbacks(*ctxp);

  err = sasl_server_new( service_name,       /* service name (passed in) */
			 fqdn,               /* serverFQDN               */
			 realm,              /* user_realm               */
			 iplocal,            /* iplocalport              */
			 ipremote,           /* ipremoteport             */
			 (*ctxp)->callbacks, /* per-connection callbacks */
			 0,                  /* flags                    */
			 &conn );            /* returned connection ptr  */

  (*ctxp)->conn = conn;

  if ( err != SASL_OK ) {
    lua_pushstring(l, "sasl_server_new failed");
    lua_error(l);
    return 0;
  }

  /* Return 1 item on the stack (a userdata pointer to our state struct).
   * It was already pushed on the stack by new_context(). */

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
  struct _sasl_ctx *ctx = NULL;
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

  ctx = get_context(l, 1);
  mech = tostring(l, 2);
  /* Allow the 'data' param to be nil, or an empty string. */
  if ( lua_type(l, 3) == LUA_TNIL ) {
    data = NULL;
    len = 0;
  } else {
    data = tolstring(l, 3, &len);
  }

  err = sasl_server_start( ctx->conn, /* saved sasl connection              */
			   mech,   /* mech, which the client chose          */
			   data,   /* data that the client sent             */
			   len,    /* length of the client's data           */
			   &data,  /* data with which the server will reply */
			   &outlen /* size of the server's reply            */
			   );

  /* Form the reply and push onto the stack */
  lua_pushinteger(l, err);          /* SASL_CONTINUE, SASL_OK, et al  */
  if (data) {
    lua_pushlstring(l, data, outlen); /* server's reply to the client   */
  } else {
    lua_pushnil(l);
  }
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
  struct _sasl_ctx *ctx = NULL;
  const char *data = NULL;
  size_t len;
  unsigned outlen;

  if (numargs != 2) {
    lua_pushstring(l, 
		   "usage: (err, data) = cyrussasl.server_step(conn, data)");
    lua_error(l);
    return 0;
  }

  ctx = get_context(l, 1);
  data = tolstring(l, 2, &len);

  err = sasl_server_step( ctx->conn,
			  data,
			  len,
			  &data,
			  &outlen );

  /* Form the reply and push onto the stack */
  lua_pushinteger(l, err);          /* SASL_CONTINUE, SASL_OK, et al  */
  if (data) {
    lua_pushlstring(l, data, outlen); /* server's reply to the client   */
  } else {
    lua_pushnil(l);
  }
  return 2;                         /* returning 2 items on Lua stack */
}

/* 
 * cyrussasl.client_init()
 *
 * This function does not return any values. On failure, it will throw an 
 * error.
 */
static int cyrussasl_sasl_client_init(lua_State *l)
{
  int numargs = lua_gettop(l);
  int err;

  if (numargs != 0) {
    lua_pushstring(l, "usage: cyrussasl.client_init()");
    lua_error(l);
    return 0;
  }

  err = sasl_client_init( NULL ); /* Global callbacks */

  if (err != SASL_OK) {
    lua_pushstring(l, "sasl_client_init failed");
    lua_error(l);
    return 0;
  }

  return 0;
}

/* conn = cyrussasl.client_new("serice_name", "host FQDN", 
 *                             "iplocal", "ipremote")
 *
 * conn: an opaque data structure (from Lua's perspective) related to this 
 *       specific authentication attempt.
 * service_name: the name of the service that's being protected by SASL (e.g.
 *               xmpp, smtp, ...)
 * host FQDN: the fully-qualified domain name of the server that users 
 *            are connecting to. May be nil.
 * iplocal: Either nil or a string of the form "a.b.c.d;port" (for IPv4). 
 *          Used to tell the SASL library what the local side of the connection
 *          is using.
 * ipremote: Either nil or a string denoting the remote side of the connection.
 *
 * On error, this throws Lua error exceptions. (It is not the typical
 * case that this method might cause an error, except when attempting
 * to set up SASL initially during development.)
 */
static int cyrussasl_sasl_client_new(lua_State *l)
{
  const char *service_name, *fqdn, *iplocal, *ipremote;
  int numargs = lua_gettop(l);
  int err;
  sasl_conn_t *conn = NULL;
  struct _sasl_ctx **ctxp = NULL;

  if (numargs != 4) {
    lua_pushstring(l, 
		   "usage: "
		   "conn = "
		   "cyrussasl.client_new(service_name, fqdn, "
		   "iplocal, ipremote)");
    lua_error(l);
    return 0;
  }

  service_name = tostring(l, 1);
  fqdn = tostring(l, 2);
  iplocal = tostring(l, 3);
  ipremote = tostring(l, 4);

  ctxp = new_context(l);
  if (!ctxp) {
    lua_pushstring(l, "Unable to allocate a new context");
    lua_error(l);
    return 0;
  }

  _init_client_callbacks(*ctxp);

  err = sasl_client_new( service_name,       /* service name (passed in) */
			 fqdn,               /* serverFQDN               */
			 iplocal,            /* iplocalport              */
			 ipremote,           /* ipremoteport             */
			 (*ctxp)->callbacks, /* per-connection callbacks */
			 0,                  /* flags                    */
			 &conn );            /* returned connection ptr  */

  (*ctxp)->conn = conn;

  if ( err != SASL_OK ) {
    lua_pushstring(l, "sasl_client_new failed");
    lua_error(l);
    return 0;
  }

  /* Return 1 item on the stack (a userdata pointer to our state struct).
   * It was already pushed on the stack by new_context(). */

  return 1; /* return # of arguments returned on stack */
}

/* (err, data, mech) = cyrussasl.client_start(conn, mechlist)
 *
 * Arguments:
 *   conn: the return result from a previous call to client_new
 *   mechlist: 
 *
 * Return values:
 *   err: the (integer) SASL error code reflecting the state of the attempt 
 *        (e.g. SASL_OK, SASL_CONTINUE, SASL_BADMECH, ...)
 *   mech: the mechanism to use during this attempt (e.g. "PLAIN" or "GSSAPI")
 *   data: data that the server wants to send to the client in order 
 *         to continue the authN attempt. Returned as a Lua string object.
 */

static int cyrussasl_sasl_client_start(lua_State *l)
{
  int numargs = lua_gettop(l);
  int err;
  struct _sasl_ctx *ctx = NULL;
  const char *mechlist = NULL;
  const char *mechout = NULL;
  const char *data = NULL;
  size_t len;
  unsigned outlen;

  if (numargs != 2) {
    lua_pushstring(l, 
		   "usage: "
		   "(err, data, mech) = cyrussasl.client_start(conn, mechlist)");
    lua_error(l);
    return 0;
  }

  /* Pull arguments off of the stack... */

  ctx = get_context(l, 1);
  /* Allow the mechlist to be NULL. */
  if ( lua_type(l, 2) == LUA_TNIL ) {
    mechlist = NULL;
  } else {
    mechlist = tolstring(l, 2, &len);
  }

  err = sasl_client_start( ctx->conn, /* saved sasl connection              */
			   mechlist,  /* mech, which the client chose       */
			   NULL,      /* prompt_need                        */
			   &data,     /* data return                        */
			   &outlen,   /* data length return                 */
			   &mechout   /* chosen mechanism return            */
			   );

  /* Form the reply and push onto the stack */
  lua_pushinteger(l, err);          /* SASL_CONTINUE, SASL_OK, et al  */
  if (data) {
    lua_pushlstring(l, data, outlen); /* server's reply to the client   */
  } else {
    lua_pushnil(l);
  }
  lua_pushstring(l, mechout);       /* chosen mech                    */
  return 3;                         /* returning 3 items on Lua stack */
}

/* (err, data) = cyrussasl.client_step(conn, data)
 *
 * Arguments:
 *   conn: the return result from a previous call to client_new
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
static int cyrussasl_sasl_client_step(lua_State *l)
{
  int numargs = lua_gettop(l);
  int err;
  struct _sasl_ctx *ctx = NULL;
  const char *data = NULL;
  size_t len;
  unsigned outlen;

  if (numargs != 2) {
    lua_pushstring(l, 
		   "usage: (err, data) = cyrussasl.client_step(conn, data)");
    lua_error(l);
    return 0;
  }

  ctx = get_context(l, 1);
  data = tolstring(l, 2, &len);

  err = sasl_client_step( ctx->conn,
			  data,
			  len,
			  NULL, /* prompt_need */
			  &data,
			  &outlen );

  /* Form the reply and push onto the stack */
  lua_pushinteger(l, err);          /* SASL_CONTINUE, SASL_OK, et al  */
  if (data) {
    lua_pushlstring(l, data, outlen); /* server's reply to the client   */
  } else {
    lua_pushnil(l);
  }
  return 2;                         /* returning 2 items on Lua stack */
}

/* cyrussasl.setssf(conn, min_ssf, max_ssf)
 *
 * conn: the conn pointer from cyrussasl.server_new().
 * min_ssf, max_ssf: set the minimum and maximum security strength factor 
 *                   required for this AuthN.
 *
 * Throws Lua errors if it fails (as it should not typically fail).
 * Does not return any value.
 */
static int cyrussasl_setssf(lua_State *l)
{
  sasl_security_properties_t secprops;
  int err;
  int min_ssf, max_ssf;
  struct _sasl_ctx *ctx = NULL;

  int numargs = lua_gettop(l);
  if (numargs != 3) {
    lua_pushstring(l, "usage: cyrussasl.setssf(conn, min_ssf, max_ssf)");
    lua_error(l);
    return 0;
  }

  ctx     = get_context(l, 1);
  min_ssf = tointeger(l, 2);
  max_ssf = tointeger(l, 3);

  memset(&secprops, 0L, sizeof(secprops));
  secprops.min_ssf = min_ssf;
  secprops.max_ssf = max_ssf;

  err = sasl_setprop(ctx->conn, SASL_SEC_PROPS, &secprops);
  if ( err != SASL_OK ) {
    lua_pushstring(l, "setssf failed");
    lua_error(l);
    return 0;
  }

  return 0;
}


/* cyrussasl.setprop(conn, propnum, val)
 *
 * conn: the conn pointer from cyrussasl.server_new().
 * propnum: an integer corresponding to the property to set
 * val: a lua string object
 *
 * Throws Lua errors if it fails (as it should not typically fail).
 * Does not return any value.
 */
static int cyrussasl_sasl_setprop(lua_State *l)
{
  int err;
  int proptype;
  const void *proparg;
  struct _sasl_ctx *ctx = NULL;

  int numargs = lua_gettop(l);
  if (numargs != 3) {
    lua_pushstring(l, "usage: cyrussasl.setprop(conn, propnum, propval)");
    lua_error(l);
    return 0;
  }

  ctx      = get_context(l, 1);
  proptype = tointeger(l, 2);
  proparg  = tolstring(l, 3, NULL);

  err = sasl_setprop(ctx->conn, proptype, &proparg);
  if ( err != SASL_OK ) {
    const char *ret = get_context_message(ctx);
    if (ret)
      lua_pushstring(l, ret);
    else
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
  if (numargs != 1) {
    lua_pushstring(l, "usage: b64data = cyrussasl.encode64(data)");
    lua_error(l);
    return 0;
  }

  len = 0;
  data = tolstring(l, 1, &len);

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
    lua_pushstring(l, "usage: data = cyrussasl.decode64(b64data)");
    lua_error(l);
    return 0;
  }

  data = tostring(l, 1);
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

  if (outdata) {
    lua_pushlstring(l, outdata, outlen);
  } else {
    lua_pushnil(l);
  }
  free(outdata);
  return 1;
}

/* mechslist = cyrussasl.listmech(conn, authid, prefix, separator, suffix)
 *
 * Return all of the available mechanisms to the Cyrus SASL library.
 *
 * conn: the conn pointer from cyrussasl.server_new().
 * authid: the username trying to authenticate. May be nil.
 * prefix: prefix to prepend to the returned string. May be an empty string.
 * separator: the string to use to separate mechanisms. May be empty.
 * suffix: suffix to postpend to the returned string. May be empty.
 *
 * mechslist: a Lua string object containing the mechanisms (GSSAPI, et al)
 */
static int cyrussasl_sasl_listmech(lua_State *l)
{
  int err;
  struct _sasl_ctx *ctx = NULL;
  const char *ext_authid = NULL;
  const char *data = NULL;
  const char *prefix = NULL;
  const char *separator = NULL;
  const char *suffix = NULL;
  unsigned len;
  int count;

  int numargs = lua_gettop(l);
  if (numargs != 5) {
    lua_pushstring(l, 
		   "usage: "
		   "mechslist = cyrussasl.listmech"
		   "(conn, authid, prefix, separator, suffix)");
    lua_error(l);
    return 0;
  }

  ctx        = get_context(l, 1);
  ext_authid = tostring(l, 2);
  prefix     = tostring(l, 3);
  separator  = tostring(l, 4);
  suffix     = tostring(l, 5);

  err = sasl_listmech(ctx->conn,
		      ext_authid,
		      prefix,
		      separator,
		      suffix,
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

/* data = cyrussasl.getprop(conn, property)
 *
 * conn: the conn pointer from cyrussasl.server_new().
 * property: a SASL property (e.g. SASL_USERNAME, SASL_SSF)
 *
 * This is coded to handle the majority of properties available in 
 * Cyrus SASL (as of this writing, of course). Since each one is 
 * individually and explcitly coded, that means that additions to the 
 * SASL library will require some additions/changes here.
 *
 * The type of each return value depends on the specific property 
 * being queried.
 */

static int cyrussasl_getprop(lua_State *l)
{
  struct _sasl_ctx *ctx = NULL;
  unsigned *maxbufsize;
  const char *strdata;
  sasl_ssf_t *ssf;
  int propnum;
  int ret;

  int numargs = lua_gettop(l);
  if (numargs != 2) {
    lua_pushstring(l, "usage: user = cyrussasl.get_prop(conn, property)");
    lua_error(l);
    return 0;
  }

  ctx = get_context(l, 1);
  propnum = tointeger(l, 2);

  switch (propnum) {
    /* strings */
  case SASL_USERNAME:
  case SASL_DEFUSERREALM:
  case SASL_SERVICE:
  case SASL_SERVERFQDN:
  case SASL_AUTHSOURCE:
  case SASL_MECHNAME:
  case SASL_PLUGERR:
  case SASL_IPLOCALPORT:
  case SASL_IPREMOTEPORT:
    ret = sasl_getprop(ctx->conn, propnum, (const void **)&strdata); // return strdata
    lua_pushstring(l, strdata);
    lua_pushnumber(l, ret);
    return 2;
    

  case SASL_SSF: // sasl_ssf_t*
    ret = sasl_getprop(ctx->conn, propnum, (const void **)&ssf); // return *ssf
    lua_pushnumber(l, *ssf);
    lua_pushnumber(l, ret);
    return 2;

  case SASL_MAXOUTBUF: // unsigned
    ret = sasl_getprop(ctx->conn, propnum, (const void **)&maxbufsize); // return *maxbufsize
    lua_pushnumber(l, *maxbufsize);
    lua_pushnumber(l, ret);
    return 2;

    /* I'm not sure how SASL_GETOPTCTX would be useful to a Lua
     * caller, so I'm not including it for the moment.  If you're
     * reading this and have a good use case, drop me a line and we'll
     * figure out how to integrate it. */

  default:
    lua_pushstring(l, "Unsupported property passed to cyrussasl.getprop()");
    lua_error(l);
    return 0;
  }

  /* NOTREACHED */
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
  struct _sasl_ctx *ctx = NULL;
  const char *ret;
  unsigned ulen;

  int numargs = lua_gettop(l);
  if (numargs != 1) {
    lua_pushstring(l, "usage: user = cyrussasl.get_username(conn)");
    lua_error(l);
    return 0;
  }

  ctx = get_context(l, 1);

  ret = get_context_user(ctx, &ulen);
  if (ret && ulen)
    lua_pushlstring(l, ret, ulen);
  else
    lua_pushstring(l, "");

  return 1;
}

/* cyrussasl.set_username(conn, username)
 *
 * For client-side connections that require a username, this will 
 * set it (before calling client_start, presumably).
 */
static int cyrussasl_set_username(lua_State *l)
{
  struct _sasl_ctx *ctx = NULL;
  const char *uname = NULL;
  size_t ulen = 0;

  int numargs = lua_gettop(l);
  if (numargs != 2) {
    lua_pushstring(l, "usage: cyrussasl.set_username(conn, username)");
    lua_error(l);
    return 0;
  }

  ctx = get_context(l, 1);
  uname = tolstring(l, 2, &ulen);

  set_context_user(ctx, uname, ulen);

  return 0;
}

/* user = cyrussasl.get_authname(conn)
 *
 * conn: the conn pointer from cyrussasl.server_new().
 * user: the authname decoded from user data as part of the negotiation.
 */
static int cyrussasl_get_authname(lua_State *l)
{
  struct _sasl_ctx *ctx = NULL;
  const char *ret;
  int numargs = lua_gettop(l);

  if (numargs != 1) {
    lua_pushstring(l, "usage: user = cyrussasl.get_authname(conn)");
    lua_error(l);
    return 0;
  }

  ctx = get_context(l, 1);

  ret = get_context_authname(ctx);
  if (ret)
    lua_pushstring(l, ret);
  else
    lua_pushstring(l, "");

  return 1;
}

/* cyrussasl.set_authname(conn, username)
 *
 * For client-side connections that require an authname, this will 
 * set it (before calling client_start, presumably).
 */
static int cyrussasl_set_authname(lua_State *l)
{
  struct _sasl_ctx *ctx = NULL;
  const char *uname = NULL;
  size_t ulen = 0;

  int numargs = lua_gettop(l);
  if (numargs != 2) {
    lua_pushstring(l, "usage: cyrussasl.set_authname(conn, authname)");
    lua_error(l);
    return 0;
  }

  ctx = get_context(l, 1);
  uname = tolstring(l, 2, &ulen);

  set_context_authname(ctx, uname);

  return 0;
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
  struct _sasl_ctx *ctx = NULL;
  const char *ret;
  int numargs = lua_gettop(l);
  if (numargs != 1) {
    lua_pushstring(l, "usage: cyrussasl.get_message(conn)");
    lua_error(l);
    return 0;
  }

  ctx = get_context(l, 1);

  ret = get_context_message(ctx);
  if (ret)
    lua_pushstring(l, ret);
  else
    lua_pushstring(l, "");

  return 1;
}

/* old_cb = cyrussasl.set_canon_cb(conn, cb)
 *
 * conn: the conn pointer from cyrussasl.server_new()
 * cb: a function that is passed the username, realm (may be nil), and
 *     either "authcid", "authzid", or "both" to indicate whether
 *     the username is the authentication identity, the authorization
 *     identity, or both (both seems to happen under some circumstances).
 *     The function should return a normalized username.
 * old_cb: the previous callback (or nil)
 *
 * Used to canonicalize usernames.
 *
 */
static int cyrussasl_set_canon_cb(lua_State *l)
{
  struct _sasl_ctx *ctx = NULL;
  int numargs = lua_gettop(l);
  int old_ref;
  int type;

  if (numargs != 2) {
    lua_pushstring(l, "usage: cyrussasl.set_canon_cb(conn, cb)");
    lua_error(l);
    return 0;
  }

  ctx = get_context(l, 1);

  type = lua_type(l, 2);
  if (type != LUA_TFUNCTION && type != LUA_TNIL) {
    char err[256];
    snprintf(err, sizeof(err),
	      "expected function or nil, got %s",
	       lua_typename(l, type));
    lua_pushstring(l, err);
    lua_error(l);
    return 0;
  }

  old_ref = ctx->canon_cb_ref;
  /* Store the new function */
  ctx->canon_cb_ref = luaL_ref(l, LUA_REGISTRYINDEX);

  /* Push the old function onto the stack and free its ref */
  lua_rawgeti(l, LUA_REGISTRYINDEX, old_ref);
  luaL_unref(l, LUA_REGISTRYINDEX, old_ref);

  return 1;
}

/* old_cb = cyrussasl.set_log_cb(cb, minimum priority level)
 *
 * cb: a function that is passed the log message and priority.
 *     priority is one of "error", "fail" (auth failures), "warn",
 *     "note", "debug", "trace", and "pass" (includes passwords).
 * minimum priority level: the minimum severity level messages to call
 *     in the cb.  The default is "warn".
 * old_cb: the previous callback (or nil)
 *
 * Used for debug logging.
 */
static int cyrussasl_set_log_cb(lua_State *l)
{
  int old_ref;
  int numargs = lua_gettop(l);
  int type;

  type = lua_type(l, 1);
  if (type != LUA_TFUNCTION && type != LUA_TNIL) {
    char err[256];
    snprintf(err, sizeof(err),
	      "expected function or nil, got %s",
	       lua_typename(l, type));
    lua_pushstring(l, err);
    lua_error(l);
    return 0;
  }

  /* Store the minimum desired log level */
  minimum_log_prio = luaL_checkoption(l, 2, "warn", level_strings);
  if (numargs > 1)
    lua_pop(l, numargs - 1);

  old_ref = log_cb_ref;
  /* Store the new function */
  log_cb_ref = luaL_ref(l, LUA_REGISTRYINDEX);

  /* Push the old function onto the stack and free its ref */
  lua_rawgeti(l, LUA_REGISTRYINDEX, old_ref);
  luaL_unref(l, LUA_REGISTRYINDEX, old_ref);

  return 1;
}

/* (err, data) = cyrussasl.encode(conn, msg)
 *
 * conn: the conn pointer from cyrussasl.server_new().
 * msg: the data to encode
 *
 * It's not clear whether or not this is useful as-is; this is largely untested.
 */

static int cyrussasl_encode(lua_State *l)
{
  struct _sasl_ctx *ctx = NULL;
  const char *msg;
  size_t msg_len = 0;
  unsigned out_len = 0;
  const char *out_data = NULL;
  int err;

  int numargs = lua_gettop(l);
  if (numargs != 2) {
    lua_pushstring(l, "usage: cyrussasl.encode(conn, msg)");
    lua_error(l);
    return 0;
  }

  ctx = get_context(l, 1);
  msg = tolstring(l, 2, &msg_len);

  err = sasl_encode(ctx->conn, msg, msg_len, &out_data, &out_len);
  lua_pushinteger(l, err);
  if (err == SASL_OK) {
    lua_pushlstring(l, out_data, out_len);
  } else {
    lua_pushliteral(l, "");
  }

  return 2;
}

/* (err, data) = cyrussasl.decode(conn, msg)
 *
 * conn: the conn pointer from cyrussasl.server_new().
 * msg: the data to decode
 *
 * It's not clear whether or not this is useful as-is; this is largely untested.
 */

static int cyrussasl_decode(lua_State *l)
{
  struct _sasl_ctx *ctx = NULL;
  const char *msg;
  size_t msg_len = 0;
  unsigned out_len = 0;
  const char *out_data = NULL;
  int err;

  int numargs = lua_gettop(l);
  if (numargs != 2) {
    lua_pushstring(l, "usage: cyrussasl.decode(conn, msg)");
    lua_error(l);
    return 0;
  }

  ctx = get_context(l, 1);
  msg = tolstring(l, 2, &msg_len);

  err = sasl_decode(ctx->conn, msg, msg_len, &out_data, &out_len);
  lua_pushinteger(l, err);
  if (err == SASL_OK) {
    lua_pushlstring(l, out_data, out_len);
  } else {
    lua_pushliteral(l, "");
  }

  return 2;
}


/* metatable, hook for calling gc_context on context structs */
static const luaL_Reg meta[] = {
  { "__gc", gc_context },
  { NULL,   NULL        }
};

/* function table for this module */
static const struct luaL_Reg methods[] = {
  { "setssf",       cyrussasl_setssf            },
  { "setprop",      cyrussasl_sasl_setprop      },
  { "listmech",     cyrussasl_sasl_listmech     },
  { "encode64",     cyrussasl_sasl_encode64     },
  { "decode64",     cyrussasl_sasl_decode64     },
  { "get_version",  cyrussasl_get_version       },
  { "server_init",  cyrussasl_sasl_server_init  },
  { "server_new",   cyrussasl_sasl_server_new   },
  { "server_start", cyrussasl_sasl_server_start },
  { "server_step",  cyrussasl_sasl_server_step  },
  { "client_init",  cyrussasl_sasl_client_init  },
  { "client_new",   cyrussasl_sasl_client_new   },
  { "client_start", cyrussasl_sasl_client_start },
  { "client_step",  cyrussasl_sasl_client_step  },
  { "getprop",      cyrussasl_getprop           },
  { "get_username", cyrussasl_get_username      },
  { "set_username", cyrussasl_set_username      },
  { "get_authname", cyrussasl_get_authname      },
  { "get_message",  cyrussasl_get_message       },
  { "set_canon_cb", cyrussasl_set_canon_cb      },
  { "set_log_cb",   cyrussasl_set_log_cb        },
  { "encode",       cyrussasl_encode            },
  { "decode",       cyrussasl_decode            },
  { NULL,           NULL                        }
};

/* SASL constants that we'll export */
struct _saslconst {
  const char *name;
  int val;
};

static const struct _saslconst constants[] = {

  /* Properties */
  { "SASL_USERNAME",     SASL_USERNAME     },
  { "SASL_SSF",          SASL_SSF          },
  { "SASL_MAXOUTBUF",    SASL_MAXOUTBUF    },
  { "SASL_DEFUSERREALM", SASL_DEFUSERREALM },
  { "SASL_GETOPTCTX",    SASL_GETOPTCTX    },
  { "SASL_IPLOCALPORT",  SASL_IPLOCALPORT  },
  { "SASL_IPREMOTEPORT", SASL_IPREMOTEPORT },
  { "SASL_SERVICE",      SASL_SERVICE      },
  { "SASL_SERVERFQDN",   SASL_SERVERFQDN   },
  { "SASL_AUTHSOURCE",   SASL_AUTHSOURCE   },
  { "SASL_MECHNAME" ,    SASL_MECHNAME     },
  { "SASL_PLUGERR",      SASL_PLUGERR      },

  /* Return Codes */
  { "SASL_OK",           SASL_OK           },
  { "SASL_CONTINUE",     SASL_CONTINUE     },

  { NULL,                0                 }
};

/* Module initializer, called from Lua when the module is loaded. */
int luaopen_cyrussasl(lua_State *L)
{
  const struct _saslconst *p = constants;

  /* Create metatable, which is used to tie C data structures to our garbage 
   * collection function. */
  luaL_newmetatable(L, MODULENAME);
#if LUA_VERSION_NUM == 501
  luaL_openlib(L, 0, meta, 0);
#else
  lua_newtable(L);
  luaL_setfuncs(L, meta, 0);
#endif
  lua_pushliteral(L, "__index");
  lua_pushvalue(L, -3);               /* dup methods table*/
  lua_rawset(L, -3);                  /* metatable.__index = methods */
  lua_pushliteral(L, "__metatable");
  lua_pushvalue(L, -3);               /* dup methods table*/
  lua_rawset(L, -3);                  /* hide metatable:
                                         metatable.__metatable = methods */
  lua_pop(L, 1);                      /* drop metatable */

  /* Construct a new namespace table for Luaand return it. */
#if LUA_VERSION_NUM == 501
  /* Lua 5.1: pollute the root namespace */
  luaL_openlib(L, MODULENAME, methods, 0);
#else
  /* Lua 5.2 and above: be a nice namespace citizen */
  lua_newtable(L);
  luaL_setfuncs(L, methods, 0);
#endif

  /* Inject all of the SASL constants in to the table */
  while (p->name) {
    lua_pushstring(L, p->name);
    lua_pushnumber(L, p->val);
    lua_rawset(L, -3);
    p++;
  }

  return 1;                           /* return methods table on the stack */

}

