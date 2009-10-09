#include <lua.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PLUGINDIR "/usr/lib/sasl2"

// FIXME: this obviously is stupid; it's not tied to a session. But it's here
// to prove the point that this works...
static char cur_username[256] = { 0 };

static int sasl_my_log(void *context __attribute__((unused)),
		       int priority,
		       const char *message)
{
  const char *label;
  if (! message)
    return SASL_BADPARAM;
  switch (priority) {
  case SASL_LOG_ERR:
    label = "Error";
    break;
  case SASL_LOG_NOTE:
    label = "Info";
    break;
  default:
    label = "Other";
    break;
  }

  fprintf(stderr, "error: SASL %s: %s\n", 
	  label, message);
  return SASL_OK;
}

static int
getpath( void *context,
	 char ** path)
{
  if (! path)
    return SASL_BADPARAM;

  *path = PLUGINDIR;
  return SASL_OK;
}

int sasl_canon_user(sasl_conn_t *conn,
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

  strncpy(cur_username, user, sizeof(cur_username));

  strcpy(out_user, user);
  *out_ulen = strlen(user);

  return SASL_OK;
}

static sasl_callback_t callbacks[] = {
  {
    SASL_CB_LOG, &sasl_my_log, NULL
  }, {
    SASL_CB_GETPATH, &getpath, NULL
  }, {
    SASL_CB_CANON_USER, &sasl_canon_user, NULL
  }, {
    SASL_CB_LIST_END, NULL, NULL
  }
};

void expected(lua_State *l, const char *exp, int index) {
  char err[256];
  snprintf(err, sizeof(err), "expected %s, got %s",
	   exp, lua_typename(l, index));
  lua_pushstring(l, err);
  lua_error(l);
}

lua_Integer tointeger(lua_State *l, int index) {
  if (lua_type(l, index) != LUA_TNUMBER)
    expected(l, "integer", index);
  return lua_tointeger(l, index);
}

const char *tolstring(lua_State *l, int index, size_t *len) {
  if (lua_type(l, index) != LUA_TSTRING)
    expected(l, "string", index);
  return lua_tolstring(l, index, len);
}

const char *tostring(lua_State *l, int index) {
  return tolstring(l, index, NULL);
}

void *tolightuserdata(lua_State *l, int index) {
  if (lua_type(l, index) != LUA_TLIGHTUSERDATA)
    expected(l, "lightuserdata", index);
  return lua_touserdata(l, index);
}

void declfunc(lua_State *l, const char *name, lua_CFunction func) {
  lua_pushcfunction(l, func);
  lua_setfield(l, -2, name);
}

// jorj:server_init()
int _cyrussasl_sasl_server_init(lua_State *l)
{
  int numargs = lua_gettop(l);
  int err;

  if (numargs != 0) {
    lua_pushstring(l, "usage: jorj:server_init()");
    lua_error(l);
    return 0;
  }

  err = sasl_server_init(NULL, // callbacks
			 "prosody"); // FIXME: replace app name with an argument
  if (err != SASL_OK) {
    lua_pushstring(l, "sasl_server_init failed");
    lua_error(l);
    return 0;
  }

  return 0;
}


// conn = jorj::server_new()
int _cyrussasl_sasl_server_new(lua_State *l)
{
  int numargs = lua_gettop(l);
  int err;
  sasl_conn_t *conn = NULL;

  if (numargs != 0) {
    lua_pushstring(l, "usage: conn = jorj:server_new()");
    lua_error(l);
    return 0;
  }

  // FIXME: callbacks really belongs in init, not in server_new... but if it
  // works here, that's okay for now

  err = sasl_server_new( "xmpp", // service
			 NULL,   // localdomain
			 NULL,   // userdomain
			 NULL,   // iplocal
			 NULL,   // ipremote
			 callbacks, // callbacks
			 0,      // flags
			 &conn ); // connection ptr
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

// (err, data, datalen) = jorj::server_start(conn, mech, data, datalen)
int _cyrussasl_sasl_server_start(lua_State *l)
{
  int numargs = lua_gettop(l);
  int err;
  sasl_conn_t *conn = NULL;
  const char *mech = NULL;
  const char *data = NULL;
  unsigned len;
  int i;

  if (numargs != 4) {
    lua_pushstring(l, "usage: conn = jorj:server_start(conn,mech,data,len)");
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

  err = sasl_server_start( conn,
			   mech,
			   data,
			   len,
			   &data,
			   &len );

  /*
    -- this is unnecessary; the error will be pushed up in the return code, so 
    -- the caller will get the error condition without us having to throw one.
  if ( err != SASL_OK && err != SASL_CONTINUE) {
    lua_pushstring(l, "sasl_server_start failed");
    lua_error(l);
    return 0;
  }
  */

  // push the result code, data and len
  lua_pushinteger(l, err); // might be SASL_CONTINUE or SASL_OK
  lua_pushlstring(l, data, len);
  lua_pushinteger(l, len);
  return 3;
}

// (err, data, datalen) = jorj::server_step(conn, data, datalen)
int _cyrussasl_sasl_server_step(lua_State *l)
{
  int numargs = lua_gettop(l);
  int err;
  sasl_conn_t *conn = NULL;
  const char *data = NULL;
  unsigned len;

  if (numargs != 3) {
    lua_pushstring(l, "usage: conn = jorj:server_step(conn,data,len)");
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
			  &len );
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
  lua_pushlstring(l, data, len);
  lua_pushinteger(l, len);

  return 3;
}

// jorj::setprop(conn)
int _cyrussasl_sasl_setprop(lua_State *l)
{
  sasl_security_properties_t secprops;
  int err;
  sasl_conn_t *conn = NULL;

  int numargs = lua_gettop(l);
  if (numargs != 1) {
    lua_pushstring(l, "usage: jorj:setprop(conn)");
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

// b64data=jorj::encode64(data, len)
int _cyrussasl_sasl_encode64(lua_State *l)
{
  unsigned len_out;
  int alloclen;
  char *buf = NULL;
  const char *data = NULL;
  unsigned len;
  int err;

  int numargs = lua_gettop(l);
  if (numargs != 2) {
    lua_pushstring(l, "usage: jorj:encode64(data, len)");
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

// data, len = jorj::decode64(b64data)
int _cyrussasl_sasl_decode64(lua_State *l)
{
  const char *data = NULL;
  unsigned len;
  int err;
  void *ret;

  int numargs = lua_gettop(l);
  if (numargs != 1) {
    lua_pushstring(l, "usage: jorj:decode64(b64data)");
    lua_error(l);
    return 0;
  }

  data = tostring(l, 1);
  lua_pop(l, 1);
  len = strlen(data);

  // perform a decode-in-place. According to docs, this is kosher.
  err = sasl_decode64(data, len, data, len, &len);
  if ( err != SASL_OK ) {
    lua_pushstring(l, "sasl_decode64 failed");
    lua_error(l);
    return 0;
  }

  lua_pushlstring(l, data, len);
  lua_pushinteger(l, len);
  return 2;
}

// mechsdata, len = jorj::listmech(conn)
int _cyrussasl_sasl_listmech(lua_State *l)
{
  int err;
  sasl_conn_t *conn = NULL;
  const char *ext_authid = NULL;
  const char *data = NULL;
  unsigned len;
  int count;

  int numargs = lua_gettop(l);
  if (numargs != 1) {
    lua_pushstring(l, "usage: jorj:listmech(conn)");
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

// FIXME: need to pass 'conn' into this in order to get the right one
int _cyrussasl_get_username(lua_State *l)
{
  lua_pushstring(l, cur_username);

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

  return 1;
}

