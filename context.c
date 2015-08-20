#include <lua.h>
#include <lauxlib.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "context.h"
#include "luaabstract.h"

/* strdup() is a POSIX function that is not part of the ANSI standard. This
 * simple wrapper provides the same functionality for platforms that don't
 * have POSIX defined. */
char *local_strdup(const char *s1)
{
#ifdef POSIX
  return strdup(s1);
#else
  char *ret = malloc(strlen(s1)+1);
  if (!ret)
    return NULL;

  strcpy(ret, s1);

  return ret;
#endif
}

/* new_context returns a lua userdata variable which has two important 
 * properties:
 *
 * 1. It is a pointer to the pointer to a context struct, which carries the 
 *    C-internal state for this SASL negotiation; and 
 * 2. It has a metatable associated with it that will call our destructor when 
 *    Lua decides to garbage-collect the userdata variable.
 */
struct _sasl_ctx **new_context(lua_State *L)
{
  struct _sasl_ctx *data       = NULL;
  struct _sasl_ctx **luserdata = NULL;

  data = malloc(sizeof(struct _sasl_ctx));
  if (!data)
    return NULL;

  data->magic        = CYRUSSASL_MAGIC;
  data->L            = L;
  data->conn         = NULL;
  data->last_message = NULL;
  data->user         = NULL;
  data->authname     = NULL;
  data->canon_cb_ref = LUA_REFNIL;

  /* Now that we have the context struct, we need to construct a Lua variable
   * to carry the data. And that variable needs to callback to our __gc method
   * for it in order to deallocate the memory we've just allocated. 
   * 
   * Note that we're allocing a new userdata object of the size of the 
   * _pointer_ to our new struct.
   */

  luserdata = (struct _sasl_ctx **) lua_newuserdata(L, sizeof(data));
  if (!luserdata) {
    lua_pushstring(L, "Unable to alloc newuserdata");
    lua_error(L);
    free(data);
    return NULL;
  }
  *luserdata = data;                /* Store the pointer in the userdata */
  luaL_getmetatable(L, MODULENAME); /* Retrieve the metatable w/ __gc hook */
  lua_setmetatable(L, -2);          /* Set luserdata's metatable to that one */

  return luserdata;
}

struct _sasl_ctx *get_context(lua_State *l, int idx)
{
  struct _sasl_ctx **ctxp = (struct _sasl_ctx **)lua_touserdata(l, idx);
  if (ctxp == NULL) {
    lua_pushstring(l, "userdata is NULL");
    lua_error(l);
    return NULL;
  }

  return *ctxp;
}

void free_context(struct _sasl_ctx *ctx)
{
  if (!ctx || ctx->magic != CYRUSSASL_MAGIC) 
    return;

  if (ctx->conn)
    sasl_dispose(&ctx->conn);
  if (ctx->last_message)
    free(ctx->last_message);
  if (ctx->user)
    free(ctx->user);
  if (ctx->authname)
    free(ctx->authname);
  free(ctx);
}

int gc_context(lua_State *L)
{
  struct _sasl_ctx **luadata = (struct _sasl_ctx **)lua_touserdata(L, 1);

  if (luadata == NULL) {
    lua_pushstring(L, "userdata is NULL");
    lua_error(L);
    return 0;
  }

  if ((*luadata)->canon_cb_ref != LUA_REFNIL)
    luaL_unref(L, LUA_REGISTRYINDEX, (*luadata)->canon_cb_ref);
  free_context(*luadata);
  return 0;
}

void set_context_conn(struct _sasl_ctx *ctx, sasl_conn_t *conn)
{
  if (!ctx || ctx->magic != CYRUSSASL_MAGIC)
    return;

  ctx->conn = conn;
}

void set_context_message(struct _sasl_ctx *ctx, const char *msg)
{
  if (!ctx || ctx->magic != CYRUSSASL_MAGIC)
    return;
  if (!msg)
    return;

  if (ctx->last_message)
    free(ctx->last_message);
  ctx->last_message = local_strdup(msg);
}

void set_context_user(struct _sasl_ctx *ctx, const char *usr, unsigned ulen)
{
  if (!ctx || ctx->magic != CYRUSSASL_MAGIC)
    return;
  if (!usr)
    return;

  if (ctx->user)
    free(ctx->user);

  ctx->ulen = ulen;

  if (usr == NULL || ulen == 0) {
    ctx->user = NULL;
    return;
  }

  ctx->user = malloc(ulen+1);
  if (!ctx->user)
    return;
  memcpy(ctx->user, usr, ulen);
  ctx->user[ulen] = '\0';
}

void set_context_authname(struct _sasl_ctx *ctx, const char *usr)
{
  if (!ctx || ctx->magic != CYRUSSASL_MAGIC)
    return;
  if (!usr)
    return;

  if (ctx->authname)
    free(ctx->authname);
  ctx->authname = local_strdup(usr);
}

const char *get_context_message(struct _sasl_ctx *ctx)
{
  if (!ctx || ctx->magic != CYRUSSASL_MAGIC)
    return NULL;

  return ctx->last_message;
}

const char *get_context_user(struct _sasl_ctx *ctx, unsigned *ulen_out)
{
  if (!ctx || ctx->magic != CYRUSSASL_MAGIC)
    return NULL;

  if (ulen_out)
    *ulen_out = ctx->ulen;
  
  return ctx->user;
}

const char *get_context_authname(struct _sasl_ctx *ctx)
{
  if (!ctx || ctx->magic != CYRUSSASL_MAGIC)
    return NULL;
  
  return ctx->authname;
}
