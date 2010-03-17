#include <lua.h>
#include <stdio.h>

#include "luaabstract.h"

const char *tolstring(lua_State *l, int index, size_t *len)
{
  int type = lua_type(l, index);
  if (type != LUA_TSTRING) {
    char err[256];
    snprintf(err, sizeof(err),
	     "expected string, got %s",
	     lua_typename(l, type));
    lua_pushstring(l, err);
    lua_error(l);
    return NULL;
  }

  return lua_tolstring(l, index, len);
}

const char *tostring(lua_State *l, int index)
{
  if (lua_type(l, index) == LUA_TNIL)
    return NULL;

  return tolstring(l, index, NULL);
}

int tointeger(lua_State *l, int index)
{
  int type = lua_type(l, index);
  if (type != LUA_TNUMBER) {
    char err[256];
    snprintf(err, sizeof(err),
	     "expected integer, got %s",
	     lua_typename(l, type));
    lua_pushstring(l, err);
    lua_error(l);
    return 0;
  }
  return lua_tointeger(l, index);
}
