#include <lua.h>
#include <stdio.h>

#include "luaabstract.h"

const char *tolstring(lua_State *l, int index, size_t *len)
{
  if (lua_type(l, index) != LUA_TSTRING) {
    char err[256];
    snprintf(err, sizeof(err),
	     "expected string, got %s",
	     lua_typename(l, index));
    lua_pushstring(l, err);
    lua_error(l);
    return NULL;
  }

  return lua_tolstring(l, index, len);
}

const char *tostring(lua_State *l, int index)
{
  return tolstring(l, index, NULL);
}

