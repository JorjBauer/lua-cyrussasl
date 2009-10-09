#include <lua.h>
#include <stdio.h>

#include "luaabstract.h"

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
