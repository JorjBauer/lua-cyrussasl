#ifndef __LUAABSTRACT_H
#define __LUAABSTRACT_H

#include <lua.h>

void expected(lua_State *l, const char *exp, int index);
lua_Integer tointeger(lua_State *l, int index);
const char *tolstring(lua_State *l, int index, size_t *len);
const char *tostring(lua_State *l, int index);
void *tolightuserdata(lua_State *l, int index);
void declfunc(lua_State *l, const char *name, lua_CFunction func);

#endif
