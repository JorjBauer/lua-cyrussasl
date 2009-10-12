#ifndef __LUAABSTRACT_H
#define __LUAABSTRACT_H

#include <lua.h>

const char *tolstring(lua_State *l, int index, size_t *len);
const char *tostring(lua_State *l, int index);
int         tointeger(lua_State *l, int index);

#endif
