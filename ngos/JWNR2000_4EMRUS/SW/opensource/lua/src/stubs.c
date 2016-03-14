/*
********************************************************************************
*
* FILE NAME:    stubs.c
*
* DESCRIPTION:  Function stubs for removal of parsing functionailty in LUA.
*
* From Lua technical note 2 (http://www.lua.org/notes/ltn002.html)
*
********************************************************************************
*/

#include "llex.h"
#include "lparser.h"
#include "ldebug.h"

void luaX_init(lua_State *L)
{
    UNUSED(L);
}

Proto *luaY_parser(lua_State *L, ZIO *z, Mbuffer *buff)
{
    UNUSED(z);
    UNUSED(buff);
    luaG_runerror(L, "parser not loaded");
    return NULL;
}
