/*
 *	UnderHook
 *	api/uhook.c
 *
 *	Written By:
 *		Michael Laforest	< para >
 *		Email: < paralizer -AT- users -DOT- sourceforge -DOT- net >
 *
 *	Copyright 2005
 *
 *	This file is part of UnderHook.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *	$Header$
 *
 */
#include <stdio.h>

#ifdef _WIN32
	#define WIN32_LEAN_AND_MEAN
	#include <windows.h>
#else
	#include <dlfcn.h>
#endif

#include "uhook.h"

struct uhook_t* _uhook = NULL;
struct uhook_api_t* _uhook_api = NULL;
void* uhook_mod = NULL;


/*
 *	Load the UnderHook module and setup all
 *	functions and structures needed.
 */
int uhook_startup(char* uhook_file) {
	void* entry = NULL;
	int (*entry_func)(struct uhook_api_t**) = NULL;

	if (uhook_mod || _uhook)
		/* Already loaded */
		return 0;

	/*
	 *	Load the module.
	 */
	uhook_mod = dlopen(uhook_file, RTLD_NOW);

	if (!uhook_mod)
		/* Can't load module */
		return 0;
	
	/*
	 *	Get the module entry point and execute it.
	 */
	entry = dlsym(uhook_mod, "uhook_main");

	if (!entry)
		/* Can't find entry point */
		return 0;

	entry_func = entry;
	entry_func(&_uhook_api);


	/*
	 *	If incorrect API version, return 0.
	 */
	if (_uhook_api->api_version != UHOOK_API_VERSION) {
		uhook_shutdown();
		return 0;
	}


	/*
	 *	Set all the function pointers so the macros work properly.
	 *	It is also a cleaner API rather than using _uhook_api-> for everything.
	 */
	uhook_set_object					= _uhook_api->uhook_set_object;
	uhook_init							= _uhook_api->uhook_init;
	uhook_free							= _uhook_api->uhook_free;
	uhook_set							= _uhook_api->uhook_set;
	uhook_set_func_attr					= _uhook_api->uhook_set_func_attr;
	_add_hook							= _uhook_api->_add_hook;
	_uhook_remove_all_hooks_for_func	= _uhook_api->_uhook_remove_all_hooks_for_func;
	uhook_get_hook_node					= _uhook_api->uhook_get_hook_node;
	uhook_resize_stack					= _uhook_api->uhook_resize_stack;
	uhook_make_void_ptr					= _uhook_api->uhook_make_void_ptr;
	mem_set_permissions					= _uhook_api->mem_set_permissions;
	_uhook_remove_hook					= _uhook_api->_uhook_remove_hook;

	/*
	 *	Initialize UnderHook.
	 */
	_uhook = uhook_init();
	uhook_set_object(_uhook);

	return 1;
}


/*
 *	Unload UnderHook.
 */
void uhook_shutdown() {
	/*
	 *	Free UnderHook.
	 */
	uhook_free(_uhook);
	_uhook = NULL;

	/*
	 *	Unload the module.
	 */
	dlclose(uhook_mod);
	uhook_mod = NULL;

	_uhook_api = NULL;

	/*
	 *	Set all the API function pointers to NULL.
	 */
	uhook_set_object					= NULL;
	uhook_init							= NULL;
	uhook_free							= NULL;
	uhook_set							= NULL;
	uhook_set_func_attr					= NULL;
	_add_hook							= NULL;
	_uhook_remove_all_hooks_for_func	= NULL;
	uhook_get_hook_node					= NULL;
	uhook_resize_stack					= NULL;
	uhook_make_void_ptr					= NULL;
	mem_set_permissions					= NULL;
	_uhook_remove_hook					= NULL;
}
