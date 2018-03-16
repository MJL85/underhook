/*
 *	UnderHook
 *	api/uhook.h
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
#ifndef _UHOOK_H
#define _UHOOK_H


int uhook_startup(char* uhook_file);
void uhook_shutdown();


/*
 *	Operating system dependent macros.
 */
#ifdef _WIN32
	#define dlopen(file, x)         (void*)LoadLibrary(file)
	#define dlsym(dll, func)        (void*)GetProcAddress((HMODULE)(dll), (func))
	#define dlclose(dll)            FreeLibrary((HMODULE)(dll))

	char* _dlerror();
	#define dlerror()				_dlerror()
#else
#endif


typedef unsigned char byte;


/*
 *	UnderHook version.
 *
 *	UHOOK_VERSION specifies the implementation version of UnderHook.
 *	UHOOK_API_VERSION specifies the interface version.
 *
 *	Often times the API verson will remain constant between
 *	UnderHook versions allowing 3rd party applications to use
 *	newer versions without the need to change their code.
 *
 *	It is advised you do not use UnderHook if you load it and find
 *	the API version is not what you expected it to be.  This may
 *	indicate some of the code being used by your program is no
 *	longer compatible with that version of UnderHook and may
 *	cause errors.
 */
#define UHOOK_VERSION		0.2
#define UHOOK_API_VERSION	0.3


/******************************************
 *	START: Public interface.
 ******************************************/

/*
 *	Add a function hook.
 *
 *	tfunc		- target function to be modified
 *	nfunc		- function to be called upon invocation
 *	order		- pre or post calling
 *	param_size	- size of parameter list in bytes (can be larger than actual size)
 *
 *	Use ADD_HOOK for a normal function hook
 *	where tfunc has a frame pointer and you
 *	want to use uhook's internal handler.
 *
 *	Use ADD_MANUAL_HOOK for a function hook
 *	where rfunc has a frame pointer and you
 *	want to use a custom handler.
 *
 *	Use ADD_HOOK_NOFRAME is the function tfunc
 *	has no frame pointer.
 *
 *	Use ADD_MANUAL_HOOK_NOFRAME for a function
 *	that has no frame pointer and where you want
 *	to use a custom handler.
 */
#define ADD_HOOK(tfunc, nfunc, order)		_add_hook(_uhook, (void*)tfunc, (void*)nfunc, NULL, order, 0, 0)
#define ADD_MANUAL_HOOK(tfunc, nfunc)		_add_hook(_uhook, (void*)tfunc, (void*)NULL, (void*)nfunc, 0, UHOOK_FUNCATTR_MANUAL_HOOK, 0)

#define ADD_HOOK_NOFRAME(tfunc, nfunc, order, param_size)	_add_hook(_uhook, (void*)tfunc, (void*)nfunc, NULL, order, UHOOK_FUNCATTR_NOFRAMEPTR, param_size)


/*
 *	Remove a function hook.
 */
#define REMOVE_HOOK(tfunc, nfunc)			_uhook_remove_hook(_uhook, tfunc, nfunc)
#define REMOVE_ALL_HOOKS(tfunc)				_uhook_remove_all_hooks_for_func(_uhook, tfunc)


/******************************************
 *	END: Public interface.
 ******************************************/


/*
 *	Size of the hash table for hooked
 *	function structures.
 *	Must be a power of 2.
 */
#define UHOOK_HASH_SIZE		32


/*
 *	This must be the first parameter for a bound function.
 */
#define UHOOK_THISHOOK_PTR		struct uhook_func_t* const thishook


/*
 *	User definable flags for uhook_t->flags
 */
#define UHOOK_STACK_AUTODETECT	0x01

#define UHOOK_DEFAULT_FLAGS		UHOOK_STACK_AUTODETECT

#define UHOOK_IS_SET(n)			((_uhook->flags & n) == n)


/*
 *	Macros to set function attribtues.
 */
#define UHOOK_SET_FUNC_ATTR(hook, n)	hook->flags |= n
#define UHOOK_FUNC_HAS_ATTR(hook, n)	((hook->flags & n) == n)


/*
 *	User definable function attributes.
 */
#define UHOOK_FUNCATTR_STACK_SIZE	0x01
#define UHOOK_FUNCATTR_MANUAL_HOOK	0x02
#define UHOOK_FUNCATTR_NOFRAMEPTR	0x04


/*
 *	Return attributes for internal use (appending from above list)
 */
#define UHOOK_FUNCRET_NORMAL		0x08
#define UHOOK_FUNCRET_SUPERSEDE		0x10
#define UHOOK_FUNCRET_OVERRIDE		0x20
#define UHOOK_FUNCRET_BREAK			0x40

#define UHOOK_RET(val)				return val
#define UHOOK_RET_VOID()			return
#define UHOOK_RET_VOID_SUPERSEDE()	do {															\
										if (thishook)												\
											UHOOK_SET_FUNC_ATTR(thishook, UHOOK_FUNCRET_SUPERSEDE);	\
										return;														\
									} while (0)
#define UHOOK_RET_SUPERSEDE(val)	do {															\
										if (thishook)												\
											UHOOK_SET_FUNC_ATTR(thishook, UHOOK_FUNCRET_SUPERSEDE);	\
										return val;													\
									} while (0)
#define UHOOK_RET_VOID_OVERRIDE()	do {															\
										if (thishook)												\
											UHOOK_SET_FUNC_ATTR(thishook, UHOOK_FUNCRET_OVERRIDE);	\
										return;														\
									} while (0)
#define UHOOK_RET_OVERRIDE(val)		do {															\
										if (thishook)												\
											UHOOK_SET_FUNC_ATTR(thishook, UHOOK_FUNCRET_OVERRIDE);	\
										return val;													\
									} while (0)

									
/*
 *	These macros are used to create and call the original function.
 */
#define GET_HOOK_FUNC(func)			uhook_get_hook_node(_uhook, func)
#define GET_ORIG_FUNC(ret, ...)		ret (*_uh_orig_fptr)( __VA_ARGS__ ) = thishook->orig
#define CALL_ORIG_FUNC(...)			_uh_orig_fptr( __VA_ARGS__ )

 
/*
 *	Function invoking order.
 */
#define PRE_CALL		0				/* function is called before original function */
#define POST_CALL		1				/* function is called after original function */


/*
 *	Struct for a function bound to a hook.
 */
struct uhook_bound_func_t {
	struct uhook_bound_func_t* next;
	void* func;	
};


/*
 *	Struct for a given hook.
 */
struct uhook_func_t {
	struct uhook_func_t* next;
	void* func;
	void* orig;
	byte* stack;
	int alloc_stack_size;				/* the size of the temp stack (byte* stack)	*/
	int stack_size;						/* the size of the real function stack		*/
	int flags;
	struct uhook_bound_func_t* bind_pre;
	struct uhook_bound_func_t* bind_pre_last;
	struct uhook_bound_func_t* bind_post;
	struct uhook_bound_func_t* bind_post_last;
};


/*
 *	UnderHook instance object.
 */
struct uhook_t {
	struct uhook_func_t* func_tbl[UHOOK_HASH_SIZE];	/* array of hooked functions */
	int bitmode;			/* 32/16 */
	int flags;
};


/*
 *	External global uhook object.
 */
extern struct uhook_t* _uhook;


/*
 *	Interface object between application and uhook module.
 */
struct uhook_api_t {
	double version;
	double api_version;

	void (*uhook_set_object)(struct uhook_t* uh);
	
	struct uhook_t* (*uhook_init)();
	void (*uhook_free)(struct uhook_t* uh);

	void (*uhook_set)(struct uhook_t* uh, int enable, int disable);
	void (*uhook_set_func_attr)(struct uhook_t* uh, void* func, int setting, int value);

	int (*_add_hook)(struct uhook_t* uh, void* tfunc, void* nfunc, void* hfunc, int order, int attributes, int param_size);
	void (*_uhook_remove_all_hooks_for_func)(struct uhook_t* uh, void* func);

	struct uhook_func_t* (*uhook_get_hook_node)(struct uhook_t* uh, void* func);
	void (*uhook_resize_stack)(struct uhook_func_t* hptr, int size);
	void* (*uhook_make_void_ptr)(int dummy, ...);

	int (*mem_set_permissions)(void* src, int flags);

	int (*_uhook_remove_hook)(struct uhook_t* uh, void* tfunc, void* nfunc);
};


/*
 *	These are the API functions to be used.
 *	They will all be set to the same pointers in uhook_api_t.
 */
#ifdef __cplusplus
extern "C"
{
#endif

	#ifdef __UHOOK_SRC
		void uhook_set_object(struct uhook_t* uh);
			
		struct uhook_t* uhook_init();
		void uhook_free(struct uhook_t* uh);
		
		void uhook_set(struct uhook_t* uh, int enable, int disable);
		void uhook_set_func_attr(struct uhook_t* uh, void* func, int setting, int value);
		
		int _add_hook(struct uhook_t* uh, void* tfunc, void* nfunc, void* hfunc, int order, int attributes, int param_size);
		void _uhook_remove_all_hooks_for_func(struct uhook_t* uh, void* func);
		
		struct uhook_func_t* uhook_get_hook_node(struct uhook_t* uh, void* func);
		void uhook_resize_stack(struct uhook_func_t* hptr, int size);
		void* uhook_make_void_ptr(int dummy, ...);
		
		int mem_set_permissions(void* src, int flags);
		
		int _uhook_remove_hook(struct uhook_t* uh, void* tfunc, void* nfunc);
	#else
		void (*uhook_set_object)(struct uhook_t* uh);
		struct uhook_t* (*uhook_init)();
		void (*uhook_free)(struct uhook_t* uh);
		void (*uhook_set)(struct uhook_t* uh, int enable, int disable);
		void (*uhook_set_func_attr)(struct uhook_t* uh, void* func, int setting, int value);
		int (*_add_hook)(struct uhook_t* uh, void* tfunc, void* nfunc, void* hfunc, int order, int attributes, int param_size);
		void (*_uhook_remove_all_hooks_for_func)(struct uhook_t* uh, void* func);
		struct uhook_func_t* (*uhook_get_hook_node)(struct uhook_t* uh, void* func);
		void (*uhook_resize_stack)(struct uhook_func_t* hptr, int size);
		void* (*uhook_make_void_ptr)(int dummy, ...);
		int (*mem_set_permissions)(void* src, int flags);
		int (*_uhook_remove_hook)(struct uhook_t* uh, void* tfunc, void* nfunc);
	#endif

#ifdef __cplusplus
}
#endif

#endif /* _UHOOK_H */
