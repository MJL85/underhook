/*
 *	UnderHook
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#ifndef _WIN32
	#include <unistd.h>
	#include <sys/mman.h>
#else
	#define WIN32_LEAN_AND_MEAN
	#include <Windows.h>
#endif

#include "definitions.h"
#include "asm.h"
#include "handler.h"
#include "uhook.h"

static void uhook_delink_bound_func_node(struct uhook_t* uh, struct uhook_func_t* nptr);
static struct uhook_func_t* uhook_free_hook_struct(struct uhook_func_t* nptr);
static void inject_push(void* src, long value);
static void inject_jmp(void* src, void* dest);
static int uhook_hash_index(void* address);
static int _uhook_delink_bind(struct uhook_t* uh, struct uhook_func_t* hook, void* func);
static void _uhook_hard_remove_hook(struct uhook_t* uh, struct uhook_func_t* hook);


/*
 *	Global instance and API object
 */
struct uhook_t* _uhook;
struct uhook_api_t uhook_api = {
	UHOOK_VERSION,
	UHOOK_API_VERSION,
	uhook_set_object,
	uhook_init,
	uhook_free,
	uhook_set,
	uhook_set_func_attr,
	_add_hook,
	_uhook_remove_all_hooks_for_func,
	uhook_get_hook_node,
	uhook_resize_stack,
	uhook_make_void_ptr,
	mem_set_permissions,
	_uhook_remove_hook
};


/*
 *	Entry point (when used as a shared object)
 */
DLLEXPORT int uhook_main(struct uhook_api_t** uh) {
	if (!uh)
		return 0;
	
	*uh = &uhook_api;
	
	return 1;
}


/*
 *	Initialize an instance of UnderHook.
 */
struct uhook_t* uhook_init() {
	struct uhook_t* uh = (struct uhook_t*)malloc(sizeof(struct uhook_t));
	memset(uh, 0, sizeof(struct uhook_t));
	
	uh->flags = UHOOK_DEFAULT_FLAGS;
	
	uh->bitmode = (OPERAND_32_BIT | ADDR_32_BIT);
	return uh;
}


/*
 *	Set the global _uhook object to be uh.
 *	This is needed if uhook is being used as
 *	a dynamic library.
 */
void uhook_set_object(struct uhook_t* uh) {
	_uhook = uh;
}


/*
 *	Free an instance of UnderHook.
 */
void uhook_free(struct uhook_t* uh) {
	struct uhook_func_t* nptr = NULL;
	int i = 0;
	int manual_hook = 0;

	for (; i < UHOOK_HASH_SIZE; ++i) {
		nptr = uh->func_tbl[i];
		
		while (nptr) {
			manual_hook = UHOOK_FUNC_HAS_ATTR(nptr, UHOOK_FUNCATTR_MANUAL_HOOK);

			/*
			 *	Here we want to remove all hooks to this function, so
			 *	we can just go ahead and repatch now.
			 */
			if (!copy_func_header_opcodes(_uhook, nptr, nptr->orig, (byte**)&nptr->func,
				(manual_hook ? UHOOK_PATCH_SIZE_MANUAL : UHOOK_PATCH_SIZE_NORM))) {

				DEBUG("ERROR: Unable to restore function.\n");
				return;
			}
		
			nptr = uhook_free_hook_struct(nptr);
		}
	}

	free(uh);
}


/*
 *	Remove the given function node from the
 *	hooked function hash table.
 */
static void uhook_delink_bound_func_node(struct uhook_t* uh, struct uhook_func_t* nptr) {
	struct uhook_func_t* lnptr = NULL;
	int i = 0;
	
	/* iterate through each bucket */
	for (; i < UHOOK_HASH_SIZE; ++i) {
		lnptr = uh->func_tbl[i];

		if (lnptr == nptr) {
			/* delink the first node in the list */
			uh->func_tbl[i] = nptr->next;
			return;
		}
		
		/* try to find the node to the left of the one we want */
		while (lnptr && lnptr->next) {
			if (lnptr->next == nptr)
				break;
			lnptr = lnptr->next;
		}
		
		if (lnptr) {
			/* the next node is the node we want to delink */
			lnptr->next = nptr->next;
			break;
		}
	}
}


/*
 *	Free a hook structure.
 *	This will not repatch the function.
 *
 *	Returns pointer to next node.
 */
static struct uhook_func_t* uhook_free_hook_struct(struct uhook_func_t* nptr) {
	struct uhook_func_t* next = NULL;
	struct uhook_bound_func_t* bptr = NULL;
	
	if (!nptr)
		return NULL;
	
	free(nptr->orig);
	if (nptr->stack)
		free(nptr->stack);
	
	/* free pre binds */
	bptr = nptr->bind_pre;
	while (bptr) {
		nptr->bind_pre_last = bptr->next;
		free(bptr);
		bptr = nptr->bind_pre_last;
	}
	
	/* free post binds */
	bptr = nptr->bind_post;
	while (bptr) {
		nptr->bind_post_last = bptr->next;
		free(bptr);
		bptr = nptr->bind_post_last;
	}
	
	next = nptr->next;
	free(nptr);
	
	return next;
}


/*
 *	Set the permissions for a given page in memory.
 *
 *	Flags can be:
 *		MEM_RX	- Read and execute
 *		MEM_RWX	- Read, write, and execute
 *
 *	Returns 1 if successful.
 */
int mem_set_permissions(void* src, int flags) {
	#ifndef _WIN32
		int pagesize = getpagesize();
		if (mprotect(((byte*)src - ((long)src % pagesize)), 10, flags) == -1) {
			perror("mem_set_permissions()");
			return 0;
		}
		return 1;
	#else
		int old;

		FlushInstructionCache(GetCurrentProcess(), NULL, 0);

		if (!VirtualProtect(src, 10, flags, &old)) {
			char buf[1024] = {0};
			FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
						(LPCVOID)FORMAT_MESSAGE_FROM_HMODULE,
						GetLastError(), 0, buf, 1024, NULL);
			DEBUG(">>> [%s]\n", buf);
			return 0;
		}
		return 1;
	#endif
}


/*
 *	Inject a push opcode at the given address
 *	with the given value.
 */
static void inject_push(void* src, long value) {
	*(unsigned char*)src = OP_PUSH;
	*(long*)((byte*)src + 1) = value;
}


/*
 *	Inject a jmp opcode at the given address
 *	to the given destination.
 *	Jumps are relative.
 */
static void inject_jmp(void* src, void* dest) {
	*(unsigned char*)src = OP_JMP;
	*(long*)((byte*)src+1) = (long)((byte*)dest - ((byte*)src + OP_JMP_SIZE));
}


/*
 *	Enable or disable a flag for uhook.
 *	Flags may be OR'ed togther.
 *
 *	Valid flags are in uhook.h under
 *		"User definable flags for uhook_t->flags"
 */
void uhook_set(struct uhook_t* uh, int enable, int disable) {
	/* remove mutually exclusive flags */
	enable &= ~disable;
	disable &= ~enable;
	
	/* update uhook flags */
	uh->flags |= enable;
	uh->flags &= ~disable;
}


/*
 *	Set specified hooked function attributes.
 *
 *	Valid flags are in uhook.h under
 *		User definable function attributes.
 */
void uhook_set_func_attr(struct uhook_t* uh, void* func, int setting, int value) {
	struct uhook_func_t* hook = uhook_get_hook_node(uh, func);
	if (!hook)
		return;
	
	switch (setting) {
		
		case UHOOK_FUNCATTR_STACK_SIZE:
			hook->stack_size = value;
			break;
		
		default:
			hook->flags |= setting;
	}	
}


/*
 *	Make a hook from tfunc->nfunc.
 *
 *	Parameters:
 *		uh			- uhook structure
 *		tfunc		- target function to hook
 *		nfunc		- the function to be bound to tfunc
 *		hfunc		- handler function, normally NULL (if NULL, will be set to UHOOK_HANDLER_FUNC)
 *		order		- what order to bind (PRE_CALL/POST_CALL)
 *		attributes	- what attributes to set for this hooked function
 *		param_size	- the size of the parameters in bytes (set to 0 if you want to use autodetection)
 *
 *	Return:
 *		0 - failure
 *		1 - successful
 */ 
int _add_hook(struct uhook_t* uh, void* tfunc, void* nfunc, void* hfunc, int order, int attributes, int param_size) {
	struct uhook_func_t* hook = NULL;
	struct uhook_bound_func_t* bind = NULL;
	int i = 0;
	int new_hook = 0;		/* is this a new hook? */
	int manual_hook = 0;	/* is this a mnaual hook? */

	DEBUG("_add_hook()\n");
	
	if (!hfunc)
		/* No handler specified - use UHOOK_HANDLER_FUNC */
		hfunc = UHOOK_HANDLER_FUNC;

	/* Get or allocate hook information structure */
	hook = uhook_get_hook_node(uh, tfunc);
	if (!hook) {
		hook = (struct uhook_func_t*)malloc(sizeof(struct uhook_func_t));
		memset(hook, 0, sizeof(struct uhook_func_t));
		new_hook = 1;
	}
	
	/* is this a manual hook? */
	manual_hook = ((attributes & UHOOK_FUNCATTR_MANUAL_HOOK) == UHOOK_FUNCATTR_MANUAL_HOOK);
	if (manual_hook)
		hook->flags |= UHOOK_FUNCATTR_MANUAL_HOOK;
	
	/* set attribute flags and param size */
	hook->flags |= attributes;
	hook->stack_size = param_size;
	
	DEBUG("new hook? %i\tmanual hook? %i\n", new_hook, manual_hook);
	DEBUG("hook struct is:\t\t\t%p\n", hook);

	/*
	 *	If this function is hooked and it was a manual hook,
	 *	or if the function is hooked and this is a manual hook attempt,
	 *	then no further functions can be bound to it.
	 */
	if (!new_hook && (manual_hook || UHOOK_FUNC_HAS_ATTR(hook, UHOOK_FUNCATTR_MANUAL_HOOK))) {
		DEBUG("this function already manually hooked\n");
		return 0;
	}

	/*
	 *	Initialize a function bind structure
	 *	Only needed if it's not a manual hook.
	 */
	if (!manual_hook) {
		bind = (struct uhook_bound_func_t*)malloc(sizeof(struct uhook_bound_func_t));
	
		bind->next = NULL;
		bind->func = (func_ptr)nfunc;
	}
	
	if (!hook->func) {
		/* Make initial hook on target function */
		hook->func = tfunc;
		
		/*
		 *	Duplicate first bytes of function so it can
		 *	be called directly without invoking the
		 *	handler.
		 */
		if (!copy_func_header_opcodes(uh, hook, tfunc, (byte**)&hook->orig,
			(manual_hook ? UHOOK_PATCH_SIZE_MANUAL : UHOOK_PATCH_SIZE_NORM))) {
				
			free(bind);
			if (new_hook)
				free(hook);
			return 0;
		}
		
		if (!mem_set_permissions(tfunc, MEM_RWX)) {
			// todo - revert old func
			free(bind);
			if (new_hook)
				free(hook);
			return 0;
		}
		
		/* Inject a PUSH with the hook node address and a JMP from tfunc to hfunc */
		if (manual_hook) {
			/* manual hook patch */
			inject_jmp(tfunc, (void*)hfunc);
		} else {
			/* normal hook patch */
			inject_push(tfunc, (long)hook);
			inject_jmp((byte*)tfunc + OP_PUSH_SIZE, (void*)hfunc);
		}
		
		if (!mem_set_permissions(tfunc, MEM_RX)) {
			// todo - revert old func - revert jmp
			free(bind);
			if (new_hook)
				free(hook);
			return 0;
		}
		
		/* Add new hooked function to uhook information hash table if it's a new hook */
		if (new_hook) {
			i = uhook_hash_index(tfunc);
			if (!_uhook->func_tbl[i])
				_uhook->func_tbl[i] = hook;
			else {
				struct uhook_func_t* nptr = _uhook->func_tbl[i];
				while (nptr->next)
					nptr = nptr->next;
				nptr->next = hook;
			}
		}
	}

	/*
	 *	If this was a manual hook, nothing further is needed.
	 */
	if (manual_hook)
		return 1;
	
	/* Add function bind to hook list */
	if (order == PRE_CALL) {
		/* pre order */
		if (!hook->bind_pre)
			hook->bind_pre = hook->bind_pre_last = bind;
		else
			hook->bind_pre_last = hook->bind_pre_last->next = bind;
	} else {
		/* post order */
		if (!hook->bind_post)
			hook->bind_post = hook->bind_post_last = bind;
		else
			hook->bind_post_last = hook->bind_post_last->next = bind;
	}

	return 1;
}


/*
 *	Remove all hooks made on the given function.
 *	This will result in a repatching of the target
 *	function and deletion of all assoicated hooks
 *	from memory.
 *
 *	This is the public interface version of
 *	_uhook_hard_remove_hook()
 */
void _uhook_remove_all_hooks_for_func(struct uhook_t* uh, void* func) {
	/* Get the node for this function address */
	struct uhook_func_t* nptr = uhook_get_hook_node(uh, func);
	
	if (!nptr)
		/* This function is not hooked */
		return;
	
	/*
	 *	Since we are removing all bound functions from
	 *	this hook, we can safely repatch the target
	 *	function at this time.
	 */
	_uhook_hard_remove_hook(uh, nptr);
}


/*
 *	Repatch the function for the given hook and deallocate
 *	and remove the hook structure from memory.
 *
 *	This is the backend version of
 *	_uhook_remove_all_hooks_for_func()
 */
static void _uhook_hard_remove_hook(struct uhook_t* uh, struct uhook_func_t* hook) {
	int manual_hook = UHOOK_FUNC_HAS_ATTR(hook, UHOOK_FUNCATTR_MANUAL_HOOK);

	if (!copy_func_header_opcodes(_uhook, hook, hook->orig, (byte**)&hook->func,
		(manual_hook ? UHOOK_PATCH_SIZE_MANUAL : UHOOK_PATCH_SIZE_NORM))) {

		DEBUG("ERROR: Unable to restore function.\n");
		return;
	}
	
	/* Delink the node from the hash table */
	uhook_delink_bound_func_node(uh, hook);
	
	/* Now delete the node itself */
	uhook_free_hook_struct(hook);
}


/*
 *	Remove a given hook to a given hooked function.
 *	If no further hooks apply for that function, the
 *	target function will be repatched.
 *
 *	tfunc	- target function that was hooked
 *	nfunc	- bound function that is being removed
 *
 *	Returns 1 for success, 0 for failure.
 */
int _uhook_remove_hook(struct uhook_t* uh, void* tfunc, void* nfunc) {
	/* Get the node for this function address */
	int manual_hook = 0;
	struct uhook_func_t* hook = uhook_get_hook_node(uh, tfunc);
	
	if (!hook)
		/* This function is not hooked */
		return -1;
	
	manual_hook = UHOOK_FUNC_HAS_ATTR(hook, UHOOK_FUNCATTR_MANUAL_HOOK);
	
	/*
	 *	If this is not a manual hook, find the bound function in
	 *	the PRE_CALL or POST_CALL list.
	 */
	if (!_uhook_delink_bind(uh, hook, nfunc))
		return -2;
	
	/*
	 *	If there are no longer any binds for this hook,
	 *	repatch the function and remove this hook from
	 *	memory.
	 */
	if (!hook->bind_pre && !hook->bind_post)
		_uhook_hard_remove_hook(uh, hook);
	
	return 1;
}


/*
 *	Locate a bound function in the given hooks list
 *	and delink and deallocate it.
 */
static int _uhook_delink_bind(struct uhook_t* uh, struct uhook_func_t* hook, void* func) {
	struct uhook_bound_func_t* nptr = NULL;
	struct uhook_bound_func_t* pptr = NULL;
	int i = 0;
	
	/* try to find the bind */
	for (; i < 2; ++i) {		
		nptr = (i ? hook->bind_post : hook->bind_pre);
		while (nptr) {
			if (nptr->func == func)
				break;		
			pptr = nptr;
			nptr = nptr->next;
		}
		
		if (nptr)
			break;
	}
	
	if (!nptr)
		/* function not bound to this hook */
		return 0;
	
	if (!pptr) {
		/* if there is no parent pointer, first bind in list */
		if (!i)
			hook->bind_pre = nptr->next;		/* pre list */
		else
			hook->bind_post = nptr->next;		/* post list */
	} else
		/* otherwise set the parents next to be the nodes next */
		pptr->next = nptr->next;
	
	if (!nptr->next) {
		/* if there is no next pointer, last bind in list */
		if (!i)
			hook->bind_pre_last = nptr->next;		/* pre list */
		else
			hook->bind_post_last = nptr->next;		/* post list */
	}
	
	/* free the node */
	free(nptr);	
	
	return 1;
}


/*
 *	Calculate the index the given address
 *	should reside in the hash table.
 *
 *	UHOOK_HASH_SIZE must be a power of 2.
 */
static int uhook_hash_index(void* address) {
	return (int)((long)address & (UHOOK_HASH_SIZE - 1));
}


/*
 *	Return a pointer to the hook information
 *	structure assoicated with the given hooked
 *	function address.
 */
struct uhook_func_t* uhook_get_hook_node(struct uhook_t* uh, void* func) {
	int i = uhook_hash_index(func);
	struct uhook_func_t* nptr = NULL;
	
	if (!uh->func_tbl[i])
		return NULL;
	
	nptr = uh->func_tbl[i];
	
	while (nptr) {
		if (nptr->func == func)
			return nptr;
		nptr = nptr->next;
	}
	
	return NULL;
}


/*
 *	Reallocate the temporary stack space to a
 *	suitable multipule of UHOOK_STACK_SIZE_INC
 *	that can hold at least "size" bytes for the
 *	given function hook.
 *
 *	The resize formula is based on the _INTSIZEOF macro.
 */
void uhook_resize_stack(struct uhook_func_t* hptr, int size) {
	hptr->alloc_stack_size = ((size + UHOOK_STACK_SIZE_INC - 1) & ~(UHOOK_STACK_SIZE_INC - 1));
	if (!hptr->stack)
		hptr->stack = (byte*)malloc(hptr->alloc_stack_size);
	else
		hptr->stack = (byte*)realloc(hptr->stack, hptr->alloc_stack_size);
}


/*
 *	This hack will convert an arbitrary pointer
 *	after the "dummy" parameter to a void*.
 *
 *	CyberMind came up with this one.
 */
void* uhook_make_void_ptr(int dummy, ...) {
	va_list va;
	void* vptr = NULL;
	
	va_start(va, dummy);
	vptr = va_arg(va, void*);
	va_end(va);
	
	return vptr;
}


/*
 *	Dummy function used for no debugging with Win32.
 *	Todo - what to do with this..?
 */
#ifndef _UH_DEBUG
inline int _dummy_func(char* b, ...) { return 0; }
#endif
