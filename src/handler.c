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
#include <stdarg.h>
#include <string.h>
#include "definitions.h"
#include "uhook.h"
#include "handler.h"

#ifdef _WIN32
	/*
	 *	Disable the compiler warning:
	 *		warning C4731: '_uhook_handler_callgate' : frame pointer register 'ebp' modified by inline assembly code
	 *
	 *	This is not a warning since this is what we wanted to do.
	 */
	#pragma warning(disable:4731)
#endif

static long _uhook_handler_callgate(func_ptr func, void* stack, int size);

/*
 *	Function is called when a hooked function is invoked.
 *	This will call bound functions and the original
 *	function using the callgate.
 */
long _uhook_func_handler(struct uhook_func_t* hptr, ...) {
	struct uhook_bound_func_t* nptr = NULL;
	int param_size = 0xDEAD;
	va_list va;
	long ret = 0;
	long super_ret = 0;
	int super_ret_set = 0;

	/*
	 *	Since hptr was pushed onto the stack after
 	 *	the CALL was made, hptr is above EIP on the
 	 *	stack.  Switch these two to correct it.
 	 */
	#ifndef _WIN32
		__asm__ __volatile__(
			"pushl %eax					\n"
			"pushl %ebx					\n"
			"movl 4(%ebp), %eax			\n"
			"movl 8(%ebp), %ebx			\n"
			"movl %eax, 8(%ebp)			\n"
			"movl %ebx, 4(%ebp)			\n"
			"popl %ebx					\n"
			"popl %eax					\n"
		);
	#else
		__asm {
			push eax
			push ebx
			mov eax, [ebp+4]
			mov ebx, [ebp+8]
			mov [ebp+8], eax
			mov [ebp+4], ebx
			pop ebx
			pop eax
		};
	#endif
		
	DEBUG("*****\n*****\n***** HANDLER CALLED *****\n*****\n*****\n");
	
	/*
	 *	Calculate the size of the previous
	 *	stack frame to estimate the size in bytes
	 *	of the parameter list.
	 *
	 *	Only do this if UHOOK_STACK_AUTODETECT is enabled
	 *	and the function has not been flagged as not having
	 *	a frame pointer.
	 */
	 if (UHOOK_IS_SET(UHOOK_STACK_AUTODETECT) &&
		 !UHOOK_FUNC_HAS_ATTR(hptr, UHOOK_FUNCATTR_NOFRAMEPTR)) {
		#ifndef _WIN32
			__asm__ __volatile__(
				"pushl %%eax				\n"
				"pushl %%ebx				\n"
		
				"movl (%%ebp), %%ebx		\n" /* ebx = old			*/
				"movl %%ebp, %%eax			\n" /* eax = new			*/
				"subl %%ebx, %%eax			\n" /* eax = new - old		*/
		
				"movl $0, %%ebx				\n" /* new-old is negative, so *= -1 */
				"subl %%eax, %%ebx			\n"

				"subl $8, %%ebx				\n" /* size -= 8 bytes (eip,ebp)	*/
		
				"movl %%ebx, %0				\n" /* set param_size = %ebx		*/
		
				"popl %%ebx					\n"
				"popl %%eax					\n"
			 
			 	: "=g" (param_size)
			);
		#else
			__asm {
				push eax
				push ebx
		
				mov ebx, [ebp]
				mov eax, ebp
				sub eax, ebx
		
				mov ebx, 0
				sub ebx, eax

				sub ebx, 8
		
				mov param_size, ebx

				pop ebx
				pop eax
			};
		#endif
	} else
		/* Otherwise we use the user defined stack size */
		param_size = hptr->stack_size;
	
	DEBUG("--- handler called [%p] [stack size: %i] ---\n", hptr, param_size);

	/* We need extra room for the thishook pointer on the stack */
	param_size += sizeof(void*);

	hptr->stack_size = param_size;

	/*	Resize stack buffer if needed	*/
	if ((param_size > hptr->alloc_stack_size) || (!hptr->stack))
		uhook_resize_stack(hptr, param_size);

	/* Put the thishook pointer on the top of the stack */
	*(int*)(hptr->stack) = (int)hptr;

	/* Duplicate stack frame */
	va_start(va, hptr);
	memcpy(hptr->stack+4, va, hptr->stack_size);
	va_end(va);
	
	/* Invoke pre binds */
	nptr = hptr->bind_pre;
	for (; nptr; nptr = nptr->next) {
		DEBUG("\n\ncalling gate (pre)...\n");
		
		/* Disable any left over return attributes */
		hptr->flags &= ~(UHOOK_FUNCRET_NORMAL | UHOOK_FUNCRET_SUPERSEDE | UHOOK_FUNCRET_OVERRIDE | UHOOK_FUNCRET_BREAK);

		ret = _uhook_handler_callgate(nptr->func, hptr->stack, hptr->stack_size);
		DEBUG("back to handler (pre)...\n\n\n");
		
		/* Check for any special returns */
		HANDLE_FUNC_RETURNS();
		
	}

	/* Invoke original function - stack offset by sizeof(void*) for thishook pointer */
	DEBUG("\n\ncalling gate (orig)...\n");
	ret = _uhook_handler_callgate(hptr->orig, hptr->stack+sizeof(void*), hptr->stack_size);
	if (!super_ret_set)
		super_ret = ret;
	DEBUG("back to handler (orig)...\n\n\n");

	/* Invoke post binds */
	nptr = hptr->bind_post;
	for (; nptr; nptr = nptr->next) {
		DEBUG("\n\ncalling gate (post)... %x %i\n", (unsigned int)nptr->func, hptr->stack_size);

		/* Disable any left over return attributes */
		hptr->flags &= ~(UHOOK_FUNCRET_NORMAL | UHOOK_FUNCRET_SUPERSEDE | UHOOK_FUNCRET_OVERRIDE | UHOOK_FUNCRET_BREAK);

		ret = _uhook_handler_callgate(nptr->func, hptr->stack, hptr->stack_size);
		DEBUG("back to handler (post)...\n\n\n");

		/* Check for any special returns */
		HANDLE_FUNC_RETURNS();
	}

	DEBUG("--- handler end ---\n");
	return super_ret;
}


/*
 *	This will call the function "func"
 *	after reintroducing the saved stack
 *	frame parameters onto the stack.
 */
static long _uhook_handler_callgate(func_ptr func, void* stack, int size) {
	byte* _ebp;
	int shift;

	#ifndef _WIN32
		__asm__ __volatile__(
			/*
			 *	Backup the current EBP value in the ebp variable.
			 */
			"movl %%ebp, %0			\n"		/* var _ebp */
		
			/*
			 *	Calculate amount of room needed on the stack
			 *	for the saved parameters.
			 *	(size of current parameters) - (size of needed parameters)
			 *	Store result in EAX
			 */
			"movl 16(%%ebp), %%eax	\n"
			"subl $8, %%eax			\n"
		
			/*
			 *	Adjust EBP and ESP to reflect changes.
			 */
			"subl %%eax, %%ebp		\n"
			"subl %%eax, %%esp		\n"

			/*
			 *	Copy needed register values to
			 *	the stack for local variables.
			 */
			"movl %%ebp, %0			\n"		/* var _ebp		*/
			"movl %%eax, %1			\n"		/* var shift	*/
			
			: "=g" (_ebp), "=g" (shift)
		);
	#else
		__asm {
			mov _ebp, ebp
		
			mov eax, [ebp+16]
			sub eax, 8
		
			sub ebp, eax
			sub esp, eax

			mov _ebp, ebp
			mov shift, eax
		}
	#endif
	
	/*
	 *	Shift saved EBP and EIP on stack upward
	 *	to align with the new EBP value.
	 *
	 *	Copy 20 bytes for:
	 *			4 bytes - EBP
	 *			4 bytes - EIP
	 *			4 bytes - func (function parameter)
	 *			4 bytes - stack (function parameter)
	 *			4 bytes - size (function parameter)
	 */
	memcpy(_ebp, _ebp + shift, 20);
	
	/*
	 *	Save the function address we will be invoking
	 *	because the next copy will replace all current
	 *	parameters.
	 */
	#ifndef _WIN32
		__asm__ __volatile__("movl 8(%ebp), %ebx\n");
	#else
		__asm { mov ebx, [ebp+8] };
	#endif

	/*
	 *	Copy saved stack parameters into the new
	 *	space allocated for them.
	 */
	 memcpy(_ebp + 8, stack, size);

	/*
	 *	Leave the current stack frame
	 *	and jump to the bound function.
	 *	The EIP will be the first thing on
	 *	the stack still, and points back to
	 *	the function handler, so this callgate
	 *	will be skipped on return.
	 */
	#ifndef _WIN32
		__asm__ __volatile__(
				"leave\n"
				"jmp *%ebx\n"
		);
	#else
		__asm {
			leave
			jmp ebx
		};
	#endif
	
	return 0xDEADBEEF;	/* control will never reach here */
}
