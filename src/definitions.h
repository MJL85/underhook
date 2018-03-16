/*
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
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *	$Header$
 *
 */
 
#ifndef _DEFINITIONS_H
#define _DEFINITIONS_H


/*
 *	This is the UnderHook source.
 *	This must not be defined in applications using UH.
 */
#define __UHOOK_SRC


/*
 *	This is so mem_set_permissions() can use both
 *	VirtualProtect() and mprotect() with universal flags
 */
#ifdef _WIN32
	#define MEM_RX		PAGE_EXECUTE_READ
	#define MEM_RWX		PAGE_EXECUTE_READWRITE
#else
	#define MEM_RX		(PROT_READ | PROT_EXEC)
	#define MEM_RWX		(PROT_READ | PROT_WRITE | PROT_EXEC)
#endif


/*
 *	Uncomment this to enable debugging.
 *	This will compile everything in test.c including a main()
 */
//#define _UH_DEBUG
#ifdef _WIN32
	#define WIN32_LEAN_AND_MEAN
	#include <windows.h>

	#define DLLEXPORT				__declspec(dllexport)
		
	#define inline					__inline

	inline int _dummy_func(char* b, ...);

	#ifdef _UH_DEBUG
		#define DEBUG	printf
	#else
		#define DEBUG	_dummy_func
	#endif

#else
	#define DLLEXPORT


	#ifdef _UH_DEBUG
		#define DEBUG	printf
	#else
		#define DEBUG(s, ...)
	#endif
#endif

 
#ifdef __cplusplus
		#define C_DLLEXPORT extern "C" DLLEXPORT
#else
		#define C_DLLEXPORT DLLEXPORT
#endif


/*
 *	The standard hook handler.
 */
#define UHOOK_HANDLER_FUNC			_uhook_func_handler


/*
 *      All "hooks" are called with no stack modifications
 *      so the current stack frame can be used.
 */
typedef void (*func_ptr)();


/*
 *	The number of bytes uhook must rewrite
 *	to hook a function.
 *
 *	A normal patch needs a push, a manual is a direct jump only.
 */
#define UHOOK_PATCH_SIZE_NORM		OP_JMP_SIZE + OP_PUSH_SIZE
#define UHOOK_PATCH_SIZE_MANUAL		OP_JMP_SIZE


/*
 *	Initial temporary stack size for uhook.
 *	Increased by the same increment as needed.
 *	Must be a power of 2.
 */
#define UHOOK_STACK_SIZE_INC	512
 

/*
 *	Flags for uhook_t->bitmode
 */
#define OPERAND_32_BIT		0x01
#define OPERAND_16_BIT		0x02
#define ADDR_32_BIT			0x04
#define ADDR_16_BIT			0x08


#ifdef __cplusplus
extern "C"
{
#endif



#ifdef __cplusplus
}
#endif

#endif /* _DEFINITIONS_H */
