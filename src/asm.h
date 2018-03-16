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
 
#ifndef _ASM_H
#define _ASM_H

#include "uhook.h"
#include "definitions.h"

struct opcode_t;
struct uhook_t;
struct uhook_func_t;

typedef int (*opcode_parse_fptr)(struct uhook_t*, struct opcode_t*, byte*, byte*);
struct opcode_t {
	byte op;
	
	int opsize32;
	int opsize16;
	int modrm;						/* offset to modr/m byte (0 if none)	*/
	int branch;						/* does this instruction branch? (if so this is the offset to the offset)	*/
	int flags;
	opcode_parse_fptr fptr;
};

/*
 *	This nice little series of defines was inspired by Detours.
 *	It's much easier to just put common elements in a definition
 *	than in the array itself in asm.c.
 */

/*
 *	opcode_t flags
 */
#define OPERAND_ADDR		0x01

							/*			size32	size16		modr/m		branch?		flags			function		*/
#define OP_COPY_BYTE					1,		1,			0,			0,			0,				copy_opcode
#define OP_COPY_BYTES_2					2,		2,			0,			0,			0,				copy_opcode
#define OP_COPY_BYTES_2_MODRM			2,		2,			1,			0,			0,				copy_opcode
#define OP_COPY_BYTES_3					3,		3,			0,			0,			0,				copy_opcode
#define OP_COPY_BYTES_4					4,		4,			0,			0,			0,				copy_opcode
#define OP_COPY_0F						0,		0,			0,			0,			0,				NULL
#define OP_COPY_66						0,		0,			0,			0,			0,				NULL
#define OP_COPY_67						0,		0,			0,			0,			0,				NULL
#define OP_COPY_BYTES_2_MODRM_OPERAND	6,		4,			1,			0,			0,				copy_opcode	// operand word/double word
#define OP_COPY_BYTES_2_MODRM_1_BYTE	3,		3,			1,			0,			0,				copy_opcode	// operand 1 byte
#define OP_COPY_JUMP					0,		0,			0,			0,			0,				NULL
#define OP_COPY_BYTES_3OR5				5,		3,			0,			0,			0,				copy_opcode	// operand 2 or 4 bytes
#define OP_COPY_BYTES_3OR5_ADDR			5,		3,			0,			0,			OPERAND_ADDR,	copy_opcode
#define OP_COPY_BYTES_5OR7				0,		0,			0,			0,			0,				NULL		// operand address 32-bit or 48-bit
#define OP_COPY_BYTE_DNY				0,		0,			0,			0,			0,				NULL
#define OP_COPY_BYTES_2_DNY				0,		0,			0,			0,			0,				NULL
#define OP_COPY_BYTES_3_DNY				0,		0,			0,			0,			0,				NULL
#define OP_COPY_BYTES_2_NOJUMP			0,		0,			0,			0,			0,				NULL
#define OP_COPY_BYTES_2_JUMP			0,		0,			0,			0,			0,				NULL
#define OP_COPY_PREFIX					0,		0,			0,			0,			0,				NULL
#define OP_BADOP						0,		0,			0,			0,			0,				NULL
#define OP_COPY_BYTES_3OR5_BRANCH		5,		3,			0,			1,			0,				copy_opcode
#define OP_COPY_FF						0,		0,			0,			0,			0,				copy_opcode_ff
#define OP_COPY_F7						0,		0,			0,			0,			0,				copy_opcode_f7

/* NULL entry for opcodes not yet implemented */
#define NULL_ENTRY						0,		0,			0,			0,			0,				NULL

#define OP_JMP			0xe9
#define OP_JMP_SIZE		5

#define OP_PUSH			0x68
#define OP_PUSH_SIZE	5
	
#ifdef __cplusplus
extern "C"
{
#endif

int copy_func_header_opcodes(struct uhook_t* uhook, struct uhook_func_t* hook, void* src, byte** copy, int bytes);

#ifdef __cplusplus
}
#endif


#endif /* _ASM_H */
