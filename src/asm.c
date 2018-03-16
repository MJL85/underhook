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
#include <string.h>
#include <malloc.h>

#ifdef _WIN32
	#define WIN32_LEAN_AND_MEAN
	#include <Windows.h>
#else
	#include <sys/mman.h>
#endif

#include "definitions.h"
#include "uhook.h"
#include "asm.h"

static int copy_opcode(struct uhook_t* uhook, struct opcode_t* op, byte* src, byte* dest);
static int copy_opcode_ff(struct uhook_t* uhook, struct opcode_t* op, byte* src, byte* dest);
static int copy_opcode_f7(struct uhook_t* uhook, struct opcode_t* op, byte* src, byte* dest);

struct opcode_t opcodes[] = {
	{	0x00,	OP_COPY_BYTES_2_MODRM	},			// ADD Eb, Gb
	{	0x01,	OP_COPY_BYTES_2_MODRM	},			// ADD Ev, Gv
	{	0x02,	OP_COPY_BYTES_2_MODRM	},			// ADD Gb, Eb
	{	0x03,	OP_COPY_BYTES_2_MODRM	},			// ADD Gv, Ev
	{	0x04,	OP_COPY_BYTES_2			},			// ADD AL, Ib
	{	0x05,	OP_COPY_BYTES_3OR5		},			// ADD eAX, Iv
	{	0x06,	OP_COPY_BYTE			},			// PUSH ES
	{	0x07,	OP_COPY_BYTE			},			// POP ES
	{	0x08,	OP_COPY_BYTES_2_MODRM	},			// OR Eb, Gb
	{	0x09,	OP_COPY_BYTES_2_MODRM	},			// OR Ev, Gv
	{	0x0A,	OP_COPY_BYTES_2_MODRM	},			// OR Gb, Eb
	{	0x0B,	OP_COPY_BYTES_2_MODRM	},			// OR Gv, Ev
	{	0x0C,	OP_COPY_BYTES_2			},			// OR AL, Ib
	{	0x0D,	OP_COPY_BYTES_3OR5		},			// OR eAX, Iv
	{	0x0E,	OP_COPY_BYTE			},			// PUSH CS
	{	0x0F,	OP_COPY_0F				},			// 2 byte escape (extends opcodes to another set)

	{	0x10,	OP_COPY_BYTES_2_MODRM	},			// ADC Eb, Gb
	{	0x11,	OP_COPY_BYTES_2_MODRM	},			// ADC Ev, Gv
	{	0x12,	OP_COPY_BYTES_2_MODRM	},			// ADC Gb, Eb
	{	0x13,	OP_COPY_BYTES_2_MODRM	},			// ADC Gv, Ev
	{	0x14,	OP_COPY_BYTES_2			},			// ADC AL, Ib
	{	0x15,	OP_COPY_BYTES_3OR5		},			// ADC eAX, Iv
	{	0x16,	OP_COPY_BYTE			},			// PUSH SS
	{	0x17,	OP_COPY_BYTE			},			// POP SS
	{	0x18,	OP_COPY_BYTES_2_MODRM	},			// SBB Eb, Gb
	{	0x19,	OP_COPY_BYTES_2_MODRM	},			// SBB Ev, Gv
	{	0x1A,	OP_COPY_BYTES_2_MODRM	},			// SBB Gb, Eb
	{	0x1B,	OP_COPY_BYTES_2_MODRM	},			// SBB Gv, Ev
	{	0x1C,	OP_COPY_BYTES_2			},			// SBB AL, Ib
	{	0x1D,	OP_COPY_BYTES_3OR5		},			// SBB eAX, Iv
	{	0x1E,	OP_COPY_BYTE			},			// PUSH DS
	{	0x1F,	OP_COPY_BYTE			},			// POP DS

	{	0x20,	OP_COPY_BYTES_2_MODRM	},			// AND Eb, Gb
	{	0x21,	OP_COPY_BYTES_2_MODRM	},			// AND Ev, Gv
	{	0x22,	OP_COPY_BYTES_2_MODRM	},			// AND Gb, Eb
	{	0x23,	OP_COPY_BYTES_2_MODRM	},			// AND Gv, Ev
	{	0x24,	OP_COPY_BYTES_2			},			// AND AL, Ib
	{	0x25,	OP_COPY_BYTES_3OR5		},			// AND eAX, Iv
	{	0x26,	OP_COPY_PREFIX			},			// SEG = ES
	{	0x27,	OP_COPY_BYTE			},			// DAA
	{	0x28,	OP_COPY_BYTES_2_MODRM	},			// SUB Eb, Gb
	{	0x29,	OP_COPY_BYTES_2_MODRM	},			// SUB Ev, Gv
	{	0x2A,	OP_COPY_BYTES_2_MODRM	},			// SUB Gb, Eb
	{	0x2B,	OP_COPY_BYTES_2_MODRM	},			// SUB Gv, Ev
	{	0x2C,	OP_COPY_BYTES_2			},			// SUB AL, Ib
	{	0x2D,	OP_COPY_BYTES_3OR5		},			// SUB eAX, Iv
	{	0x2E,	OP_COPY_PREFIX			},			// SEG = CS
	{	0x2F,	OP_COPY_BYTE			},			// DAS

	{	0x30,	OP_COPY_BYTES_2_MODRM	},			// XOR Eb, Gb
	{	0x31,	OP_COPY_BYTES_2_MODRM	},			// XOR Ev, Gv
	{	0x32,	OP_COPY_BYTES_2_MODRM	},			// XOR Gb, Eb
	{	0x33,	OP_COPY_BYTES_2_MODRM	},			// XOR Gv, Ev
	{	0x34,	OP_COPY_BYTES_2			},			// XOR AL, Ib
	{	0x35,	OP_COPY_BYTES_3OR5		},			// XOR eAX, Iv
	{	0x36,	OP_COPY_PREFIX			},			// SEG = SS
	{	0x37,	OP_COPY_BYTE			},			// AAA
	{	0x38,	OP_COPY_BYTES_2_MODRM	},			// CMP Eb, Gb
	{	0x39,	OP_COPY_BYTES_2_MODRM	},			// CMP Ev, Gv
	{	0x3A,	OP_COPY_BYTES_2_MODRM	},			// CMP Gb, Eb
	{	0x3B,	OP_COPY_BYTES_2_MODRM	},			// CMP Gv, Ev
	{	0x3C,	OP_COPY_BYTES_2			},			// CMP AL, Ib
	{	0x3D,	OP_COPY_BYTES_3OR5		},			// CMP eAX, Iv
	{	0x3E,	OP_COPY_PREFIX			},			// SEG = DS
	{	0x3F,	OP_COPY_BYTE			},			// AAS

	{	0x40,	OP_COPY_BYTE			},			// INC eAX
	{	0x41,	OP_COPY_BYTE			},			// INC eCX
	{	0x42,	OP_COPY_BYTE			},			// INC eDX
	{	0x43,	OP_COPY_BYTE			},			// INC eBX
	{	0x44,	OP_COPY_BYTE			},			// INC eSP
	{	0x45,	OP_COPY_BYTE			},			// INC eBP
	{	0x46,	OP_COPY_BYTE			},			// INC eSI
	{	0x47,	OP_COPY_BYTE			},			// INC eDI
	{	0x48,	OP_COPY_BYTE			},			// DEC eAX
	{	0x49,	OP_COPY_BYTE			},			// DEC eCX
	{	0x4A,	OP_COPY_BYTE			},			// DEC eDX
	{	0x4B,	OP_COPY_BYTE			},			// DEC eBX
	{	0x4C,	OP_COPY_BYTE			},			// DEC eSP
	{	0x4D,	OP_COPY_BYTE			},			// DEC eBP
	{	0x4E,	OP_COPY_BYTE			},			// DEC eSI
	{	0x4F,	OP_COPY_BYTE			},			// DEC eDI

	{	0x50,	OP_COPY_BYTE			},			// PUSH eAX
	{	0x51,	OP_COPY_BYTE			},			// PUSH eCX
	{	0x52,	OP_COPY_BYTE			},			// PUSH eDX
	{	0x53,	OP_COPY_BYTE			},			// PUSH eBX
	{	0x54,	OP_COPY_BYTE			},			// PUSH eSP
	{	0x55,	OP_COPY_BYTE			},			// PUSH eBP
	{	0x56,	OP_COPY_BYTE			},			// PUSH eSI
	{	0x57,	OP_COPY_BYTE			},			// PUSH eDI
	{	0x58,	OP_COPY_BYTE			},			// POP eAX
	{	0x59,	OP_COPY_BYTE			},			// POP eCX
	{	0x5A,	OP_COPY_BYTE			},			// POP eDX
	{	0x5B,	OP_COPY_BYTE			},			// POP eBX
	{	0x5C,	OP_COPY_BYTE			},			// POP eSP
	{	0x5D,	OP_COPY_BYTE			},			// POP eBP
	{	0x5E,	OP_COPY_BYTE			},			// POP eSI
	{	0x5F,	OP_COPY_BYTE			},			// POP eDI

	{	0x60,	OP_COPY_BYTE			},			// PUSHA / PUSHAD
	{	0x61,	OP_COPY_BYTE			},			// POPA / POPAD
	{	0x62,	OP_COPY_BYTES_2_MODRM	},			// BOUND Gv, Ma
	{	0x63,	OP_COPY_BYTES_2_MODRM	},			// ARPL Ew, Gw
	{	0x64,	OP_COPY_PREFIX			},			// SEG = FS
	{	0x65,	OP_COPY_PREFIX			},			// SEG = GS
	{	0x66,	OP_COPY_66				},			// Opd Size
	{	0x67,	OP_COPY_67				},			// Addr Size
	{	0x68,	OP_COPY_BYTES_3OR5		},			// PUSH Iv
	{	0x69,	OP_COPY_BYTES_2_MODRM_OPERAND	},	// IMUL Gv, Ev, Iv
	{	0x6A,	OP_COPY_BYTES_2			},			// PUSH Ib
	{	0x6B,	OP_COPY_BYTES_2_MODRM_1_BYTE	},	// IMUL Gv, Ev, Ib
	{	0x6C,	OP_COPY_BYTE			},			// INS / INSB Yb, DX
	{	0x6D,	OP_COPY_BYTE			},			// INS / INSW / INSD Yv, DX 
	{	0x6E,	OP_COPY_BYTE			},			// OUTS / OUTSB DX, Xb
	{	0x6F,	OP_COPY_BYTE			},			// OUTS / OUTSW / OUTSD DX, Xv

	{	0x70,	OP_COPY_JUMP			},			// JO
	{	0x71,	OP_COPY_JUMP			},			// JNO
	{	0x72,	OP_COPY_JUMP			},			// JB / JNE / JC
	{	0x73,	OP_COPY_JUMP			},			// JNB / JAE / JNC
	{	0x74,	OP_COPY_JUMP			},			// JZ / JE
	{	0x75,	OP_COPY_JUMP			},			// JNZ / JNE
	{	0x76,	OP_COPY_JUMP			},			// JBE / JNA
	{	0x77,	OP_COPY_JUMP			},			// JNBE / JA
	{	0x78,	OP_COPY_JUMP			},			// JS
	{	0x79,	OP_COPY_JUMP			},			// JNS
	{	0x7A,	OP_COPY_JUMP			},			// JP / JPE
	{	0x7B,	OP_COPY_JUMP			},			// JNP / JPO
	{	0x7C,	OP_COPY_JUMP			},			// JL / JNGE
	{	0x7D,	OP_COPY_JUMP			},			// JNL / JGE
	{	0x7E,	OP_COPY_JUMP			},			// JLE / JNG
	{	0x7F,	OP_COPY_JUMP			},			// JNLE / JG

	{	0x80,	OP_COPY_BYTES_2_MODRM_1_BYTE	},	// (group 1) Eb, Ib
	{	0x81,	OP_COPY_BYTES_2_MODRM_OPERAND	},	// (group 1) Ev, Iz
	{	0x82,	OP_COPY_BYTES_2			},			// (group 1) Eb, Ib
	{	0x83,	OP_COPY_BYTES_2_MODRM_1_BYTE	},	// (group 1) Ev, Iv
	{	0x84,	OP_COPY_BYTES_2_MODRM	},			// TEST Eb, Gb
	{	0x85,	OP_COPY_BYTES_2_MODRM	},			// TEST Ev, Gv
	{	0x86,	OP_COPY_BYTES_2_MODRM	},			// XCHG Eb, Gb
	{	0x87,	OP_COPY_BYTES_2_MODRM	},			// XCHG Ev, Gv
	{	0x88,	OP_COPY_BYTES_2_MODRM	},			// MOV Eb, Gb
	{	0x89,	OP_COPY_BYTES_2_MODRM	},			// MOV Ev, Gv
	{	0x8A,	OP_COPY_BYTES_2_MODRM	},			// MOV Gb, Eb
	{	0x8B,	OP_COPY_BYTES_2_MODRM	},			// MOV Gv, Ev
	{	0x8C,	OP_COPY_BYTES_2_MODRM	},			// MOV Ew, Sw
	{	0x8D,	OP_COPY_BYTES_2_MODRM	},			// LEA Gv, M
	{	0x8E,	OP_COPY_BYTES_2_MODRM	},			// MOV Sw, Ew
	{	0x8F,	OP_COPY_BYTES_2_MODRM	},			// POP Ev

	{	0x90,	OP_COPY_BYTE			},			// NOP
	{	0x91,	OP_COPY_BYTE			},			// XCHG eAX, eCX
	{	0x92,	OP_COPY_BYTE			},			// XCHG eAX, eDX
	{	0x93,	OP_COPY_BYTE			},			// XCHG eAX, eBX
	{	0x94,	OP_COPY_BYTE			},			// XCHG eAX, eSP
	{	0x95,	OP_COPY_BYTE			},			// XCHG eAX, eBP
	{	0x96,	OP_COPY_BYTE			},			// XCHG eAX, eSI
	{	0x97,	OP_COPY_BYTE			},			// XCHG eAX, eDI
	{	0x98,	OP_COPY_BYTE			},			// CBW / CWDE
	{	0x99,	OP_COPY_BYTE			},			// CWD / CDQ
	{	0x9A,	OP_COPY_BYTES_5OR7		},			// CALLF Ap
	{	0x9B,	OP_COPY_BYTE			},			// FWAIT / WAIT
	{	0x9C,	OP_COPY_BYTE			},			// PUSHF / PUSHFD Fv
	{	0x9D,	OP_COPY_BYTE			},			// POPF  / POPFD Fv
	{	0x9E,	OP_COPY_BYTE			},			// SAHF
	{	0x9F,	OP_COPY_BYTE			},			// LAHF

	{	0xA0,	OP_COPY_BYTES_3OR5_ADDR	},			// MOV AL, Ob
	{	0xA1,	OP_COPY_BYTES_3OR5_ADDR	},			// MOV eAX, Ov
	{	0xA2,	OP_COPY_BYTES_3OR5_ADDR	},			// MOV Ob, AL
	{	0xA3,	OP_COPY_BYTES_3OR5_ADDR	},			// MOV Ov, eAX
	{	0xA4,	OP_COPY_BYTE			},			// MOVS / MOVSB Xb, Yb
	{	0xA5,	OP_COPY_BYTE			},			// MOVS / MOVSW / MOVSD Xv, Yv
	{	0xA6,	OP_COPY_BYTE			},			// CMPS / CMPSB Xb, Yb
	{	0xA7,	OP_COPY_BYTE			},			// CMPS / CMPSW / CMPSD Xv, Yv
	{	0xA8,	OP_COPY_BYTES_2			},			// TEST AL, Ib
	{	0xA9,	OP_COPY_BYTES_3OR5		},			// TEST eAX, Iv
	{	0xAA,	OP_COPY_BYTE			},			// STOS / STOSB Yb, AL
	{	0xAB,	OP_COPY_BYTE			},			// STOS / STOSW / STOSD Yv, eAX
	{	0xAC,	OP_COPY_BYTE			},			// LODS / LODSB AL, Xb
	{	0xAD,	OP_COPY_BYTE			},			// LOADS / LODSW / LODSD eAX, Xv
	{	0xAE,	OP_COPY_BYTE			},			// SCAS / SCASB AL, Yb
	{	0xAF,	OP_COPY_BYTE			},			// SCAS / SCASW / SCASD eAX, Xv

	{	0xB0,	OP_COPY_BYTES_2			},			// MOV AL
	{	0xB1,	OP_COPY_BYTES_2			},			// MOV CL
	{	0xB2,	OP_COPY_BYTES_2			},			// MOV DL
	{	0xB3,	OP_COPY_BYTES_2			},			// MOV BL
	{	0xB4,	OP_COPY_BYTES_2			},			// MOV AH
	{	0xB5,	OP_COPY_BYTES_2			},			// MOV CH
	{	0xB6,	OP_COPY_BYTES_2			},			// MOV DH
	{	0xB7,	OP_COPY_BYTES_2			},			// MOV BH
	{	0xB8,	OP_COPY_BYTES_3OR5		},			// MOV eAX
	{	0xB9,	OP_COPY_BYTES_3OR5		},			// MOV eCX
	{	0xBA,	OP_COPY_BYTES_3OR5		},			// MOV eDX
	{	0xBB,	OP_COPY_BYTES_3OR5		},			// MOV eBX
	{	0xBC,	OP_COPY_BYTES_3OR5		},			// MOV eSP
	{	0xBD,	OP_COPY_BYTES_3OR5		},			// MOV eBP
	{	0xBE,	OP_COPY_BYTES_3OR5		},			// MOV eSI
	{	0xBF,	OP_COPY_BYTES_3OR5		},			// MOV eDI

	{	0xC0,	OP_COPY_BYTES_2_MODRM_1_BYTE	},	// (group 2) Eb, Ib
	{	0xC1,	OP_COPY_BYTES_2_MODRM_1_BYTE	},	// (group 2) Ev, Ib
	{	0xC2,	OP_COPY_BYTES_3			},			// RETN Iw
	{	0xC3,	OP_COPY_BYTE			},			// RETN
	{	0xC4,	OP_COPY_BYTES_2_MODRM	},			// LES Gv, Mp
	{	0xC5,	OP_COPY_BYTES_2_MODRM	},			// LDS Gv, Mp
	{	0xC6,	OP_COPY_BYTES_2_MODRM_1_BYTE	},	// (group 11) MOV Eb, Ib
	{	0xC7,	OP_COPY_BYTES_2_MODRM_OPERAND	},	// (group 11) MOV Ev, Iv
	{	0xC8,	OP_COPY_BYTES_4			},			// ENTER Iw, Ib
	{	0xC9,	OP_COPY_BYTE			},			// LEAVE
	{	0xCA,	OP_COPY_BYTES_3_DNY		},			// RETF Iw
	{	0xCB,	OP_COPY_BYTE_DNY		},			// RETF
	{	0xCC,	OP_COPY_BYTE_DNY		},			// INT 3
	{	0xCD,	OP_COPY_BYTES_2_DNY		},			// INT Ib
	{	0xCE,	OP_COPY_BYTE_DNY		},			// INTO
	{	0xCF,	OP_COPY_BYTE_DNY		},			// IRET

	{	0xD0,	OP_COPY_BYTES_2_MODRM	},			// (group 2) Eb, Ib
	{	0xD1,	OP_COPY_BYTES_2_MODRM	},			// (group 2) Ev, 1
	{	0xD2,	OP_COPY_BYTES_2_MODRM	},			// (group 2) Eb, CL
	{	0xD3,	OP_COPY_BYTES_2_MODRM	},			// (group 2) Ev, CL
	{	0xD4,	OP_COPY_BYTES_2			},			// AAM Ib
	{	0xD5,	OP_COPY_BYTES_2			},			// AAD Ib
	{	0xD6,	OP_BADOP				},			//
	{	0xD7,	OP_COPY_BYTE			},			// XLAT / XLATB
	{	0xD8,	OP_COPY_BYTES_2_MODRM	},			// (ESC 0)
	{	0xD9,	OP_COPY_BYTES_2_MODRM	},			// (ESC 1) 
	{	0xDA,	OP_COPY_BYTES_2_MODRM	},			// (ESC 2)
	{	0xDB,	OP_COPY_BYTES_2_MODRM	},			// (ESC 3)
	{	0xDC,	OP_COPY_BYTES_2_MODRM	},			// (ESC 4)
	{	0xDD,	OP_COPY_BYTES_2_MODRM	},			// (ESC 5)
	{	0xDE,	OP_COPY_BYTES_2_MODRM	},			// (ESC 6)
	{	0xDF,	OP_COPY_BYTES_2_MODRM	},			// (ESC 7)

	{	0xE0,	OP_COPY_BYTES_2_NOJUMP	},			//
	{	0xE1,	OP_COPY_BYTES_2_NOJUMP	},			//
	{	0xE2,	OP_COPY_BYTES_2_NOJUMP	},			//
	{	0xE3,	OP_COPY_BYTES_2_JUMP	},			//
	{	0xE4,	OP_COPY_BYTES_2			},			//
	{	0xE5,	OP_COPY_BYTES_2			},			//
	{	0xE6,	OP_COPY_BYTES_2			},			//
	{	0xE7,	OP_COPY_BYTES_2			},			//
	{	0xE8,	OP_COPY_BYTES_3OR5_BRANCH	},		// CALL Jv
	{	0xE9,	OP_COPY_BYTES_3OR5_BRANCH	},		// JMP Jv
	{	0xEA,	NULL_ENTRY	},			//
	{	0xEB,	NULL_ENTRY	},			//
	{	0xEC,	NULL_ENTRY	},			//
	{	0xED,	NULL_ENTRY	},			//
	{	0xEE,	NULL_ENTRY	},			//
	{	0xEF,	NULL_ENTRY	},			//

	{	0xF0,	NULL_ENTRY	},			//
	{	0xF1,	NULL_ENTRY	},			//
	{	0xF2,	NULL_ENTRY	},			//
	{	0xF3,	NULL_ENTRY	},			//
	{	0xF4,	NULL_ENTRY	},			//
	{	0xF5,	NULL_ENTRY	},			//
	{	0xF6,	NULL_ENTRY	},			//
	{	0xF7,	OP_COPY_F7	},						// Single byte OpCode extension (Grp 3)
	{	0xF8,	NULL_ENTRY	},			//
	{	0xF9,	NULL_ENTRY	},			//
	{	0xFA,	NULL_ENTRY	},			//
	{	0xFB,	NULL_ENTRY	},			//
	{	0xFC,	NULL_ENTRY	},			//
	{	0xFD,	NULL_ENTRY	},			//
	{	0xFE,	NULL_ENTRY	},			//
	{	0xFF,	OP_COPY_FF	}						// Single byte OpCode extension (Grp 5)
};


/*
 *	ModR/M Decoding
 *	( http://www.swansontec.com/sintel.htm )
 *
 *  +---+---+---+---+---+---+---+---+
 *  |  MOD  |    REG    |    R/M    |
 *  +---+---+---+---+---+---+---+---+
 *
 *	MOD:
 *		00 - ( & 0x00 ) - operands memory address is in R/M
 *		01 - ( & 0x40 ) - operands memory address is R/M + byte displacement
 *		10 - ( & 0x80 ) - operands memory address is R/M + word displacement
 *		11 - ( & 0xC0 ) - operand is R/M
 *
 *	R/M:
 *		Under MOD 01:	100 = ESP
 *
 *	In 32-bit Mode:
 *		When MOD is a memory address (00, 01, 10) and R/M is ESP, SIB byte is needed.
 */

int copy_func_header_opcodes(struct uhook_t* uhook, struct uhook_func_t* hook, void* src, byte** copy, int bytes) {
	byte* f = src;
	byte* orig = NULL;
	int i = 0, len = 0;
	int patch = 1;		/* 1= func->block	0=block->func */
	
	if (!*copy) {
		/* PATCH: func -> block */
		*copy = (byte*)malloc(sizeof(byte*) * bytes);
	} else {
		/* REPATCH: block -> func */
		if (!mem_set_permissions(*copy, MEM_RWX)) {
			//printf("unable to set rwx for block\n");
			free(*copy);
			*copy = NULL;
			return 0;
		}
		patch = 0;
	}
		
	orig = *copy;
	
	/* copy opcodes */
	for (i = 0; i < bytes;) {
		if (opcodes[*f].fptr) {
			len = opcodes[*f].fptr(uhook, &opcodes[*f], f, (orig + i));
			if (*f == 0xc3) {
				/* ret reached */
				break;
			}
			f += len;
			i += len;
		} else {
			printf("*** UNKNOWN: %x\n", *f++);
			break;
			++i;
		}
	}
	
	/* inject a jmp opcode here to next opcode of real function */
	if (patch) {
		orig[i] = OP_JMP;
		*(long*)(orig + i + 1) = (long)(f - (orig + i + OP_JMP_SIZE));
		//*(long*)(orig + i + 1) = (long)(f - (orig + i + OP_PUSH_SIZE + OP_JMP_SIZE));
		//printf("src is: %x\n", src);
		//printf("will jump to: %x\n", orig + 5 + *(long*)(orig + i + 1));
	} else {
		/* function that was repatched should be set back to +rx */
		return (mem_set_permissions(orig, MEM_RX));
	}
	
	/* set +rwx permissions for block */
 	return (mem_set_permissions(orig, MEM_RWX));
}


static int copy_opcode(struct uhook_t* uhook, struct opcode_t* op, byte* src, byte* dest) {
	int i = 0;
	byte* osrc = src;
	byte* odest = dest;
	byte* modrm = ((op->modrm) ? (src + op->modrm) : NULL);
	
	/*
	 *	If this opcode has an address, use address mode.
	 *	Otherwise use operand mode.
	 */
	int bitmode = ((op->flags & OPERAND_ADDR) ?
				((uhook->bitmode & ADDR_32_BIT) ? 32 : 16) :
				((uhook->bitmode & OPERAND_32_BIT) ? 32 : 16));
	int len = ((bitmode == 32) ? op->opsize32 : op->opsize16);
	//printf(" bitmode: %i\tlen: %i\n", bitmode, len);
	
	//printf("  ModR/M = %x\n", modrm ? *modrm : 0);
	
	/* if there is R/M byte, decode it */
	if (op->modrm) {
		if ((*modrm & 0xC0) != 0xC0) {
			/* mod is 00, 01, or 10 */
			//printf("  modrm - mod=00,01,10\n");
			if ((*modrm & 0xC0) == 0x80) {
				/* mod is 10 - word displacement */
				len += 4;
			} else if ((*modrm & 0xC0) == 0x40) {
				/* mod is 01 - byte displacement */
				++len;
			}
			if ((*modrm & 0x07) == 0x04) {
				/* R/M is 100 (ESP) - SIB needed */
				//printf("  SIB - yes\n");
				++len;
			}
		} else {
			//printf("  modrm - mod=11\n");
		}
	}

	/* copy fixed number of bytes */
	for (; i < len; ++i)
		*dest++ = *src++;

	/* if opcode branches, calculate new offset */
	if (op->branch) {
		//printf("  branch - yes\n");
		// todo - is this correct adjustment?
		if (bitmode == 32) {
			/* 32 bit */
			long oo = *(long*)(osrc + op->branch);
			long no = ((src + oo) - dest);
			*(long*)(odest + op->branch) = no;
			//printf("old: %p + %p = %p\n", src, oo, src+oo);
			//printf("new: %p + %p = %p\n", dest, no, dest+no);
		} else if (bitmode == 16) {
			/* 16 bit */
			short oo = *(short*)(osrc + op->branch);
			short no = ((src + oo) - dest);
			*(short*)(odest + op->branch) = no;
		}
	} else {
		//printf("  branch - no\n");
	}
	
	return len;
}


static int copy_opcode_ff(struct uhook_t* uhook, struct opcode_t* op, byte* src, byte* dest) {
	int copy_size = 2;			/* opcode + ModRM + (operands?) */
	
	/*
	 *	ModR/M:
	 *		000		Inc Ev
	 *		001		Dec Ev
	 *		010		Calln Ev
	 *		011		Callf Ep
	 *		100		JMPN Ev
	 *		101		JMPF Ep
	 *		110		PUSH Ev
	 */
	
	/* Copy the opcode and ModRM byte */
	*dest++ = *src++;
	*dest++ = *src++;
	
	/* The next byte is a ModR/M byte */
	if (
		((*src & 0x07) == 0x00) ||		/* Inc Ev	*/
		((*src & 0x07) == 0x01) ||		/* Dec Ev	*/
		((*src & 0x07) == 0x02) ||		/* Calln Ev	*/
		((*src & 0x07) == 0x04) ||		/* JMPN Ev	*/
		((*src & 0x07) == 0x06)			/* PUSH Ev	*/
		) {
		
		if (uhook->bitmode & OPERAND_32_BIT) {
			*(long*)dest = *(long*)src;
			copy_size += 4;
		} else if (uhook->bitmode == OPERAND_16_BIT) {
			*(short*)dest = *(short*)src;
			copy_size += 2;
		}
	} else if (
			((*src & 0x07) == 0x03) ||	/* Callf Ep	*/
			((*src & 0x07) == 0x05)		/* JMPF Ep	*/
			) {
					
		/* 4 or 6 byte pointer */
		*(long*)dest = *(long*)src;
		copy_size += 4;
	}
	
	return copy_size;
}


static int copy_opcode_f7(struct uhook_t* uhook, struct opcode_t* op, byte* src, byte* dest) {
	/*
	 *	ModR/M:
	 *		000		Test Ib/Iv
	 *		001		
	 *		010		NOT
	 *		011		NEG
	 *		100		MUL AL/EAX
	 *		101		IMUL AL/EAX
	 *		110		DIV AL/EAX
	 *		111		IDIV AL/EAX
	 */
	
	if ((*src & 0x07) == 0x00) {
		struct opcode_t this_op = { 0xF7, OP_COPY_BYTES_2_MODRM_OPERAND };
		return (this_op.fptr(uhook, &this_op, src, dest));
	} else {	
		struct opcode_t this_op = { 0xF7, OP_COPY_BYTES_2_MODRM };
		return (this_op.fptr(uhook, &this_op, src, dest));
	}
	
	return 0;
}
