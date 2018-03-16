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
 
#ifndef _HANLDER_H
#define _HANLDER_H


/*
 *	Handle how the hook handler should deal with
 *	special returns.
 *	Since this is used twice in the same function,
 *	and since it is not really a function in itself,
 *	a macro may be the best choice.
 */ 
#define HANDLE_FUNC_RETURNS()	do {																		\
									/* Check for any special returns */										\
									if (UHOOK_FUNC_HAS_ATTR(hptr, UHOOK_FUNCRET_SUPERSEDE)) {				\
										/* SUPERSEDE */														\
										return ret;															\
									} else if (UHOOK_FUNC_HAS_ATTR(hptr, UHOOK_FUNCRET_OVERRIDE)) {			\
										/* OVERRIDE */														\
										super_ret = ret;													\
										super_ret_set = 1;													\
									} else if (UHOOK_FUNC_HAS_ATTR(hptr, UHOOK_FUNCRET_BREAK)) {			\
										/* BREAK */															\
									}																		\
								} while (0)


#ifdef __cplusplus
extern "C"
{
#endif

struct uhook_func_t;

long _uhook_func_handler(struct uhook_func_t* hptr, ...);

#ifdef __cplusplus
}
#endif

#endif /* _HANLDER_H */
