/*
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
 */

/*
 *	This file demonstrates how to make a hook.
 *	The strcmp() system function does not have a frame pointer.
 *
 *	Running a disassembly on this file gives:
 *		0804840c <strcmp@plt>:
 *		 804840c:       ff 25 98 9d 04 08       jmp    *0x8049d98
 *		 8048412:       68 00 00 00 00          push   $0x0
 *		 8048417:       e9 e0 ff ff ff          jmp    80483fc <_init+0x18>
 *
 *	This hook will redirect to strcmp_nocase() which is a case
 *	insensitive string comparison function.
 *	The return will halt the execution of the real strcmp()
 *	and override the return value.
 */

#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <ctype.h>
#include "uhook.h"


/*
 *	Case insensitive string compare.
 *
 *	Note:
 *		"return" is not used here since this
 *		function is specificlly used for hooking.
 *		Using return may produce undesired results.
 *
 *		However, it is now possible to call the function
 *		directly with the first parameter are NULL.
 *		The function will behave normally.
 */
int strcmp_nocase(UHOOK_THISHOOK_PTR, char* s1, char* s2) {
	if (!s1 && s2)				return -1;
	else if (s1 && !s2)			return 1;
	else if (!s1 && !s2)		return 0;

	while (*s1) {
		if (!*s2)
			UHOOK_RET_SUPERSEDE(1);
		if (tolower(*s1) > tolower(*s2))
			UHOOK_RET_SUPERSEDE(1);
		else if (tolower(*s1) < tolower(*s2))
			UHOOK_RET_SUPERSEDE(-1);
		++s1;
		++s2;
	}
    
	UHOOK_RET_SUPERSEDE(*s2 ? -1 : 0);
}


int main() {
	char* s1 = "abc";
	char* s2 = "ABC";
	int status = 0;
	
	/* Start UnderHook library */
	if (!uhook_startup("/home/para/Projects/uhook/uhook.so")) {
		printf("Unable to load UnderHook library.\n");
		return 0;
	}
	
	printf("strcmp(\"%s\", \"%s\") = %i\n", s1, s2, strcmp(s1, s2));
	printf("strcmp_nocase(NULL, \"%s\", \"%s\") = %i\n", s1, s2, strcmp_nocase(NULL, s1, s2));

	/* Hook the function strcmp() to strcmp_nocase() */
	printf("Attempting to hook function...");
	fflush(stdout);
	status = ADD_HOOK(strcmp, strcmp_nocase, PRE_CALL);
	printf("%s\n", status ? "success" : "failed");
	
	/* Call strcmp() which really calls strcmp_nocase() */
	printf("strcmp(\"%s\", \"%s\") = %i\n", s1, s2, strcmp(s1, s2));

	/* Shut UnderHook down */
	//uhook_shutdown();

	return 0;
}
