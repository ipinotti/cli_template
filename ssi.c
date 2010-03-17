/* ssi - server-side-includes CGI program
**
** Copyright © 1995 by Jef Poskanzer <jef@acme.com>.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
** OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h> /* sleep */

#include "match.h"
#include "ssi.h"
#include "ssi_cmds.h"

#define ST_GROUND 0
#define ST_QUESTION 1
#define ST_LESSTHAN 2


static void read_file( char* vfilename, char* filename, FILE* fp );

static char* url;

static char timefmt[100];
static int sizefmt;
#define SF_BYTES 0
#define SF_ABBREV 1

static void
internal_error( char* reason )
    {
    char* title = "500 Internal Error";

    (void) printf( "\
Content-type: text/html\n\
\n\
<HTML><HEAD><TITLE>%s</TITLE></HEAD>\n\
<BODY><H2>%s</H2>\n\
Something unusual went wrong during a server-side-includes request:\n\
<BLOCKQUOTE>\n\
%s\n\
</BLOCKQUOTE>\n\
</BODY></HTML>\n", title, title, reason );
    }


static void
not_found( char* filename )
    {
    char* title = "404 Not Found";

    (void) printf( "\
Content-type: text/html\n\
\n\
<HTML><HEAD><TITLE>%s</TITLE></HEAD>\n\
<BODY><H2>%s</H2>\n\
The requested server-side-includes filename, %s,\n\
does not seem to exist.\n\
</BODY></HTML>\n", title, title, filename );
    }

static void
not_permitted(char* directive, char* tag, char* val )
    {
    char* title = "Not Permitted";

    (void) printf( "\
<HR><H2>%s</H2>\n\
The filename requested in the %s %s=%s directive\n\
may not be fetched.\n\
<HR>\n", title, directive, tag, val );
    }

static int
check_filename( char* filename )
    {
    static int inited = 0;
    static char* cgi_pattern;
//    int fnl;
//    char* cp;
//    char* dirname;
//    char* authname;
//    struct stat sb;
//    int r;
    if ( ! inited )
	{
	/* Get the cgi pattern. */
	cgi_pattern = getenv( "CGI_PATTERN" );
#ifdef CGI_PATTERN
	if ( cgi_pattern == (char*) 0 )
	    cgi_pattern = CGI_PATTERN;
#endif /* CGI_PATTERN */
	inited = 1;
	}
    /* ../ is not permitted. */
    if ( strstr( filename, "../" ) != (char*) 0 )
	return 0;

#ifdef AUTH_FILE
    /* Ensure that we are not reading a basic auth password file. */
    fnl = strlen(filename);
    if ( strcmp( filename, AUTH_FILE ) == 0 ||
	 ( fnl >= sizeof(AUTH_FILE) &&
	   strcmp( &filename[fnl - sizeof(AUTH_FILE) + 1], AUTH_FILE ) == 0 &&
	   filename[fnl - sizeof(AUTH_FILE)] == '/' ) )
	return 0;

#if 0
/* Tive que desligar o teste abaixo, pois do contrario nao poderia incluir o
   arquivo '.htpasswd' em todos os diretorios e, se eu mantiver o '.htpasswd'
   somente no diretorio raiz (/web/) a autenticacao somente e' realizada para
   este diretorio.
 */

    /* Check for an auth file in the same directory.  We can't do an actual
    ** auth password check here because CGI programs are not given the
    ** authorization header, for security reasons.  So instead we just
    ** prohibit access to all auth-protected files.
    */
    dirname = strdup( filename );
    if ( dirname == (char*) 0 )
	return 0;	/* out of memory */
    cp = strrchr( dirname, '/' );
    if ( cp == (char*) 0 )
	(void) strcpy( dirname, "." );
    else
	*cp = '\0';
    authname = malloc( strlen( dirname ) + 1 + sizeof(AUTH_FILE) );
    if ( authname == (char*) 0 )
	return 0;	/* out of memory */
    (void) sprintf( authname, "%s/%s", dirname, AUTH_FILE );
    r = stat( authname, &sb );
    free( dirname );
    free( authname );
    if ( r == 0 )
	return 0;
#endif

#endif /* AUTH_FILE */

printf("%d, ", __LINE__);	    
    /* Ensure that we are not reading a CGI file. */
    if ( cgi_pattern != (char*) 0 && match( cgi_pattern, filename ) )
	return 0;
printf("%d, ", __LINE__);	    

    return 1;
    }


static void slurp( char* vfilename, char* filename, FILE* fp )
{
    char buf[1000];
    int i;
    int ich;
    int state;

    /* Now slurp in the rest of the comment from the input file. */
    i = 0;
    state = ST_GROUND;
    while ( ( ich = getc( fp ) ) != EOF )
    {
	switch ( state )
	{
	  case ST_GROUND:
	    if (ich=='?') state = ST_QUESTION;
	  break;
  
          case ST_QUESTION:
	    if ( ich == '>' )
	    {
	      buf[i-1] = '\0';
              ssi_cmd(buf);
	      return;
	    }
	    else if ( ich != '-' )
	      state = ST_GROUND;
	  break;
        }
	if ( i < sizeof(buf) - 1 )
	    buf[i++] = (char) ich;
    }
}


static void read_file( char* vfilename, char* filename, FILE* fp )
{
    int ich;
    int state;

    /* Copy it to output, while running a state-machine to look for
    ** SSI directives.
    */
    state = ST_GROUND;
    while ( ( ich = getc( fp ) ) != EOF )
    {
	switch ( state )
        {
	    case ST_GROUND:
	        if ( ich == '<' )
	            { state = ST_LESSTHAN; continue; }
	    break;
	    
	    case ST_LESSTHAN:
	        if ( ich == '?' )
		{
		    slurp( vfilename, filename, fp );
		    state = ST_GROUND;
		    continue;
		}
	        else
		{ state = ST_GROUND; (void) fputs ( "<", stdout ); }
	    break;
	}
	putchar( (char) ich );
    }
}

int ssi_main(void)
    {
    char* script_name;
    char* path_info;
    char* path_translated;
    FILE* fp;

    /* Default formats. */
    (void) strcpy( timefmt, "%a %b %e %T %Z %Y" );
    sizefmt = SF_BYTES;

    /* Get the name that we were run as. */
    script_name = getenv( "SCRIPT_NAME" );
    if ( script_name == (char*) 0 )
	{
	internal_error( "Couldn't get SCRIPT_NAME environment variable." );
	exit( 1 );
	}

    /* Append the PATH_INFO, if any, to get the full URL. */
    path_info = getenv( "PATH_INFO" );
    if ( path_info == (char*) 0 )
	{
	internal_error( "Couldn't get PATH_INFO environment variable." );
	exit( 1 );
	}
    url = (char*) malloc( strlen( script_name ) + strlen( path_info ) + 1 );
    if ( url == (char*) 0 )
	{
	internal_error( "Out of memory." );
	exit( 1 );
	}
    (void) sprintf( url, "%s%s", script_name, path_info );

    /* Get the name of the file to parse. */
    path_translated = getenv( "PATH_TRANSLATED" );
    if ( path_translated == (char*) 0 )
	{
	internal_error( "Couldn't get PATH_TRANSLATED environment variable." );
	exit( 1 );
	}

    if ( ! check_filename( path_translated ) )
	{
	not_permitted("initial", "PATH_TRANSLATED", path_translated );
	exit( 1 );
	}

    /* Open it. */
    fp = fopen( path_translated, "r" );
    if ( fp == (FILE*) 0 )
	{
	not_found( path_translated );
	exit( 1 );
	}

    /* The MIME type has to be text/html. */
    (void) fputs( "Content-type: text/html\n\n", stdout );

    /* Read and handle the file. */
    read_file( path_info, path_translated, fp );

    (void) fclose( fp );

    exit( 0 );
    }
