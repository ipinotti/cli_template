#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

struct istat {
  char 				name[8];
  
  unsigned long		in_btcount;
  unsigned long		in_pkcount;
  int				in_btstat[32];
  int				in_pkstat[32];
  
  unsigned long		out_btcount;
  unsigned long		out_pkcount;
  int				out_btstat[32];
  int				out_pkstat[32];
};

struct istat World[64];
int          WorldSz;
int          CircPos;

int find_if (const char *);
void proc2if (char *, const char *);
double mkrate (int *, int, int, int);
unsigned long colval (const char *, int);

int main (int argc, char *argv[])
{
	FILE 			*procf;
	char			 buffer[1024];
	int			 cr_if;
	int			 cr_st;

	char			 if_name[8];
	unsigned long	 if_ipk, if_ibt;
	unsigned long	 if_opk, if_obt;
	
	WorldSz = 0;
	CircPos = 0;
	
//	strcpy (argv[0], "Stats Monitor");
	
	for (cr_if=0; cr_if<64; ++cr_if)
	{
		World[cr_if].name[0] = '\0';
		World[cr_if].in_btcount = 0;
		World[cr_if].in_pkcount = 0;
		World[cr_if].out_btcount = 0;
		World[cr_if].out_pkcount = 0;
		
		for (cr_st=0; cr_st<32; ++cr_st)
		{
			World[cr_if].in_btstat[cr_st] = 0;
			World[cr_if].in_pkstat[cr_st] = 0;
			World[cr_if].out_btstat[cr_st] = 0;
			World[cr_if].out_pkstat[cr_st] = 0;
		}
	}
	
	while (1)
	{
		procf = fopen ("/proc/net/dev", "r");
		if (!procf)
		{
			fprintf (stderr, "Could not open /proc/net/dev\n");
			exit (1);
		}
		while (!feof (procf))
		{
			buffer[0] = 0;
			fgets (buffer, 1023, procf);
			if (strlen (buffer) && (!strchr (buffer, '|')))
			{
				proc2if (if_name, buffer);
				if_ibt = colval (buffer, 0); // rcv bytes
				if_ipk = colval (buffer, 1); // rcv packets
				if_obt = colval (buffer, 8); // tx  bytes
				if_opk = colval (buffer, 9); // tx  packets
				
				cr_if = find_if (if_name);
				if (cr_if < 0)
				{
					strncpy (World[WorldSz].name, if_name, 7);
					World[WorldSz].name[7] = 0;
					World[WorldSz].in_btcount = if_ibt;
					World[WorldSz].in_pkcount = if_ipk;
					World[WorldSz].out_btcount = if_obt;
					World[WorldSz].out_pkcount = if_opk;
					cr_if = WorldSz;
					++WorldSz;
				}
				
				World[cr_if].in_btstat[CircPos] =
					if_ibt - World[cr_if].in_btcount;
				
				World[cr_if].in_pkstat[CircPos] =
					if_ipk - World[cr_if].in_pkcount;
				
				World[cr_if].out_btstat[CircPos] =
					if_obt - World[cr_if].out_btcount;
				
				World[cr_if].out_pkstat[CircPos] =
					if_opk - World[cr_if].out_pkcount;
				
				World[cr_if].in_btcount  = if_ibt;
				World[cr_if].in_pkcount  = if_ipk;
				World[cr_if].out_btcount = if_obt;
				World[cr_if].out_pkcount = if_opk;
			}
		}
		fclose (procf);
		
		procf = fopen ("/var/run/iftab.cish.new","w");
		if (!procf)
		{
			fprintf (stderr, "! Error: could not write runfile\n");
			exit (1);
		}
		fprintf (procf, "#iface\tpkin\t1m\t5m\tbtin\t1m\t5m\tpkout\t1m\t5m\tbtout\t1m\t5m\n");
		
		for (cr_if=0; cr_if < WorldSz; ++cr_if)
		{
			fprintf (procf,"%s\t", World[cr_if].name);
			fprintf (procf,"%.02f\t", ((double) World[cr_if].in_pkstat[CircPos])/((double) 10));
			fprintf (procf,"%.02f\t", mkrate (World[cr_if].in_pkstat, 30, CircPos, 6)/((double) 10));
			fprintf (procf,"%.02f\t", mkrate (World[cr_if].in_pkstat, 30, CircPos, 30)/((double) 10));
			fprintf (procf,"%.02f\t", ((double) World[cr_if].in_btstat[CircPos])/((double) 10));
			fprintf (procf,"%.02f\t", mkrate (World[cr_if].in_btstat, 30, CircPos, 6)/((double) 10));
			fprintf (procf,"%.02f\t", mkrate (World[cr_if].in_btstat, 30, CircPos, 30)/((double) 10));
			fprintf (procf,"%.02f\t", ((double) World[cr_if].out_pkstat[CircPos])/((double) 10));
			fprintf (procf,"%.02f\t", mkrate (World[cr_if].out_pkstat, 30, CircPos, 6)/((double) 10));
			fprintf (procf,"%.02f\t", mkrate (World[cr_if].out_pkstat, 30, CircPos, 30)/((double) 10));
			fprintf (procf,"%.02f\t", ((double) World[cr_if].out_btstat[CircPos])/((double) 10));
			fprintf (procf,"%.02f\t", mkrate (World[cr_if].out_btstat, 30, CircPos, 6)/((double) 10));
			fprintf (procf,"%.02f\t", mkrate (World[cr_if].out_btstat, 30, CircPos, 30)/((double) 10));
			fprintf (procf,"\n");
		}
		fclose (procf);
		
		rename ("/var/run/iftab.cish.new", "/var/run/iftab.cish");
		
		++CircPos;
		if (CircPos>=30) CircPos = 0;
		sleep (10);
	}
}

int find_if (const char *ifname)
{
	int cr_if;
	
	for (cr_if=0; cr_if<WorldSz; ++cr_if)
	{
		if (strcmp (World[cr_if].name, ifname) == 0)
			return cr_if;
	}
	return -1;
}

// retorna o nome da interface (primeiro item da string, antes do ':')
void proc2if (char *dst, const char *src)
{
	int opos;
	char *crsr = (char *) src;
	
	opos = 0;
	
	while (*crsr == ' ') ++crsr;
	if (*crsr)
	{
		while ((opos<7)&&(*crsr != ':'))
		{
			dst[opos++] = *crsr;
			++crsr;
		}
		dst[opos] = 0;
	}
}

// retorna o valor da coluna numero 'pos'
unsigned long colval (const char *buf, int pos)
{
	char *crsr;
	int out;
	
	crsr = strchr (buf, ':');
	if (!crsr) return 666;
	while ((*crsr) && (!isdigit (*crsr))) ++crsr;
	
	for (out=0; out<pos; ++out)
	{
	    while ((*crsr>='0')&&(*crsr<='9')) ++crsr;
	    while ((*crsr) && ((*crsr<'0')||(*crsr>'9'))) ++crsr;
	    if (!(*crsr)) return 666;
	}
	
	return strtoul (crsr, NULL, 10);
}

double mkrate (int *array, int size, int pos, int sample)
{
	int crsr;
	int amount;
	double total;
	
	crsr = pos;
	amount = 0;
	total = 0;
	
	while (amount < sample)
	{
		total += array[crsr];
		--crsr;
		++amount;
		if (crsr<0) crsr = size-1;
	}
	
	return (total/amount);
}
