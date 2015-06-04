/*
 * Perform dynamic DNS updates for hosts using IPv6 stateless
 * address autoconfiguration.
 *
 * Copyright (C) 2005 Philip Blundell <philb@gnu.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

int ttl = 3600;
char *myhostname, *mydomain, *tsigkey;

char *cfgfile = "/etc/ddnsv6d.conf";

struct nsupdate_req
{
  int nr;
  char **strings;
};

void
run_nsupdate (struct nsupdate_req *req)
{
  FILE *fp;
  int i;
  
  fp = popen ("nsupdate", "w");
  if (! fp)
    {
      syslog (LOG_ERR, "cannot invoke nsupdate");
      return;
    }

  for (i = 0; i < req->nr; i++)
    {
      fputs (req->strings[i], fp);
      fputc ('\n', fp);
    }

  fputs ("send\n", fp);

  fclose (fp);
}

struct nsupdate_req *
new_req (void)
{
  struct nsupdate_req *req;

  req = malloc (sizeof (*req));

  memset (req, 0, sizeof (*req));

  return req;
}

void
free_req (struct nsupdate_req *req)
{
  int i;

  for (i = 0; i < req->nr; i++)
    free (req->strings[i]);

  if (req->strings)
    free (req->strings);

  free (req);
}

void
add_to_req (struct nsupdate_req *req, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  req->nr++;
  req->strings = realloc (req->strings, req->nr * sizeof (char *));
  vasprintf (&req->strings[req->nr - 1], fmt, ap);
  va_end (ap);
}

int
in6_bits (struct in6_addr *a, int b)
{
  return ((a->in6_u.u6_addr8[b / 8] << (b & 7)) >> 4) & 15;
}

void
make_reverse_name (struct in6_addr *a, char *p)
{
  int i;
  const char hexdigits[] = "0123456789abcdef";

  for (i = 124; i >= 0; i -= 4)
    {
      int bits;

      bits = in6_bits (a, i);

      *p++ = hexdigits[bits];
      *p++ = '.';
    }

  strcpy (p, "ip6.arpa");
}

void
add_address (struct in6_addr *a, int prefixlen)
{
  char buf[128];
  char revhostname[256];
  struct nsupdate_req *req;

  inet_ntop (AF_INET6, a, buf, sizeof (buf));

  syslog (LOG_INFO, "new address %s", buf);

  make_reverse_name (a, revhostname);
  
  req = new_req ();
  if (tsigkey)
    add_to_req (req, "key %s", tsigkey);
  add_to_req (req, "update delete %s", myhostname);
  add_to_req (req, "update add %s %d IN AAAA %s", myhostname, ttl, buf);
  run_nsupdate (req);
  free_req (req);

  req = new_req ();
  if (tsigkey)
    add_to_req (req, "key %s", tsigkey);
  add_to_req (req, "update delete %s", revhostname);
  add_to_req (req, "update add %s %d IN PTR %s", revhostname, ttl, myhostname);
  run_nsupdate (req);
  free_req (req);
}

void
delete_address (struct in6_addr *a, int prefixlen)
{
  char buf[128];
  struct nsupdate_req *req;
  
  inet_ntop (AF_INET6, a, buf, sizeof (buf));

  syslog (LOG_INFO, "delete address %s", buf);

  /*
   * XXX Should make an effort to clean up old PTR records here, something like:
   *
   * req = new_req ();
   * if (tsigkey)
   *   add_to_req (req, "key %s", tsigkey);
   * add_to_req (req, "prereq yxrrset %s IN PTR %s", revhostname, myhostname);
   * add_to_req (req, "update delete %s", revhostname);
   * run_nsupdate (req);
   * free_req (req);
   *
   * But: if the address on our main interface has gone away, might not be able to
   * reach the nameserver.  Probably need to defer the update until a new address 
   * is assigned.  No need to delete the old AAAA record since it will just be
   * overwritten by the new address.
   */
}

void
rtnl_address_event (struct nlmsghdr *h, struct ifaddrmsg *msg)
{
  struct in6_addr *a;
  int attrlen;
  struct rtattr *attr;

  /* Ignore non IPv6 addresses */
  if (msg->ifa_family != AF_INET6)
    return;

  /* Ignore link local addresses */
  if (msg->ifa_scope >= RT_SCOPE_LINK)
    return;

  attrlen = h->nlmsg_len - NLMSG_ALIGN (sizeof (struct ifaddrmsg));
  if (attrlen >= sizeof (*a) + sizeof (struct rtattr))
    {
      attr = IFA_RTA (msg);
      a = RTA_DATA (attr);

      if (h->nlmsg_type == RTM_NEWADDR)
	add_address (a, msg->ifa_prefixlen);
      else if (h->nlmsg_type == RTM_DELADDR)
	delete_address (a, msg->ifa_prefixlen);
    }
}

void
rtnl_process (int fd)
{
  char	buf[8192];
  struct sockaddr_nl nladdr;
  struct iovec iov = { buf, sizeof(buf) };
  int status;
  struct nlmsghdr *h;

  struct msghdr msg = {
    (void*)&nladdr, sizeof(nladdr),
    &iov,	1,
    NULL,	0,
    0
  };
  
  for (;;)
    {
      status = recvmsg (fd, &msg, 0);
      if (status <= 0)
	break;

      if (msg.msg_namelen != sizeof (nladdr)) 
	continue;

      h = (struct nlmsghdr*)buf;
      while (NLMSG_OK (h, status)) 
	{
	  switch (h->nlmsg_type)
	    {
	    case RTM_NEWADDR:
	    case RTM_DELADDR:
	      rtnl_address_event (h, NLMSG_DATA (h));
	      break;
	    }
	  
	  h = NLMSG_NEXT (h, status);
	}
    }
}

void
getfqdn (char *domainname)
{
  char leafname[256];
    
  if (gethostname (leafname, sizeof (leafname)))
    {
      perror ("gethostname");
      exit (1);
    }

  asprintf (&myhostname, "%s.%s", leafname, domainname);
}

char *
xstrdup (const char *str)
{
  char *v;

  v = strdup (str);
  if (!v)
    {
      perror ("strdup");
      exit (1);
    }

  return v;
}

void
handle_config_line (char *buf, const char *fn, int lnr)
{
  char *key, *q;

  buf[strlen (buf) - 1] = 0;

  while (isspace (*buf))
    buf++;
  if (*buf == 0 || *buf == '\n' || *buf == '#')
    return;

  key = buf;
  buf++;
  while (*buf != 0 && ! isspace (*buf))
    buf++;
  q = buf;
  while (isspace (*buf))
    buf++;
  if (*buf == 0)
    {
      fprintf (stderr, "%s:%d: missing value\r\n", fn, lnr);
      exit (1);
    }
  *q = 0;

  if (!strcmp (key, "domain"))
    mydomain = xstrdup (buf);
  else if (!strcmp (key, "tsigkey"))
    tsigkey = xstrdup (buf);
  else if (!strcmp (key, "ttl"))
    ttl = atoi (buf);
  else
    {
      fprintf (stderr, "%s:%d: unrecognized \"%s\"\r\n", fn, lnr, key);
      exit (1);
    }
}

void
read_config (const char *fn)
{
  FILE *fp;
  int line = 1;
  char buf[512];

  fp = fopen (fn, "r");
  if (! fp)
    {
      perror (fn);
      exit (1);
    }

  while (! feof (fp))
    {
      if (fgets (buf, sizeof (buf), fp))
	handle_config_line (buf, fn, line++);
    }
  fclose (fp);
}

int
main (int argc, char *argv[])
{
  int fd;
  struct sockaddr_nl local;
  int nodaemon = 0;
  int opt;

  while (opt = getopt (argc, argv, "h?dc:"), opt != -1)
    {
      switch (opt)
	{
	case 'h':
	case '?':
	  fprintf (stderr, "usage: %s [-d] [-c file]\n", argv[0]);
	  exit (0);

	case 'd':
	  nodaemon = 1;
	  break;

	case 'c':
	  cfgfile = optarg;
	  break;
	}
    }

  read_config (cfgfile);

  getfqdn (mydomain);

  fd = socket (AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (fd < 0)
    {
      perror ("socket");
      exit (1);
    }

  memset (&local, 0, sizeof (local));
  local.nl_family = AF_NETLINK;
  local.nl_groups = RTMGRP_IPV6_IFADDR;
  
  if (bind (fd, (struct sockaddr*)&local, sizeof (local)) < 0) 
    {
      perror("Cannot bind netlink socket");
      close (fd);
      return -1;
    }

  openlog ("ddnsv6d", 0, LOG_DAEMON);

  if (! nodaemon)
    daemon (0, 0);

  rtnl_process (fd);

  exit (0);
}
