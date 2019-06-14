/* vim: set tabstop=8 shiftwidth=2 softtabstop=2 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2018 Red Hat, Inc.
 *
 * Author: Nathaniel McCallum
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "core.h"
#include "tlssock.h"
#include "idx.h"

#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static inline bool
is_tls(int fd, int errnum)
{
  tls_auto_t *tls = NULL;
  tls = idx_get(fd);
  if (!tls && errnum != 0)
    errno = errnum;
  return tls;
}

static int
inner_protocol(int protocol)
{
  switch (protocol) {
  case IPPROTO_TLS: return 0;
  default: return protocol;
  }
}

static tls_t *
test_tls_new(int fd)
{
  int protocol;
  int domain;
  int type;

  if (getsockopt_int(fd, SOL_SOCKET, SO_DOMAIN, &domain) < 0)
    return NULL;

  if (getsockopt_int(fd, SOL_SOCKET, SO_TYPE, &type) < 0)
    return NULL;

  if (getsockopt_int(fd, SOL_SOCKET, SO_PROTOCOL, &protocol) < 0)
    return NULL;

  if (!is_tls_domain(domain)) {
    errno = EINVAL; // FIXME
    return NULL;
  }

  if (!is_tls_type(type)) {
    errno = EINVAL; // FIXME
    return NULL;
  }

  if (!is_tls_inner_protocol(protocol)) {
    errno = EINVAL; // FIXME
    return NULL;
  }

  return tls_new();
}

int
accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  return accept4(sockfd, addr, addrlen, 0);
}

int
accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
  int fd;

  fd = NEXT(accept4)(sockfd, addr, addrlen, flags);

  if (fd >= 0) {
    tls_auto_t *lis = NULL;

    lis = idx_get(sockfd);
    if (lis) {
      tls_auto_t *con = NULL;

      con = test_tls_new(fd);
      if (!con || !idx_set(fd, con, NULL)) {
        close(fd);
        return -1;
      }
    }
  }

  return fd;
}

int
close(int fd)
{
  idx_del(fd);
  return NEXT(close)(fd);
}

int
dup(int oldfd)
{
  return is_tls(oldfd, ENOTSUP) ? -1 :
    NEXT(dup)(oldfd);
}

int
dup2(int oldfd, int newfd)
{
  return is_tls(oldfd, ENOTSUP) ? -1 :
    NEXT(dup2)(oldfd, newfd);
}

FILE *
fdopen(int fd, const char *mode)
{
  return is_tls(fd, ENOTSUP) ? NULL :
    NEXT(fdopen)(fd, mode);
}

int
getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
  int *prot = optval;
  int ret;

  /* Pass TLS level options into the tls_t layer. */
  if (level == IPPROTO_TLS) {
    tls_auto_t *tls = NULL;

    tls = idx_get(sockfd);
    if (!tls) {
      errno = EINVAL; // FIXME
      return -1;
    }

    switch(optname) {
      case TLS_IS_SERVER:
        *(int *) optval = tls->is_server;
        *optlen = sizeof(int);

        break;

      case TLS_PSK:
        *(int *) optval = tls->auth_method;
        *optlen = sizeof(int);

        break;

      case TLS_PSK_USER:
        if (tls->username == NULL) {
          fprintf(stderr, "Username has not been set!\n");
          return -1;
        }

        *optlen = strlen(tls->username);
        char *username = strdup(tls->username);
        optval = username;

        break;

      case TLS_PSK_KEY:
        *optlen = tls->key_size;
        optval = malloc(tls->key_size);
        memcpy(optval, tls->key, tls->key_size);

        break;
    }
    //return tls_getsockopt(tls->tls_prv, sockfd, optname, optval, optlen);
    return 0;
  }

  ret = NEXT(getsockopt)(sockfd, level, optname, optval, optlen);

  /* Translate the inner protocol to the outer one. */
  if (ret >= 0 && level == SOL_SOCKET && optname == SO_PROTOCOL &&
      is_tls_inner_protocol(*prot)) {
    tls_auto_t *tls = NULL;

    if (*optlen != sizeof(*prot)) {
      errno = EINVAL; // FIXME
      return -1;
    }

    tls = idx_get(sockfd);
    if (tls)
      *prot = IPPROTO_TLS;
  }

  return ret;
}

ssize_t
read(int fd, void *buf, size_t count)
{
  tls_auto_t *tls = NULL;

  tls = idx_get(fd);
  if (!tls)
    return NEXT(read)(fd, buf, count);

  return tls_read(tls, fd, buf, count);
}

ssize_t
recv(int sockfd, void *buf, size_t len, int flags)
{
  tls_auto_t *tls = NULL;

  tls = idx_get(sockfd);
  if (!tls)
    return NEXT(recv)(sockfd, buf, len, flags);

  if (flags != 0)
    return EINVAL; // FIXME

  return tls_read(tls, sockfd, buf, len);
}

ssize_t
recvfrom(int sockfd, void *buf, size_t len, int flags,
         struct sockaddr *src_addr, socklen_t *addrlen)
{
  if (src_addr == NULL && addrlen == NULL)
    return recv(sockfd, buf, len, flags);

  return is_tls(sockfd, ENOSYS) ? -1 : // TODO
    NEXT(recvfrom)(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t
recvmsg(int sockfd, struct msghdr *msg, int flags)
{
  return is_tls(sockfd, ENOSYS) ? -1 : // TODO
    NEXT(recvmsg)(sockfd, msg, flags);
}

ssize_t
send(int sockfd, const void *buf, size_t len, int flags)
{
  tls_auto_t *tls = NULL;

  tls = idx_get(sockfd);
  if (!tls)
    return NEXT(send)(sockfd, buf, len, flags);

  if (flags != 0)
    return EINVAL; // FIXME

  return tls_write(tls, sockfd, buf, len);
}

ssize_t
sendto(int sockfd, const void *buf, size_t len, int flags,
       const struct sockaddr *dest_addr, socklen_t addrlen)
{
  if (dest_addr == NULL && addrlen == 0)
    return send(sockfd, buf, len, flags);

  return is_tls(sockfd, ENOSYS) ? -1 : // TODO
    NEXT(sendto)(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t
sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
  return is_tls(sockfd, ENOSYS) ? -1 : // TODO
    NEXT(sendmsg)(sockfd, msg, flags);
}

int
setsockopt(int sockfd, int level, int optname,
           const void *optval, socklen_t optlen)
{
  tls_auto_t *already = NULL;
  tls_auto_t *tls = NULL;

  /* Pass TLS level options into the tls_t layer. */
  if (level == IPPROTO_TLS) {

    tls = idx_get(sockfd);
    if (!tls) {
      errno = EINVAL; // FIXME
      return -1;
    }

    switch (optname) {
      case TLS_IS_SERVER:
        if (tls->handshake_start == true) {
          fprintf(stderr, "TLS_IS_SERVER has been set.\n");
          return -1;
        }

        if (*(int *)optval == 1)
          tls->is_server = 1;
        else
          tls->is_server = 0;

        break;

      case TLS_PSK:
        if (tls->handshake_start == true) {
          fprintf(stderr, "PSK has been set.\n");
          return -1;
        }

        if (*(int *)optval == 1)
          tls->auth_method = 1;
        else
        tls->auth_method = 0;

        break;

      case TLS_PSK_USER:
        if (tls->username != NULL) {
          fprintf(stderr, "Username has been set.\n");
          return -1;
        }

        if (strlen((char *)optval) != optlen) {
          errno = EINVAL;// or?
          return -1;
        }

        tls->username = strdup(optval);

        if (tls->username == NULL) {
          fprintf(stderr, "Error in copying username, the errno is %d\n", errno);
          return -1;
        }

        break;

      case TLS_PSK_KEY:
        if (tls->key != NULL) {
          fprintf(stderr, "Key has been set.\n");
          return -1;
        }

        tls->key_size = optlen;
        tls->key = malloc(optlen);
        memcpy(tls->key, optval, optlen);

        break;
    }
    return 0;
  }

  /* We only override SO_PROTOCOL on SOL_SOCKET. */
  if (level != SOL_SOCKET || optname != SO_PROTOCOL)
    return NEXT(setsockopt)(sockfd, level, optname, optval, optlen);

  /* Confirm the correct size of the input. */
  if (optlen != sizeof(int)) {
    errno = EINVAL; // FIXME
    return -1;
  }

  const int *const protocol = optval;

  /* The caller wants to transition to TLS. */
  if (*protocol == IPPROTO_TLS) {
    /* Create the new TLS instance. */
    tls = test_tls_new(sockfd);
    if (!tls)
      return -1;

    /* If setting the TLS instance worked, we're now TLS. */
    if (idx_set(sockfd, tls, &already))
      return 0;

    if (already)
      errno = EALREADY; // FIXME

    return -1;

  /* The caller wants to transition to non-TLS. */
  } else {
    /* If deletion succeeded, then transition was successful. */
    if (idx_del(sockfd))
      return 0;

    /* If the error is that there was no entry,
     * then indicated that we are already non-TLS. */
    if (errno == ENOENT)
      errno = EALREADY; // FIXME

    return -1;
  }
}

int
socket(int domain, int type, int protocol)
{
  tls_auto_t *tls = NULL;
  int fd = -1;

  fd = NEXT(socket)(domain, type, inner_protocol(protocol));
  if (fd < 0)
    return fd;

  switch (protocol) {
  case IPPROTO_TLS:
    tls = test_tls_new(fd);
    if (!tls || !idx_set(fd, tls, NULL)) {
      close(fd);
      return -1;
    }
  }

  return fd;
}

ssize_t
write(int fd, const void *buf, size_t count)
{
  tls_auto_t *tls = NULL;

  tls = idx_get(fd);
  if (!tls)
    return NEXT(write)(fd, buf, count);

  return tls_write(tls, fd, buf, count);
}

int handshake(int sockfd)
{
  tls_auto_t *tls =NULL;

  tls = idx_get(sockfd);
  if (!tls) {
    errno = EINVAL;
    return -1;
  }

  tls->handshake_start = true;
  return tls_handshake(tls, sockfd);
}
