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
#include "locks.h"
#include "tls.h"
#include "tlssock.h"

#include <gnutls/gnutls.h>

#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

struct tls_prv {

  gnutls_session_t session;

  struct {

    union {
      struct {
        gnutls_psk_client_credentials_t psk;
      } clt;

      struct {
        gnutls_psk_server_credentials_t psk;
      } srv;
    };
  } creds;
};

static inline int
g2e(int ret)
{
  switch (ret) {
  case GNUTLS_E_SUCCESS:
    return 0;

  case GNUTLS_E_AGAIN:
    errno = EAGAIN;
    return -1;

  case GNUTLS_E_INTERRUPTED:
    errno = EINTR;
    return -1;

  case GNUTLS_E_LARGE_PACKET:
    errno = EMSGSIZE;
    return -1;

  case GNUTLS_E_INSUFFICIENT_CREDENTIALS:
    errno = EACCES; // FIXME
    return -1;

  default:
    if (!gnutls_error_is_fatal(ret))
      return ret;

    errno = EIO; // FIXME
    return -1;
  }
}

tls_prv_t *
tls_prv_new(void)
{
  tls_prv_t * tls = NULL;
  tls = calloc(1, sizeof(*tls));

  if (!tls)
  return NULL;

  return tls;
}

static void
tls_creds_clear(tls_prv_t *tls, bool client)
{
  if (tls->session)
    gnutls_credentials_clear(tls->session);

  if (client) {
    if (tls->creds.clt.psk)
      gnutls_psk_free_client_credentials(tls->creds.clt.psk);
    tls->creds.clt.psk = NULL;
  } else {
    if (tls->creds.srv.psk)
      gnutls_psk_free_server_credentials(tls->creds.srv.psk);
    tls->creds.srv.psk = NULL;
  }
}

static void
tls_clear(tls_prv_t *tls)
{
  if (!tls || !tls->session)
    return;

  tls_creds_clear(tls, gnutls_session_get_flags(tls->session) & GNUTLS_CLIENT);
  gnutls_deinit(tls->session);
  tls->session = NULL;
}

void
tls_free(tls_prv_t *tls)
{
  tls_clear(tls);

  memset(tls, 0, sizeof(*tls));
  free(tls);
}

ssize_t
tls_read(tls_t *tls, int fd, void *buf, size_t count)
{
  rwhold_auto_t *hold = rwlock_rdlock(tls->lock);
  return g2e(gnutls_record_recv(tls->prv->session, buf, count));
}

ssize_t
tls_write(tls_t *tls, int fd, const void *buf, size_t count)
{
  rwhold_auto_t *hold = rwlock_rdlock(tls->lock);
  return g2e(gnutls_record_send(tls->prv->session, buf, count));
}

int
tls_getsockopt(tls_prv_t *tls, int fd, int optname, void *optval, socklen_t *optlen)
{
  errno = ENOSYS; // TODO
  return -1;
}

static ssize_t
pull_func(gnutls_transport_ptr_t ptr, void *buf, size_t count)
{
  return NEXT(read)((intptr_t) ptr, buf, count);
}

static ssize_t
push_func(gnutls_transport_ptr_t ptr, const void *buf, size_t count)
{
  return NEXT(write)((intptr_t) ptr, buf, count);
}

static ssize_t
vec_push_func(gnutls_transport_ptr_t ptr, const giovec_t *iov, int iovcnt)
{
  return NEXT(writev)((intptr_t) ptr, iov, iovcnt);
}

static int
pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms)
{
  struct pollfd pfd = { (intptr_t) ptr, POLLIN | POLLPRI };
  int timeout = 0;

  if (ms == GNUTLS_INDEFINITE_TIMEOUT)
    timeout = -1;
  else if (ms > INT_MAX)
    timeout = INT_MAX;
  else
    timeout = ms;

  return poll(&pfd, 1, timeout);
}

static int
get_flags(int fd, bool client)
{
  int flags = client ? GNUTLS_CLIENT : GNUTLS_SERVER;
  int type = 0;
  int ret = 0;

  ret = fcntl(fd, F_GETFL);
  if (ret < 0)
    return ret;
  if (ret & O_NONBLOCK)
    flags |= GNUTLS_NONBLOCK;

  if (getsockopt_int(fd, SOL_SOCKET, SO_TYPE, &type) < 0)
    return -1;
  if (type == SOCK_DGRAM)
    flags |= GNUTLS_DATAGRAM;

  return flags;
}

static int
psk_clt(gnutls_session_t session, char **username, gnutls_datum_t *key)
{
  const tls_t *tls = gnutls_session_get_ptr(session);
  uint8_t *k = tls->key;
  char *u = tls->username;
  ssize_t l = tls->key_size;

  if (l < 0)
    return -1;

  *username = gnutls_strdup(u);
  key->data = gnutls_malloc(l);
  key->size = l;
  if (key->data)
    memcpy(key->data, k, l);

  explicit_bzero(u, strlen(u));
  explicit_bzero(k, l);
  free(u);
  free(k);

  if (*username && key->data)
    return 0;

  if (*username) {
    explicit_bzero(*username, strlen(*username));
    gnutls_free(*username);
  }

  if (key->data) {
    explicit_bzero(key->data, l);
    gnutls_free(key->data);
  }

  return -1;
}

static int
psk_srv(gnutls_session_t session, const char *username, gnutls_datum_t *key)
{
  const tls_t *tls = gnutls_session_get_ptr(session);
  uint8_t *k = tls->key;
  ssize_t l = tls->key_size;

  if (l < 0)
    return -1;

  key->data = gnutls_malloc(l);
  key->size = l;
  if (key->data)
    memcpy(key->data, k, l);

  explicit_bzero(k, l);
  free(k);

  return key->data ? 0 : -1;
}

int
tls_handshake(tls_t *tls, int fd)
{
  int ret = -1;

  if (!tls->prv->session) {
    static const char *priority = "+ECDHE-PSK:+DHE-PSK:+PSK";
    int flags = 0;

    flags = get_flags(fd, !tls->is_server);
    if (flags < 0)
      return flags;

    ret = g2e(gnutls_init(&tls->prv->session, flags));
    if (ret < 0)
      return ret;

    gnutls_transport_set_int(tls->prv->session, fd);
    gnutls_transport_set_pull_function(tls->prv->session, pull_func);
    gnutls_transport_set_push_function(tls->prv->session, push_func);
    gnutls_transport_set_vec_push_function(tls->prv->session, vec_push_func);
    gnutls_transport_set_pull_timeout_function(tls->prv->session, pull_timeout_func);
    gnutls_handshake_set_timeout(tls->prv->session, 0);

    ret = g2e(gnutls_set_default_priority_append(tls->prv->session, priority, NULL, 0));
    if (ret < 0)
      goto error;
  }

  if (!tls->is_server && tls->key) {
    ret = g2e(gnutls_psk_allocate_client_credentials(&tls->prv->creds.clt.psk));
    if (ret < 0)
      goto error;

    gnutls_psk_set_client_credentials_function(tls->prv->creds.clt.psk, psk_clt);
    ret = g2e(gnutls_credentials_set(tls->prv->session, GNUTLS_CRD_PSK,
                                     tls->prv->creds.clt.psk));
    if (ret < 0)
      goto error;
  } else if (tls->is_server && tls->key) {
    ret = g2e(gnutls_psk_allocate_server_credentials(&tls->prv->creds.srv.psk));
    if (ret < 0)
      goto error;

    gnutls_psk_set_server_credentials_function(tls->prv->creds.srv.psk, psk_srv);
    ret = g2e(gnutls_credentials_set(tls->prv->session, GNUTLS_CRD_PSK,
                                     tls->prv->creds.srv.psk));
    if (ret < 0)
      goto error;
  }

  gnutls_session_set_ptr(tls->prv->session, tls);
  ret = g2e(gnutls_handshake(tls->prv->session));
  gnutls_session_set_ptr(tls->prv->session, NULL);
  tls_creds_clear(tls->prv, !tls->is_server);
  if (ret >= 0 || errno == EAGAIN)
    return ret;

error:
  tls_clear(tls->prv);
  return ret;
}
