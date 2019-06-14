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

#include <string.h>

tls_t *
tls_new(void)
{
  tls_t *tls = NULL;

  tls = calloc(1, sizeof(*tls));

  if (!tls)
    return NULL;

  tls->lock = rwlock_init();
  if (!tls->lock) {
    free(tls);
    return NULL;
  }

  tls->ref = 1;
  tls->prv = tls_prv_new();

  if (!tls->prv)
    return NULL;

  return tls;
}

tls_t *
tls_incref(tls_t *tls)
{
  if (!tls)
    return NULL;
  
  {
    rwhold_auto_t *hold = rwlock_wrlock(tls->lock);
    if (!hold)
      return NULL;

    tls->ref++;
  }

  return tls;
}

tls_t *
tls_decref(tls_t *tls)
{
  if (!tls)
    return NULL;

  {
    rwhold_auto_t *hold = rwlock_wrlock(tls->lock);
    if (!hold)
      return NULL;

    if (tls->ref-- > 1)
      return tls;

    tls_free(tls->prv);
    tls_t_cleanup(tls);
    return NULL;
  }

}

void
tls_cleanup(tls_t **tls)
{
  if (tls)
    tls_decref(*tls);
}

void
tls_t_cleanup(tls_t *tls)
{

  if (tls) {
    explicit_bzero(tls->username, strlen(tls->username));
    free(tls->username);
    explicit_bzero(tls->key, tls->key_size);
    free(tls->key);
    rwlock_free(tls->lock);
    memset(tls, 0, sizeof(*tls));
    free(tls);
  }

}
