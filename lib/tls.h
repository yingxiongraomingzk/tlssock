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

#pragma once

#include "locks.h"
#include "tlssock.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <stdint.h>

#define tls_auto_t tls_t __attribute__((cleanup(tls_cleanup)))

typedef struct tls_prv tls_prv_t;

typedef struct {
    bool handshake_start;
    int is_server;
    uint64_t auth_method;
    char *username;
    uint8_t *key;
    size_t key_size;
    rwlock_t *lock;
    size_t ref;

    tls_prv_t *prv;
} tls_t;

tls_t *
tls_new(void);

tls_prv_t *
tls_prv_new(void);

void
tls_cleanup(tls_t **tls);

void
tls_t_cleanup(tls_t *tls);

void
tls_free(tls_prv_t *tls);

tls_t *
tls_incref(tls_t *tls);

tls_t *
tls_decref(tls_t *tls);

ssize_t
tls_read(tls_t *tls, int fd, void *buf, size_t count);

ssize_t
tls_write(tls_t *tls, int fd, const void *buf, size_t count);

int
tls_getsockopt(tls_prv_t *tls, int fd, int optname,
               void *optval, socklen_t *optlen);

int
tls_handshake(tls_t *tls, int fd);
