/*
 * This file is part of nss-myhostname.
 *
 * nss-myhostname is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * nss-myhostname is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with nss-myhostname; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <limits.h>
#include <nss.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

#define LOCALADDRESS (htonl(0x7F0002))

static enum nss_status fill_in_hostent(
    const char *hn,
    struct hostent *result,
    char *buffer,
    size_t buflen,
    int *errnop,
    int *h_errnop) {

    size_t l, idx; 
    char *r_addr, *r_name, *r_aliases, *r_addr_list;

    l = strlen(hn);
    if (buflen < l+1+sizeof(char*)+4+sizeof(char*)*2) {
        *errnop = ENOMEM;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }
    
    r_name = buffer;
    strcpy(buffer, hn);

    idx = l+1;

    *(char**) (buffer + idx) = NULL;
    r_aliases = buffer + idx;
    idx += sizeof(char*);
    
    r_addr = buffer + idx;
    *(uint32_t*) &buffer[idx] = LOCALADDRESS;
    idx += 4;

    r_addr_list = buffer + idx;
    * (char**) (buffer + idx) = r_addr;
    * (((char**) (buffer + idx)) +1)  = NULL;
    
    result->h_name = r_name;
    result->h_aliases = (char**) r_aliases;
    result->h_addrtype = AF_INET;
    result->h_length = 4;
    result->h_addr_list = (char**) r_addr_list;

    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_hostname_gethostbyname2_r(
    const char *name,
    int af,
    struct hostent * result,
    char *buffer,
    size_t buflen,
    int *errnop,
    int *h_errnop) {

    char hn[HOST_NAME_MAX+1];

    assert(errnop);
    assert(h_errnop);

    if (af == AF_UNSPEC)
        af = AF_INET;

    if (af != AF_INET) {
        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }

    if (gethostname(hn, sizeof(hn)-1) < 0) {
        *errnop = errno;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }

    hn[sizeof(hn)-1] = 0;

    if (strcasecmp(name, hn) != 0) {
        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }

    return fill_in_hostent(hn, result, buffer, buflen, errnop, h_errnop);
}

enum nss_status _nss_hostname_gethostbyname_r (
    const char *name,
    struct hostent *result,
    char *buffer,
    size_t buflen,
    int *errnop,
    int *h_errnop) {

    return _nss_hostname_gethostbyname2_r(
        name,
        AF_UNSPEC,
        result,
        buffer,
        buflen,
        errnop,
        h_errnop);
}

enum nss_status _nss_hostname_gethostbyaddr_r(
    const void* addr,
    int len,
    int af,
    struct hostent *result,
    char *buffer,
    size_t buflen,
    int *errnop,
    int *h_errnop) {

    char hn[HOST_NAME_MAX+1];

    assert(errnop);
    assert(h_errnop);

    if (af != AF_INET || len != 4 || (*(uint32_t*) addr) != LOCALADDRESS) {
        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }

    if (gethostname(hn, sizeof(hn)-1) < 0) {
        *errnop = errno;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }

    hn[sizeof(hn)-1] = 0;

    return fill_in_hostent(hn, result, buffer, buflen, errnop, h_errnop);
}
