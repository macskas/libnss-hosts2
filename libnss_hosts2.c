#include <nss.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>

#define _public_ __attribute__ ((visibility("default")))
#define _hidden_ __attribute__ ((visibility("hidden")))
#define ALIGN(a) (((a+sizeof(void*)-1)/sizeof(void*))*sizeof(void*))
#define HOSTS_LINE_MAXLEN 4096
#define MSTR(x) #x

#ifndef FILE_HOSTS
#define FILE_HOSTS "/etc/hosts2"
#endif

#define HOSTNAME_BUFFER_SIZE 254

#define LOOKUP_METHOD_HOSTNAME 1
#define LOOKUP_METHOD_IP 2

#define PROTO_ADDRESS_SIZE(a) (a == PF_INET6 ? 16 : 4)

int search_hosts(char lookup_method, const char *input_filter, size_t input_len, int af_filter, char *result_buffer, size_t result_buffer_length, unsigned short *result_af) _hidden_;

int search_hosts(char lookup_method, const char *input_filter, size_t input_len, int af_filter, char *result_buffer, size_t result_buffer_length, unsigned short *result_af) {
    char line[HOSTS_LINE_MAXLEN];
    char *found_ip = NULL;
    char ip_match_helper[16];
    size_t ip_length = 0;
    unsigned short ip_af = PF_UNSPEC;
    char result_ok = 0;

    char *found_strsep = NULL;
    size_t found_length = 0;
    char *line_strsep = NULL;
    size_t idx_strsep = 0;


    size_t llen = 0, l_i = 0;
    char *line_start_pos = NULL;

    FILE *fh = fopen(FILE_HOSTS, "r");
    if (fh == NULL) {
        return 0;
    }

    size_t totrim = 0;

    while (fgets(line, 4096, fh) != NULL) {
        if (result_ok)
            break;

        llen = strlen(line);
        if (llen < 5)
            continue;

        line_start_pos = line;

        char *found_comment = strchr(line_start_pos, '#');
        if (found_comment) {
            found_comment[0] = '\0';
            llen = found_comment - line_start_pos;
            if (llen < 5)
                continue;
        }

        totrim = strspn(line_start_pos, "\t\n\v\f\r ");
        if (totrim > 0) {
            if (totrim == llen) {
                continue;
            } else {
                line_start_pos = line_start_pos + totrim;
                llen = llen - totrim;
                if (llen < 5)
                    continue;
            }
        }

        // rtrim
        for (l_i = llen-1; l_i >= 0; l_i--) {
            if (!isgraph(line_start_pos[l_i])) {
                line_start_pos[l_i] = '\0';
                llen--;
            } else {
                break;
            }
        }

        if (llen < 5)
            continue;

        found_ip = NULL;
        ip_length = 0;
        ip_af = PF_UNSPEC;
        idx_strsep = 0;
        line_strsep = line_start_pos;
        while ((found_strsep = strsep(&line_strsep, "\t ")) != NULL) {
            found_length = line_strsep == NULL ? line_start_pos+llen-found_strsep : line_strsep-found_strsep-1;

            if (lookup_method == LOOKUP_METHOD_HOSTNAME) {
                if (idx_strsep == 0) {
                    found_ip = found_strsep;
                    ip_length = found_length;
                    if (ip_length < 3 || ip_length > 45)
                        break;
                } else {
                    if (found_length == 0 || input_len != found_length)
                        continue;
                    if (strcasecmp(found_strsep, input_filter) != 0)
                        continue;
                    if (strchr(found_ip, '.') && ip_length >= 5 && ip_length <= 15) {
                        ip_af = PF_INET;
                    } else if (strchr(found_ip, ':') && ip_length >= 3 && ip_length <= 45) {
                        ip_af = PF_INET6;
                    } else {
                        break;
                    }
                    if (af_filter && af_filter != ip_af) {
                        // filter by requested AF
                        break;
                    }

                    if (inet_pton(ip_af, found_ip, result_buffer) == 1) {
                        if (result_af) {
                            *result_af = ip_af;
                        }
                        result_ok = 1;
                        break;
                    } else {
                        // invalid ip
                        break;
                    }
                }
                idx_strsep++;
            } else {
                if (idx_strsep == 0) {
                    found_ip = found_strsep;
                    ip_length = found_length;
                    if (strchr(found_ip, '.') && ip_length >= 5 && ip_length <= 15) {
                        ip_af = PF_INET;
                    } else if (strchr(found_ip, ':') && ip_length >= 3 && ip_length <= 45) {
                        ip_af = PF_INET6;
                    } else {
                        break;
                    }
                    if (af_filter && af_filter != ip_af) {
                        // filter by requested AF
                        break;
                    }

                    memset(ip_match_helper, 0, 16);
                    if (inet_pton(ip_af, found_ip, ip_match_helper) != 1)
                        break;

                    if (memcmp(input_filter, ip_match_helper, input_len) != 0)
                        break;
                } else {
                    if (found_length == 0)
                        continue;

                    char invalid_host = 0;
                    for (size_t fli = 0; fli<found_length; fli++) {
                        if (!isalnum(found_strsep[fli]) && found_strsep[fli] != '-' && found_strsep[fli] != '.') {
                            invalid_host = 1;
                        }
                    }
                    if (invalid_host)
                        continue;

                    if (found_length < result_buffer_length) {
                        strncpy(result_buffer, found_strsep, result_buffer_length);
                        result_ok = 1;
                    }
                    break;
                }
                idx_strsep++;
            }
        }
    }
    fclose(fh);

    if (result_ok) {
        return 1;
    }
    return 0;
}

enum nss_status _nss_hosts2_gethostbyname4_r(
        const char *name,
        struct gaih_addrtuple **pat,
        char *buffer, size_t buflen,
        int *errnop, int *h_errnop,
        int32_t *ttlp) _public_;

enum nss_status _nss_hosts2_gethostbyname3_r(
        const char *name,
        int af,
        struct hostent *host,
        char *buffer, size_t buflen,
        int *errnop, int *h_errnop,
        int32_t *ttlp,
        char **canonp) _public_;

enum nss_status _nss_hosts2_gethostbyname2_r(
        const char *name,
        int af,
        struct hostent *host,
        char *buffer, size_t buflen,
        int *errnop, int *h_errnop) _public_;

enum nss_status _nss_hosts2_gethostbyname_r(
        const char *name,
        struct hostent *host,
        char *buffer, size_t buflen,
        int *errnop, int *h_errnop) _public_;

enum nss_status _nss_hosts2_gethostbyaddr2_r(
        const void* addr, socklen_t len,
        int af,
        struct hostent *host,
        char *buffer, size_t buflen,
        int *errnop, int *h_errnop,
        int32_t *ttlp) _public_;

enum nss_status _nss_hosts2_gethostbyaddr_r(
        const void* addr, socklen_t len,
        int af,
        struct hostent *host,
        char *buffer, size_t buflen,
        int *errnop, int *h_errnop) _public_;



enum nss_status _nss_hosts2_gethostbyname4_r(
        const char *name,
        struct gaih_addrtuple **pat,
        char *buffer, size_t buflen,
        int *errnop, int *h_errnop,
        int32_t *ttlp) {

    char result_buffer[16];
    memset(result_buffer, 0, 16);
    unsigned short af = 0;
    size_t hlen = strlen(name);
    int rc = 0;

    if (hlen) {
        rc = search_hosts(LOOKUP_METHOD_HOSTNAME, name, hlen, 0, result_buffer, 16, &af);
    }

    if (rc == 0) {
        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }

    struct gaih_addrtuple *r_tuple, *r_tuple_prev = NULL;
    char *r_name;

    size_t idx = 0;
    size_t n_addresses = 1;
    size_t l = strlen(name);
    size_t ms = ALIGN(l+1) + ALIGN(sizeof(struct gaih_addrtuple)) * (n_addresses > 0 ? n_addresses : 1);
    if (buflen < ms) {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    }

    r_name = buffer;
    memcpy(r_name, name, l+1);
    idx = ALIGN(l+1);
    r_tuple = (struct gaih_addrtuple*) (buffer + idx);
    r_tuple->next = r_tuple_prev;
    r_tuple->name = r_name;
    r_tuple->family = af;
    memcpy(r_tuple->addr, result_buffer, 16);
    r_tuple->scopeid = 0;
    idx += ALIGN(sizeof(struct gaih_addrtuple));
    r_tuple_prev = r_tuple;
    if (*pat)
        **pat = *r_tuple_prev;
    else
        *pat = r_tuple_prev;
    if (ttlp)
        *ttlp = 0;

    *h_errnop = NETDB_SUCCESS;
    h_errno = 0;

    //printf("gethostbyname4_r: %s\n", name);
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_hosts2_gethostbyname3_r(
        const char *name,
        int af,
        struct hostent *host,
        char *buffer, size_t buflen,
        int *errnop, int *h_errnop,
        int32_t *ttlp,
        char **canonp) {

    unsigned short af_result;
    char result_buffer[16];
    int rc;
    size_t hlen;

    if (af == PF_UNSPEC)
        af = PF_INET;

    if (af != PF_INET && af != PF_INET6) {
        *errnop = EAFNOSUPPORT;
        *h_errnop = NO_DATA;
        return NSS_STATUS_UNAVAIL;
    }

    af_result = 0;
    memset(result_buffer, 0, 16);

    rc = 0;
    hlen = strlen(name);

    if (hlen) {
        rc = search_hosts(LOOKUP_METHOD_HOSTNAME, name, hlen, af, result_buffer, 16, &af_result);
    }
    if (rc != 1) {
        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }

    char *r_name, *r_aliases, *r_addr, *r_addr_list;
    size_t alen, l, idx, ms;

    alen = PROTO_ADDRESS_SIZE(af_result);
    l = strlen(name);
    idx = 0;
    ms = ALIGN(l+1) + sizeof(char*) + ALIGN(alen) + 2*sizeof(char*);

    if (buflen < ms) {
        *errnop = ENOMEM;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }

    r_name = buffer;
    memcpy(r_name, name, l+1);
    idx = ALIGN(l+1);

    r_aliases = buffer + idx;
    *(char**) r_aliases = NULL;
    idx += sizeof(char*);

    r_addr = buffer + idx;
    memset(r_addr, 0, alen);
    memcpy(r_addr, result_buffer, alen);
    idx += ALIGN(alen);

    r_addr_list = buffer + idx;
    ((char**) r_addr_list)[0] = r_addr;
    ((char**) r_addr_list)[1] = NULL;
    idx += 2*sizeof(char*);

    host->h_name = r_name;
    host->h_aliases = (char**)r_aliases;
    host->h_addrtype = af_result;
    host->h_length = alen;
    host->h_addr_list = (char**)r_addr_list;

    if (ttlp)
        *ttlp = 0;

    if (canonp)
        *canonp = r_name;

    *h_errnop = NETDB_SUCCESS;
    h_errno = 0;
    return NSS_STATUS_SUCCESS;
    //printf("gethostbyname3_r: %s, %d\n", name, af);
}

enum nss_status _nss_hosts2_gethostbyname2_r(
        const char *name,
        int af,
        struct hostent *host,
        char *buffer, size_t buflen,
        int *errnop, int *h_errnop) {

    return _nss_hosts2_gethostbyname3_r(
            name,
            af,
            host,
            buffer, buflen,
            errnop, h_errnop,
            NULL,
            NULL);
}

enum nss_status _nss_hosts2_gethostbyname_r(
        const char *name,
        struct hostent *host,
        char *buffer, size_t buflen,
        int *errnop, int *h_errnop) {

    return _nss_hosts2_gethostbyname3_r(
            name,
            AF_UNSPEC,
            host,
            buffer, buflen,
            errnop, h_errnop,
            NULL,
            NULL);}


enum nss_status _nss_hosts2_gethostbyaddr2_r(
        const void* addr, socklen_t len,
        int af,
        struct hostent *host,
        char *buffer, size_t buflen,
        int *errnop, int *h_errnop,
        int32_t *ttlp) {

    if (len != PROTO_ADDRESS_SIZE(af)) {
        *errnop = EINVAL;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }

    if (af != PF_INET && af != PF_INET6) {
        *errnop = EAFNOSUPPORT;
        *h_errnop = NO_DATA;
        return NSS_STATUS_UNAVAIL;
    }

    char name[HOSTNAME_BUFFER_SIZE];
    memset(name, 0, HOSTNAME_BUFFER_SIZE);
    unsigned short af_result = 0;

    if (search_hosts(LOOKUP_METHOD_IP, addr, len, af, name, HOSTNAME_BUFFER_SIZE, &af_result) != 1) {
        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }

    char *r_name, *r_aliases, *r_addr, *r_addr_list;
    size_t alen, l, idx, ms;
    alen = len;

    l = strlen(name);
    idx = 0;
    ms = ALIGN(l+1) + sizeof(char*) + ALIGN(alen) + 2*sizeof(char*);

    if (buflen < ms) {
        *errnop = ENOMEM;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }

    r_name = buffer;
    memcpy(r_name, name, l+1);
    idx = ALIGN(l+1);

    r_aliases = buffer + idx;
    *(char**) r_aliases = NULL;
    idx += sizeof(char*);

    r_addr = buffer + idx;
    memset(r_addr, 0, len);
    memcpy(r_addr, addr, len);
    idx += ALIGN(len);

    r_addr_list = buffer + idx;
    ((char**) r_addr_list)[0] = r_addr;
    ((char**) r_addr_list)[1] = NULL;
    idx += 2*sizeof(char*);

    host->h_name = r_name;
    host->h_aliases = (char**)r_aliases;
    host->h_addrtype = af;
    host->h_length = alen;
    host->h_addr_list = (char**)r_addr_list;

    if (ttlp)
        *ttlp = 0;

    *h_errnop = NETDB_SUCCESS;
    h_errno = 0;
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_hosts2_gethostbyaddr_r(
        const void* addr, socklen_t len,
        int af,
        struct hostent *host,
        char *buffer, size_t buflen,
        int *errnop, int *h_errnop) {

    return _nss_hosts2_gethostbyaddr2_r(
            addr, len,
            af,
            host,
            buffer, buflen,
            errnop, h_errnop,
            NULL);
}
