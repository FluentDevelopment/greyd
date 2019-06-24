/*
 * Copyright (c) 2014, 2015 Mikey Austin <mikey@greyd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * @file   npf.c
 * @brief  Pluggable NPF firewall interface.
 * @author Mikey Austin
 * @date   2014
 */

#include <config.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <net/npf.h>
#include <npf.h>
#include <stdbool.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "../src/failures.h"
#include "../src/firewall.h"
#include "../src/config_section.h"
#include "../src/list.h"
#include "../src/utils.h"
#include "../src/constants.h"
#include "../src/ip.h"

#define NPFDEV_PATH "/dev/npf"
#define NPFLOG_IF   "npflog0"
#define TABLE_ID    5
#define NPF_ACTION_PASS  0 /* PF_PASS */
#define NPF_ACTION_DROP  1 /* PF_DROP */
#define NPF_DIR_INOUT    0 /* PF_INOUT */
#define NPF_DIR_IN       1
#define NPF_DIR_OUT      2

#define MIN_PFLOG_HDRLEN 45
#define PCAPSNAP 512
#define PCAPTIMO 500  /* ms */
#define PCAPOPTZ 1    /* optimize filter */
#define PCAPFSIZ 512  /* pcap filter string size */

#define satosin(sa)  ((struct sockaddr_in *)(sa))
#define satosin6(sa) ((struct sockaddr_in6 *)(sa))

/*  name argument of npf_table_create was added in NetBSD 699002600 */
#if defined(__NetBSD__) && __NetBSD_Version__ <= 699002600
#   define npf_table_create(name, id, type) npf_table_create(id, type)
#endif

/* errinfo argument of npf_config_submit was added in NetBSD 799005200 */
#if defined(__NetBSD__) && __NetBSD_Version__ <= 799005200
#   define npf_config_submit(ncf, fd, errinfo) npf_config_submit(ncf, fd)
#endif

/* Drawn from NetBSD's sys/net/npf/if_npflog.h */

#define NPFLOG_RULESET_NAME_SIZE        16

/*
 * For now, we use a header compatible with pflog.
 * This will be improved in the future.
 */
struct npfloghdr {
        uint8_t         length;
        sa_family_t     af;
        uint8_t         action;
        uint8_t         reason;
        char            ifname[IFNAMSIZ];
        char            ruleset[NPFLOG_RULESET_NAME_SIZE];
        uint32_t        rulenr;
        uint32_t        subrulenr;
        uint32_t        uid;
        uint32_t        pid;
        uint32_t        rule_uid;
        uint32_t        rule_pid;
        uint8_t         dir;
        uint8_t         pad[3];
};

/* End NetBSD sys/net/npf/if_npflog.h snippet */

struct fw_handle {
    int npfdev;
    pcap_t *pcap_handle;
    List_T entries;
};

/**
 * Setup a pipe for communication with the control command.
 */
static void destroy_log_entry(void *);
static void packet_received(u_char *, const struct pcap_pkthdr *, const u_char *);
static int npf_natlookup(int, struct sockaddr *, struct sockaddr *, struct sockaddr *);

int
Mod_fw_open(FW_handle_T handle)
{
    struct fw_handle *fwh = NULL;
    char *npfdev_path;
    int npfdev;

    npfdev_path = Config_get_str(handle->config, "npfdev_path",
                                "firewall", NPFDEV_PATH);

    if((fwh = malloc(sizeof(*fwh))) == NULL)
        return -1;

    npfdev = open(npfdev_path, O_RDONLY);
    if(npfdev < 1) {
        i_warning("could not open %s: %s", npfdev_path,
                  strerror(errno));
        return -1;
    }

    i_info("npf device %s successfully opened", npfdev_path);

    fwh->npfdev = npfdev;
    fwh->pcap_handle = NULL;
    handle->fwh = fwh;

    return 0;
}

void
Mod_fw_close(FW_handle_T handle)
{
    struct fw_handle *fwh = handle->fwh;

    if(fwh) {
        close(fwh->npfdev);
        free(fwh);
    }
    handle->fwh = NULL;
}

int
Mod_fw_replace(FW_handle_T handle, const char *set_name, List_T cidrs, short af)
{
    struct fw_handle *fwh = handle->fwh;
    int fd, nadded = 0;
    char *cidr, *fd_path = NULL;
    char *table = (char *) set_name;
    void *handler;
    struct List_entry *entry;
    struct IP_addr m, n;
    int ret;
    uint8_t maskbits;
    char parsed[INET6_ADDRSTRLEN];
    npf_ioctl_table_t nct;

    if(List_size(cidrs) == 0)
        return 0;

    memset(&nct, 0, sizeof(npf_ioctl_table_t));
    nct.nct_name = table;

    i_info("adding entries to npf table %s", table);

    /* This should somehow be atomic. */
    LIST_EACH(cidrs, entry) {
        if((cidr = List_entry_value(entry)) != NULL
           && IP_str_to_addr_mask(cidr, &n, &m, (sa_family_t*)&af) != -1)
        {
            ret = sscanf(cidr, "%39[^/]/%u", parsed, &maskbits);
            if(ret != 2 || maskbits == 0 || maskbits > IP_MAX_MASKBITS)
                continue;

            /*i_info("adding address %s to npf table %s", cidr, table);*/

            size_t alen;
            switch (af) {
            case AF_INET:
                alen = sizeof(struct in_addr);
                break;
            case AF_INET6:
                alen = sizeof(struct in6_addr);
                break;
            default:
                i_warning("unsupported address family %d", (int)af);
                continue;
            }

            nct.nct_data.ent.alen = alen;
            memcpy(&nct.nct_data.ent.addr, &n, alen);
            nct.nct_data.ent.mask = NPF_NO_NETMASK; /*maskbits;*/

            nct.nct_cmd = NPF_CMD_TABLE_LOOKUP;
            if (ioctl(fwh->npfdev, IOC_NPF_TABLE, &nct) != -1) {
                i_debug("record already exists for %s; skipping", cidr);
                continue;
            }
            if (errno != ENOENT) {
                i_warning("record already exists for %s; skipping", cidr);
                continue;
            }

            nct.nct_cmd = NPF_CMD_TABLE_ADD;
            if (ioctl(fwh->npfdev, IOC_NPF_TABLE, &nct) != -1) {
                errno = 0;
            }
            switch (errno) {
            case EEXIST:
                i_warning("entry already exists or is conflicting: %s", cidr);
                break;
            case ENOENT:
                i_warning("no matching entry was not found");
            case EINVAL:
                i_warning("invalid address or mask %s or table ID %s", cidr, table);
                break;
            default:
                if (errno) {
                    i_warning("ioctl(IOC_NPF_TABLE) returned error %s", strerror(errno));
                } else {
                    nadded++;
                }
            }
        }
    }

    i_info("submitting %d addresses to npf table %s", nadded, table);

    return nadded;

err:
    return -1;
}

int
Mod_fw_lookup_orig_dst(FW_handle_T handle, struct sockaddr *src,
                       struct sockaddr *proxy, struct sockaddr *orig_dst)
{
    struct fw_handle *fwh = handle->fwh;

    return npf_natlookup(fwh->npfdev, src, proxy, orig_dst);
}

void
Mod_fw_start_log_capture(FW_handle_T handle)
{
    struct fw_handle *fwh = handle->fwh;
    struct bpf_program  bpfp;
    char *npflog_if, *net_if;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter[PCAPFSIZ] = "ip and port 25 and action pass "
        "and tcp[13]&0x12=0x2";

    npflog_if = Config_get_str(handle->config, "npflog_if", "firewall",
                               NPFLOG_IF);
    net_if = Config_get_str(handle->config, "net_if", "firewall",
                            NULL);

    i_info("starting npflog %s capture for interface %s", npflog_if, net_if);

    if ((fwh->pcap_handle = pcap_open_live(npflog_if, PCAPSNAP, 1, PCAPTIMO,
                                           errbuf)) == NULL)
    {
        i_critical("failed to initialize failed: %s", errbuf);
    }

    if(pcap_datalink(fwh->pcap_handle) != DLT_PFLOG) {
        pcap_close(fwh->pcap_handle);
        fwh->pcap_handle = NULL;
        i_critical("invalid datalink type");
    }

    if(net_if != NULL) {
        sstrncat(filter, " and on ", PCAPFSIZ);
        sstrncat(filter, net_if, PCAPFSIZ);
    }

    if((pcap_compile(fwh->pcap_handle, &bpfp, filter, PCAPOPTZ, 0) == -1)
       || (pcap_setfilter(fwh->pcap_handle, &bpfp) == -1))
    {
        i_critical("%s", pcap_geterr(fwh->pcap_handle));
    }

    pcap_freecode(&bpfp);

    fwh->entries = List_create(destroy_log_entry);
}

void
Mod_fw_end_log_capture(FW_handle_T handle)
{
    struct fw_handle *fwh = handle->fwh;

    List_destroy(&fwh->entries);
    pcap_close(fwh->pcap_handle);
}

List_T
Mod_fw_capture_log(FW_handle_T handle)
{
    struct fw_handle *fwh = handle->fwh;
    pcap_handler ph = packet_received;

    List_remove_all(fwh->entries);
    pcap_dispatch(fwh->pcap_handle, 0, ph, (u_char *) handle);

    return fwh->entries;
}

static void
packet_received(u_char *args, const struct pcap_pkthdr *h, const u_char *sp)
{
    FW_handle_T handle = (FW_handle_T) args;
    struct fw_handle *fwh = handle->fwh;
    sa_family_t af;
    u_int8_t hdrlen;
    u_int32_t caplen = h->caplen;
    const struct ip *ip = NULL;
    const struct npfloghdr *hdr;
    char addr[INET6_ADDRSTRLEN] = { '\0' };
    int track_outbound;

    i_info("got npf packet");

    track_outbound = Config_get_int(handle->config, "track_outbound",
                                    "firewall", TRACK_OUTBOUND);

    hdr = (const struct npfloghdr *)sp;
    if(hdr->length < MIN_PFLOG_HDRLEN) {
        i_warning("invalid npflog header length (%u/%u). "
            "packet dropped.", hdr->length, MIN_PFLOG_HDRLEN);
        return;
    }
    hdrlen = BPF_WORDALIGN(hdr->length);

    if(caplen < hdrlen) {
        i_warning("npflog header larger than caplen (%u/%u). "
            "packet dropped.", hdrlen, caplen);
        return;
    }

    /* We're interested in passed packets */
    if(hdr->action != NPF_ACTION_PASS)
        return;

    af = hdr->af;
    if(af == AF_INET) {
        ip = (const struct ip *) (sp + hdrlen);
        if(hdr->dir == NPF_DIR_IN) {
            inet_ntop(af, &ip->ip_src, addr,
                      sizeof(addr));
        }
        else if(hdr->dir == NPF_DIR_OUT && track_outbound) {
            inet_ntop(af, &ip->ip_dst, addr,
                      sizeof(addr));
        }
    }

    if(addr[0] != '\0') {
        i_debug("packet received: direction = %s, addr = %s",
                (hdr->dir == NPF_DIR_IN ? "in" : "out"), addr);
        List_insert_after(fwh->entries, strdup(addr));
    }
}

static int
npf_natlookup(int npfdev, struct sockaddr *src, struct sockaddr *dst,
              struct sockaddr *orig_dst)
{
    npf_addr_t *addr[2];
    in_port_t port[2];
    int dev, af;
    size_t alen;

    char srcp[INET6_ADDRSTRLEN], dstp[INET6_ADDRSTRLEN];

    switch (af = src->sa_family) {
    case AF_INET:
        alen = sizeof(*satosin(src));

        inet_ntop(af, &satosin(src)->sin_addr, srcp, sizeof(srcp));
        inet_ntop(af, &satosin(dst)->sin_addr, dstp, sizeof(dstp));

        /* copy the source into nat_addr so it is writable */
        memcpy(orig_dst, src, sizeof(*satosin(src)));

        addr[0] = (void*)&satosin(orig_dst)->sin_addr;
        addr[1] = (void*)&satosin(dst)->sin_addr;
        port[0] = satosin(src)->sin_port;
        port[1] = satosin(dst)->sin_port;
        break;
    case AF_INET6:
        alen = sizeof(*satosin6(src));
        /* copy the source into nat_addr so it is writable */
        memcpy(orig_dst, src, sizeof(*satosin6(src)));
        inet_ntop(af, &satosin6(src)->sin6_addr, srcp, sizeof(srcp));
        inet_ntop(af, &satosin6(dst)->sin6_addr, dstp, sizeof(dstp));
        addr[0] = (void*)&satosin6(orig_dst)->sin6_addr;
        addr[1] = (void*)&satosin6(dst)->sin6_addr;
        port[0] = satosin6(src)->sin6_port;
        port[1] = satosin6(dst)->sin6_port;
        break;
    default:
        errno = EAFNOSUPPORT;
        i_warning("NAT lookup for %d: %m" , af, strerror(errno));
        return -1;
    }

    i_debug("NPF NAT lookup entry for connection from %s:%u to %s:%u", srcp, ntohs(port[0]), dstp, ntohs(port[1]));

    if (npf_nat_lookup(npfdev, af, addr, port, IPPROTO_TCP, PFIL_IN) == -1) {
        i_warning("NAT lookup failure: %m", strerror(errno));
        return -1;
    }

    // npf_nat_lookup writes the original address into addrs[0]
    /*
     * The originating address is already set into nat_addr so fill
     * in the rest, family, port (ident), len....
     */
    // switch (af) {
    // case AF_INET:
    // 	satosin(orig_dst)->sin_len = sizeof(struct sockaddr_in);
    // 	satosin(orig_dst)->sin_family = AF_INET;
    // 	break;
    // case AF_INET6:
    // 	satosin6(orig_dst)->sin6_len = sizeof(struct sockaddr_in6);
    // 	satosin6(orig_dst)->sin6_family = AF_INET6;
    // 	break;
    // }

    switch (af) {
    case AF_INET:
        inet_ntop(af, &satosin(orig_dst)->sin_addr, srcp, sizeof(srcp));
        inet_ntop(af, &satosin(dst)->sin_addr, dstp, sizeof(dstp));
        satosin(orig_dst)->sin_port = port[0];
        break;
    case AF_INET6:
        inet_ntop(af, &satosin6(orig_dst)->sin6_addr, srcp, sizeof(srcp));
        inet_ntop(af, &satosin6(dst)->sin6_addr, dstp, sizeof(dstp));
        satosin6(orig_dst)->sin6_port = port[0];
        break;
    }

    i_debug("NPF NAT lookup got NAT translation %s:%u -> %s:%u", srcp, ntohs(port[0]), dstp, ntohs(port[1]));

    return 0;
}

static void
destroy_log_entry(void *entry)
{
    if(entry != NULL)
        free(entry);
}
