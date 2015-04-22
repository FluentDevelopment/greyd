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
 * @file   blacklist.c
 * @brief  Implements blacklist interface and structures.
 * @author Mikey Austin
 * @date   2014
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trie.h"
#include "utils.h"
#include "failures.h"
#include "blacklist.h"

static int cmp_ipv4_entry(const void *a, const void *b);
static void cidr_destroy(void *cidr);
static void grow_entries(Blacklist_T list);
static int triecmp(const void *, int, const void *, int);

extern Blacklist_T
Blacklist_create(const char *name, const char *message, int flags)
{
    int len;
    Blacklist_T blacklist;

    if((blacklist = calloc(sizeof(*blacklist), 1)) == NULL) {
        i_critical("Could not create blacklist");
    }
    blacklist->count = 0;

    len = strlen(name) + 1;
    if((blacklist->name = malloc(len)) == NULL) {
        i_critical("could not malloc blacklist name");
    }
    sstrncpy(blacklist->name, name, len);

    len = strlen(message) + 1;
    if((blacklist->message = malloc(len)) == NULL) {
        i_critical("could not malloc blacklist message");
    }
    sstrncpy(blacklist->message, message, len);

    if(flags == BL_STORAGE_LIST) {
        blacklist->entries = calloc(BLACKLIST_INIT_SIZE,
                                    sizeof(struct Blacklist_entry));
        if(blacklist->entries == NULL) {
            i_critical("Could not create blacklist entries");
        }
        blacklist->size = BLACKLIST_INIT_SIZE;
        blacklist->type = BL_STORAGE_LIST;
    }
    else if(flags == BL_STORAGE_TRIE) {
        blacklist->type = BL_STORAGE_TRIE;
        blacklist->trie = Trie_create(NULL, 0, triecmp);
    }

    return blacklist;
}

extern void
Blacklist_destroy(Blacklist_T *list)
{
    if(list == NULL || *list == NULL) {
        return;
    }

    if((*list)->entries) {
        free((*list)->entries);
        (*list)->entries = NULL;
    }

    if((*list)->trie) {
        Trie_destroy((*list)->trie);
        (*list)->trie = NULL;
    }

    if((*list)->name) {
        free((*list)->name);
        (*list)->name = NULL;
    }

    if((*list)->message) {
        free((*list)->message);
        (*list)->message = NULL;
    }

    free(*list);
    *list = NULL;
}

extern int
Blacklist_match(Blacklist_T list, struct IP_addr *source, sa_family_t af)
{
    int i;
    struct IP_addr *a, *m;
    struct Blacklist_trie_entry entry;

    if(list->type == BL_STORAGE_TRIE) {
        entry.address = *source;
        entry.mask_bits = (af == AF_INET ? 32 : 128);
        return Trie_contains(list->trie, (unsigned char *) &entry,
                             sizeof(entry));
    }

    for(i = 0; i < list->count; i++) {
        a = &(list->entries[i].address);
        m = &(list->entries[i].mask);

        if(IP_match_addr(a, m, source, af) > 0) {
            return 1;
        }
    }

    return 0;
}

extern int
Blacklist_add(Blacklist_T list, const char *address)
{
    struct IP_addr n, m;
    struct Blacklist_trie_entry entry;
    int i, ret;
    unsigned int maskbits;

    ret = IP_str_to_addr_mask(address, &n, &m, &maskbits);

    if(list->type == BL_STORAGE_TRIE) {
        list->count++;
        entry.address = n;
        entry.mask_bits = maskbits;
        Trie_insert(list->trie, (unsigned char *) &entry,
                    sizeof(entry));
    }
    else {
        grow_entries(list);
        i = list->count++;
        list->entries[i].address = n;
        list->entries[i].mask = m;
    }

    return ret;
}

extern void
Blacklist_add_range(Blacklist_T list, u_int32_t start, u_int32_t end, int type)
{
    int i;

    /*
     * If the start address is greater than the end address, ignore entry.
     */
    if(start > end)
        return;

    grow_entries(list);

    if(list->entries) {
        /* Reserve room for the pair. */
        i = list->count;
        list->count += 2;

        list->entries[i].address.v4.s_addr = start;
        list->entries[i + 1].address.v4.s_addr = end;

        if(type == BL_TYPE_WHITE) {
            list->entries[i].black = 0;
            list->entries[i].white = 1;
            list->entries[i + 1].black = 0;
            list->entries[i + 1].white = -1;
        }
        else {
            list->entries[i].black = 1;
            list->entries[i].white = 0;
            list->entries[i + 1].black = -1;
            list->entries[i + 1].white = 0;
        }
    }
}

extern List_T
Blacklist_collapse(Blacklist_T blacklist)
{
    int i, bs = 0, ws = 0, state = 0, laststate;
    u_int32_t addr, bstart = 0;
    List_T cidrs;

    if(blacklist->count == 0)
        return NULL;

    qsort(blacklist->entries, blacklist->count, sizeof(struct Blacklist_entry),
          cmp_ipv4_entry);
    cidrs = List_create(cidr_destroy);

    for(i = 0; i < blacklist->count; ) {
        laststate = state;
        addr = blacklist->entries[i].address.v4.s_addr;

        do {
            bs += blacklist->entries[i].black;
            ws += blacklist->entries[i].white;
            i++;
        } while(blacklist->entries[i].address.v4.s_addr == addr);

        if(state == 1 && bs == 0)
            state = 0;
        else if(state == 0 && bs > 0)
            state = 1;

        if(ws > 0)
            state = 0;

        if(laststate == 0 && state == 1) {
            /*
             * This state transition marks the start of a blacklist region.
             */
            bstart = addr;
        }

        if(laststate == 1 && state == 0) {
            /*
             * We are at the end of a blacklist region, convert the range
             * into CIDR format.
             */
            IP_range_to_cidr_list(cidrs, bstart, (addr - 1));
        }
    }

    return cidrs;
}

static int
triecmp(const void *a, int alen, const void *b, int blen)
{
    const struct Blacklist_trie_entry *entry1 = a, *entry2 = b;
    struct IP_addr m;
    unsigned int bits = entry1->mask_bits;
    int word, i;

    /* Construct the mask. */
    if(bits <= 32)
        word = 0;
    else if(bits > 32 && bits <= 2 * 32)
        word = 1;
    if(bits > 2 * 32 && bits <= 3 * 32)
        word = 2;
    else
        word = 3;

    for(i = 0; i <= word; i++)
        m.addr32[i] = 0xFFFFFFFF;

    for(i = bits % 32; i > 0; i--)
        m.addr32[word] << 1;

    /* Mask out both addresses and compare. */
    for(i = 0; i <= word; i++) {
        if((entry1->address.addr32[i] & m.addr32[i])
           != (entry2->address.addr32[i] & m.addr32[i]))
        {
            return 0;
        }
    }

    return 1;
}

static void
grow_entries(Blacklist_T list)
{
    if(list->count >= (list->size - 2)) {
        list->entries = realloc(
            list->entries, list->size + BLACKLIST_INIT_SIZE);

        if(list->entries == NULL) {
            i_critical("realloc failed");
        }

        list->size += BLACKLIST_INIT_SIZE;
    }
}

static int
cmp_ipv4_entry(const void *a, const void *b)
{
    if(((struct Blacklist_entry *) a)->address.v4.s_addr
       > ((struct Blacklist_entry *) b)->address.v4.s_addr)
    {
        return 1;
    }

    if(((struct Blacklist_entry *) a)->address.v4.s_addr
       < ((struct Blacklist_entry *) b)->address.v4.s_addr)
    {
        return -1;
    }

    return 0;
}

static void
cidr_destroy(void *cidr)
{
    if(cidr) {
        free(cidr);
        cidr = NULL;
    }
}
