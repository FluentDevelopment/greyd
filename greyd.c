/**
 * @file   greyd.h
 * @brief  Implements greyd support constants and definitions.
 * @author Mikey Austin
 * @date   2014
 */

#include "failures.h"
#include "config.h"
#include "greyd.h"
#include "hash.h"
#include "ip.h"
#include "list.h"
#include "config_parser.h"
#include "blacklist.h"

extern void
Greyd_process_config(int fd, struct Greyd_state *state)
{
    Config_T message;
    Config_value_T value;
    Lexer_source_T source;
    Lexer_T lexer;
    Config_parser_T parser;
    Blacklist_T blacklist;
    char *bl_name, *bl_msg, *addr;
    List_T ips;
    struct List_entry *entry;
    int read_fd;

    /*
     * Duplicate the descriptor so that the incoming fd isn't closed
     * upon destroying the lexer source.
     */
    if((read_fd = dup(fd)) == -1)
        I_CRIT("dup: %m");
    source = Lexer_source_create_from_fd(read_fd);
    lexer = Config_lexer_create(source);
    parser = Config_parser_create(lexer);
    message = Config_create();

    if(Config_parser_start(parser, message) == CONFIG_PARSER_OK) {
        /*
         * Create a new blacklist and overwrite any existing.
         */
        bl_name = Config_get_str(message, "name", NULL, NULL);
        bl_msg = Config_get_str(message, "message", NULL, NULL);
        ips = Config_get_list(message, "ips", NULL);
        if(bl_name && bl_msg && ips) {
            blacklist = Blacklist_create(bl_name, bl_msg);
            LIST_FOREACH(ips, entry) {
                value = List_entry_value(entry);
                if((addr = cv_str(value)) != NULL)
                    Blacklist_add(blacklist, addr);
            }
            Hash_insert(state->blacklists, bl_name, blacklist);
            I_DEBUG("refreshing blacklist \"%s\"", bl_name);
        }
    }

    Config_destroy(&message);
    Config_parser_destroy(&parser);
}

extern void
Greyd_send_config(FILE *out, char *bl_name, char *bl_msg, List_T ips)
{
    struct List_entry *entry;
    char *ip;
    int first = 1;
    short af;

    if(List_size(ips) > 0) {
        fprintf(out, "name=\"%s\"\nmessage=\"%s\"\nips=[",
                bl_name, bl_msg);

        LIST_FOREACH(ips, entry) {
            ip = List_entry_value(entry);
            af = IP_check_addr(ip);
            fprintf(out, "%s\"%s/%d\"", (first ? "" : ","),
                    ip, (af == AF_INET ? 32 : 128));
            first = 0;
        }
    }
    fprintf(out, "]\n%%\n");

    if(fflush(out) == EOF)
        I_DEBUG("configure_greyd: fflush failed");
}
