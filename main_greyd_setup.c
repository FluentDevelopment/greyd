/**
 * @file   main_greyd_setup.c
 * @brief  Main function for the greyd-setup program.
 * @author Mikey Austin
 * @date   2014
 */

/*
 * Copyright (c) 2014 Mikey Austin.  All rights reserved.
 * Copyright (c) 2003 Bob Beck.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define _GNU_SOURCE

#include "failures.h"
#include "utils.h"
#include "config.h"
#include "list.h"
#include "hash.h"
#include "blacklist.h"
#include "spamd_parser.h"
#include "firewall.h"
#include "greyd.h"
#include "constants.h"

#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <zlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#define DEFAULT_CONFIG "/etc/greyd/greyd.conf"
#define DEFAULT_CURL   "/bin/curl"
#define DEFAULT_MSG    "You have been blacklisted..."
#define PROGNAME       "greyd-setup"
#define MAX_PLEN       1024
#define METHOD_FTP     "ftp"
#define METHOD_HTTP    "http"
#define METHOD_EXEC    "exec"
#define METHOD_FILE    "file"
#define INIT_BL        10

static void usage();
static Spamd_parser_T get_parser(Config_section_T section, Config_T config);
static int open_child(char *file, char **argv);
static int file_get(char *url, char *curl_path);
static void send_blacklist(FW_handle_T fw, Blacklist_T blacklist, int greyonly,
                           Config_T config, int final_list, List_T all_cidrs);

/* Global debug variable. */
static int debug = 0;

static void
usage()
{
    fprintf(stderr, "usage: %s [-bDdn] [-c config]\n", PROGNAME);
    exit(1);
}

static int
file_get(char *url, char *curl_path)
{
    char *argv[4];

    if(curl_path == NULL)
        return -1;

    argv[0] = curl_path;
    argv[1] = "-s";
    argv[2] = url;
    argv[3] = NULL;

    if(debug)
       fprintf(stderr, "Getting %s\n", url);

    return (open_child(curl_path, argv));
}

/**
 * Open a pipe, for the specified child process and return the descriptor
 * pertaining to it's stdout.
 */
static int
open_child(char *file, char **argv)
{
    int pdes[2];

    if(pipe(pdes) != 0)
        return (-1);

    if(file == NULL)
        return -1;

    switch(fork()) {
    case -1:
        close(pdes[0]);
        close(pdes[1]);
        return (-1);

    case 0:
        /* child */
        close(pdes[0]);
        if(pdes[1] != STDOUT_FILENO) {
            dup2(pdes[1], STDOUT_FILENO);
            close(pdes[1]);
        }
        execvp(file, argv);
        _exit(1);
    }

    /* parent */
    close(pdes[1]);

    return (pdes[0]);
}

/**
 * Given the relevant configuration section, fetch the blacklist via
 * the specified method, create a gz lexer source, then construct and
 * return a parser.
 */
static Spamd_parser_T
get_parser(Config_section_T section, Config_T config)
{
    Spamd_parser_T parser = NULL;
    Lexer_T lexer;
    Lexer_source_T source;
    char *method, *file, **ap, **argv, *curl_path, *url;
    int fd, len;
    gzFile gzf;

    /* Extract the method & file variables from the section. */
    method = Config_section_get_str(section, "method", NULL);
    if((file = Config_section_get_str(section, "file", NULL)) == NULL)
    {
        I_WARN("No file configuration variables set");
        return NULL;
    }

    if((method == NULL)
       || (strncmp(method, METHOD_FILE, strlen(METHOD_FILE)) == 0))
    {
        /*
         * A file on the local filesystem is to be processed.
         */
        fd = open(file, O_RDONLY);
    }
    else if((strncmp(method, METHOD_HTTP, strlen(METHOD_HTTP)) == 0)
            || (strncmp(method, METHOD_FTP, strlen(METHOD_FTP)) == 0))
    {
        /*
         * The file is to be fetched via curl.
         */
        section = Config_get_section(config, CONFIG_DEFAULT_SECTION);
        curl_path = Config_section_get_str(section, "curl_path",
                                           DEFAULT_CURL);

        asprintf(&url, "%s://%s", method, file);
        if(url == NULL) {
            I_WARN("Could not create URL");
            return NULL;
        }

        fd = file_get(url, curl_path);
        free(url);
        url = NULL;
    }
    else if(strncmp(method, METHOD_EXEC, strlen(METHOD_EXEC)) == 0) {
        /*
         * The file is to be exec'ed, with the output to be parsed. The
         * string specified in the "file" variable is to be interpreted as
         * a command invocation.
         */
        len = strlen(file);
        if((argv = calloc(len, sizeof(char *))) == NULL) {
            I_ERR("malloc failed");
        }

        for(ap = argv; ap < &argv[len - 1] &&
                (*ap = strsep(&file, " \t")) != NULL;)
        {
            if(**ap != '\0')
                ap++;
        }

        *ap = NULL;
        fd = open_child(argv[0], argv);
        free(argv);
        argv = NULL;
    }
    else {
        I_WARN("Unknown method %s", method);
        return NULL;
    }

    /*
     * Now run the appropriate file descriptor through zlib.
     */
    if((gzf = gzdopen(fd, "r")) == NULL) {
        I_WARN("gzdopen");
        return NULL;
    }

    source = Lexer_source_create_from_gz(gzf);
    lexer = Spamd_lexer_create(source);
    parser = Spamd_parser_create(lexer);

    return parser;
}

static void
send_blacklist(FW_handle_T fw, Blacklist_T blacklist, int greyonly,
               Config_T config, int final_list, List_T all_cidrs)
{
    List_T cidrs;
    struct List_entry *entry;
    char *cidr;
    int nadded = 0, priv_sock, reserved_port = IPPORT_RESERVED - 1;
    int cfg_port = Config_get_int(config, "config_port", NULL,
                                  GREYD_CFG_PORT);
    struct sockaddr_in cfg_addr;
    FILE *cfg_out;

    cidrs = Blacklist_collapse(blacklist);

    if(!greyonly) {
        /* Append this blacklist's cidrs to the global list. */
        LIST_FOREACH(cidrs, entry) {
            cidr = List_entry_value(entry);
            List_insert_after(all_cidrs, cidr);
        }

        /*
         * If this is the final list, we send all of the collected CIDRs
         * to the firewall in one hit.
         */
        if(final_list && (!fw || (nadded = FW_replace(fw, "greyd", all_cidrs)) < 0)) {
            errx(1, "Could not configure firewall");
            if(debug)
                warnx("%d entries added to firewall", nadded);
        }
    }

    /*
     * Send this blacklist's information to greyd over the config connection. The
     * source port must be in the privileged ranged.
     */
    priv_sock = rresvport(&reserved_port);
    if(priv_sock == -1)
        err(1, "could not bind privileged source port");

    memset(&cfg_addr, 0, sizeof(cfg_addr));
    cfg_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    cfg_addr.sin_family = AF_INET;
    cfg_addr.sin_port = htons(cfg_port);

    if(connect(priv_sock, (struct sockaddr *) &cfg_addr, sizeof(cfg_addr)) == -1)
        err(1, "could not connect to greyd-config");

    if((cfg_out = fdopen(priv_sock, "w")) == NULL)
        err(1, "could not write to greyd-config");

    Greyd_send_config(cfg_out, blacklist->name, blacklist->message, cidrs);

    fclose(cfg_out);
    close(priv_sock);
    List_destroy(&cidrs);
}

int
main(int argc, char **argv)
{
    int option, dryrun = 0, greyonly = 1, daemonize = 0;
    int bltype, res, count;
    char *config_path = DEFAULT_CONFIG, *list_name, *message;
    Spamd_parser_T parser;
    Config_T config;
    Config_section_T section;
    Blacklist_T blacklist = NULL;
    Config_value_T val;
    List_T lists, all_cidrs;
    struct List_entry *entry;
    FW_handle_T fw = NULL;

    while((option = getopt(argc, argv, "f:bdDn")) != -1) {
        switch(option) {
        case 'f':
            config_path = optarg;
            break;

        case 'n':
            dryrun = 1;
            break;

        case 'd':
            debug = 1;
            break;

        case 'b':
            greyonly = 0;
            break;

        case 'D':
            daemonize = 1;
            break;

        default:
            usage();
            break;
        }
    }

    argc -= optind;
    if(argc != 0) {
        usage();
    }

    config = Config_create();
    Config_load_file(config, config_path);

    if(daemonize) {
        daemon(0, 0);
    }

    section = Config_get_section(config, CONFIG_DEFAULT_SECTION);
    lists = Config_section_get_list(section, "lists");
    if(lists == NULL || List_size(lists) == 0) {
        I_ERR("no lists configured in %s", config_path);
    }

    if(!greyonly && !dryrun)
        fw = FW_open(config);

    all_cidrs = List_create(NULL);

    /*
     * Loop through lists configured in the configuration.
     */
    LIST_FOREACH(lists, entry) {
        val = List_entry_value(entry);
        if((list_name = cv_str(val)) == NULL)
            continue;

        if((section = Config_get_blacklist(config, list_name))) {
            /*
             * We have a new blacklist. If there was a previous list,
             * send it off and destroy it before creating the new one.
             */
            if(blacklist && !dryrun) {
                send_blacklist(fw, blacklist, greyonly, config, 0, all_cidrs);
            }
            Blacklist_destroy(&blacklist);

            message = Config_section_get_str(section, "message", DEFAULT_MSG);
            blacklist = Blacklist_create(list_name, message);
            bltype = BL_TYPE_BLACK;
        }
        else if((section = Config_get_whitelist(config, list_name))
            && blacklist != NULL)
        {
            /*
             * Add this whitelist's entries to the previous blacklist.
             */
            bltype = BL_TYPE_WHITE;
        }
        else {
            continue;
        }

        if((parser = get_parser(section, config)) == NULL) {
            I_WARN("Ignoring list %s", list_name);
            continue;
        }

        /*
         * Parse the list and populate the current blacklist.
         */
        count = blacklist->count;
        res = Spamd_parser_start(parser, blacklist, bltype);
        if(res != SPAMD_PARSER_OK) {
            I_WARN("Blacklist parse error");
        }

        if(debug) {
            fprintf(stderr, "%slist %s %zu entries\n",
                    (bltype == BL_TYPE_BLACK ? "black" : "white"),
                    list_name,
                    ((blacklist->count - count) / 2));
        }

        Spamd_parser_destroy(&parser);
    }

    /*
     * Send the last blacklist and cleanup the various objects.
     */
    if(blacklist && !dryrun) {
        send_blacklist(fw, blacklist, greyonly, config, 1, all_cidrs);
        FW_close(&fw);
    }
    Blacklist_destroy(&blacklist);
    Config_destroy(&config);

    return 0;
}
