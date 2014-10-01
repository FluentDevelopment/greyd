/**
 * @file   greydb.h
 * @brief  Defines the generic greylisting database abstraction.
 * @author Mikey Austin
 * @date   2014
 */

#ifndef GREYDB_DEFINED
#define GREYDB_DEFINED

#include "config_section.h"
#include "grey.h"

#define H DB_handle_T
#define K DB_key_T
#define V DB_val_T
#define I DB_itr_T

#define DB_KEY_IP    1 /**< An ip address. */
#define DB_KEY_MAIL  2 /**< A valid email address. */
#define DB_KEY_TUPLE 3 /**< A greylist tuple. */

#define DB_VAL_GREY         1 /**< Grey counters data. */
#define DB_VAL_MATCH_SUFFIX 2 /**< Match suffix data. */

#define DB_ERR       -1
#define DB_FOUND     0
#define DB_NOT_FOUND 1

/**
 * Keys may be of different types depending on the type of database entry.
 */
struct K {
    int type;
    union {
        char s[GREY_MAX_MAIL];  /**< May contain IP or MAIL key types. */
        struct Grey_tuple_T gt; 
    } data;
};

struct V {
    int type;
    union {
        char s[GREY_MAX_MAIL]; /**< Allowed domain. */
        struct Grey_data_T gd; /**< Greylisting counters.h */
    } data;
};

typedef struct H *H;
struct H {
    void *dbh;                /**< Module dependent handle reference. */
    Config_section_T section; /**< Module configuration section. */
};

typedef struct I *I;
struct I {
    H   handle;  /**< Database handle reference. */
    int current; /**< Current index. */
    int size;    /**< Number of elements in the iteration. */
};

/**
 * Open a connection to the configured database based on the configuration.
 */
extern H DB_open(Config_section_T db_section);

/**
 * Close a database connection.
 */
extern void DB_close(H *handle);

/**
 * Initialize the database identified by the supplied handle.
 */
extern int DB_init(H handle);

/**
 * Insert a single key/value pair into the database.
 */
extern int DB_put(H handle, struct K *key, struct V *val);

/**
 * Get a single value out of the database, associated with the
 * specified key.
 */
extern int DB_get(H handle, struct K *key, struct V *val);

/**
 * Return an iterator for all database entries. If there are no entries,
 * NULL is returned.
 */
extern I DB_get_itr(H handle);

/**
 * Return the next key/value pair from the iterator.
 */
extern int DB_itr_next(I itr, struct K *key, struct V *val);

/**
 * Cleanup a used iterator.
 */
extern void DB_close_itr(I *itr);

#undef K
#undef V
#undef H
#undef I
#endif