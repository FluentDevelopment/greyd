/**
 * @file   config.h
 * @brief  Defines the application configuration interface.
 * @author Mikey Austin
 * @date   2014
 */

#ifndef CONFIG_DEFINED
#define CONFIG_DEFINED

#include "hash.h"
#include "queue.h"
#include "config_section.h"

#define CONFIG_DEFAULT_SECTION "default"

/**
 * The main config table structure.
 */
typedef struct Config_T *Config_T;
struct Config_T {
    Hash_T  sections;           /**< This config's sections */
    Hash_T  blacklists;         /**< Configured blacklists */
    Hash_T  whitelists;         /**< Configured whitelists */
    Hash_T  processed_includes; /**< For tracking processed included files */
    Queue_T includes;           /**< A queue of included files to be parsed */
};

/**
 * Create a new empty configuration object.
 */
extern Config_T Config_create();

/**
 * Destroy a config table, freeing all sections.
 */
extern void Config_destroy(Config_T *config);

/*
 * Add a section to the configuration.
 */
extern void Config_add_section(Config_T config, Config_section_T section);

/*
 * Add a blacklist to the configuration.
 */
extern void Config_add_blacklist(Config_T config, Config_section_T section);

/*
 * Add a whitelist to the configuration.
 */
extern void Config_add_whitelist(Config_T config, Config_section_T section);

/**
 * Get a configuration section by name if one exists.
 */
extern Config_section_T Config_get_section(Config_T config, const char *section_name);

/**
 * Get a blacklist by name if one exists.
 */
extern Config_section_T Config_get_blacklist(Config_T config, const char *section_name);

/**
 * Get a whitelist by name if one exists.
 */
extern Config_section_T Config_get_whitelist(Config_T config, const char *section_name);

/**
 * Parse the specified file and load the configuration data. Any included
 * sub-configuration files will also be parsed.
 */
extern void Config_load_file(Config_T config, char *file);

/**
 * Merge the "from" configuration into the "config" configuration. Only
 * the "sections" variables are merged (ie no blacklists, whitelists, etc.).
 */
extern void Config_merge(Config_T config, Config_T from);

/**
 * Add the specified file to the list of include files to process if it
 * hasn't been processed already.
 */
extern void Config_add_include(Config_T config, const char *file);

/**
 * Get a string variable from the configuration. The section name may be
 * NULL, in which case the default section is used.
 */
extern char *Config_get_str(Config_T config, const char *varname,
                           const char *section_name, char *default_str);

/**
 * Same as the string version, but for integer config values.
 */
extern int Config_get_int(Config_T config, const char *varname,
                          const char *section_name, int default_int);

/**
 * Same as the string version, but without the default value.
 */
extern List_T Config_get_list(Config_T config, const char *varname,
                              const char *section_name);

/**
 * Set an integer value. If the section doesn't exist, it is created.
 */
extern void Config_set_int(Config_T config, const char *varname,
                           const char *section_name, int value);

/**
 * Set an string value, behaviour is the same as the int version.
 */
extern void Config_set_str(Config_T config, const char *varname,
                           const char *section_name, char *value);

#endif
