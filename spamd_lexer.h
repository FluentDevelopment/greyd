/**
 * @file   spamd_lexer.h
 * @brief  Interface for spamd blacklist lexer.
 * @author Mikey Austin
 * @date   2014
 */

#ifndef SPAMD_LEXER_DEFINED
#define SPAMD_LEXER_DEFINED

#include "lexer.h"

#define SPAMD_LEXER_MAX_INT6  32
#define SPAMD_LEXER_MAX_INT8  255

#define SPAMD_LEXER_TOK_DOT   100
#define SPAMD_LEXER_TOK_INT6  101
#define SPAMD_LEXER_TOK_INT8  102
#define SPAMD_LEXER_TOK_DASH  103
#define SPAMD_LEXER_TOK_SLASH 104
#define SPAMD_LEXER_TOK_EOF   105
#define SPAMD_LEXER_TOK_EOL   106

/**
 * Create a fresh lexer object.
 */
extern Lexer_T Spamd_lexer_create(Lexer_source_T source);

/**
 * Scan the specified lexer source's character stream and return
 * the next token seen.
 */
extern int Spamd_lexer_next_token(Lexer_T lexer);

#endif
