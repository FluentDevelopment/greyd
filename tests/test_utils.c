/**
 * @file   test_utils.c
 * @brief  Unit tests for common utility functions.
 * @author Mikey Austin
 * @date   2014
 */

#include "test.h"
#include <utils.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SIZE 50

int
main(void)
{
    char email1[SIZE] = "<tesT@Email.OrG";
    char email2[SIZE] = "<tesT2@Email.OrG>";
    char email3[SIZE] = "test3@email.org";
    char email4[SIZE] = "tesT4@Email.OrG>";
    char email5[SIZE] = "test5@email.ORG";
    char buf[SIZE];

    TEST_START(5);

    normalize_email_addr(email1, buf, sizeof(buf));
    TEST_OK(!strcmp(buf, "test@email.org"), "normalize ok");

    memset(buf, 0, sizeof(buf));
    normalize_email_addr(email2, buf, sizeof(buf));
    TEST_OK(!strcmp(buf, "test2@email.org"), "normalize ok");

    memset(buf, 0, sizeof(buf));
    normalize_email_addr(email3, buf, sizeof(buf));
    TEST_OK(!strcmp(buf, "test3@email.org"), "normalize ok");

    memset(buf, 0, sizeof(buf));
    normalize_email_addr(email4, buf, sizeof(buf));
    TEST_OK(!strcmp(buf, "test4@email.org"), "normalize ok");

    memset(buf, 0, sizeof(buf));
    normalize_email_addr(email3, buf, sizeof(buf));
    TEST_OK(!strcmp(buf, "test3@email.org"), "normalize ok");

    TEST_COMPLETE;
}