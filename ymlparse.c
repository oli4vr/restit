/* ymlparse.c
 *
 * Minimal YAML record parser for restit manifests
 * by Olivier Van Rompuy
 *
 * Parses a restricted YAML subset:
 *   - List items starting with "- "
 *   - key: value pairs (inline after "- " or indented 2+ spaces)
 *   - Blank lines and # comments are skipped
 *   - Unknown keys are silently ignored (future extensibility)
 *
 * Two-pass approach per record:
 *   Pass 1: scan for "- " markers to find record boundaries
 *   Pass 2: copy each line to a temp buffer, parse key:value from there
 *
 * The original buffer is never modified (unlike the old CSV parser).
 * *inbuff is advanced to the start of the next record after each call.
 *
 */

#include "ymlparse.h"
#include "entropy.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

cmdsched * yml_next_sched(unsigned char **inbuff, unsigned char *tpath, unsigned char mode) {
    unsigned char *buf = *inbuff;
    unsigned char *record_start = NULL, *record_end = NULL, *p, *key, *val;
    unsigned char line[1024];
    unsigned char vault[256]={0}, keystring[256]={0}, sfname[256]={0};
    unsigned char shell[128]={0}, seconds_str[32]={0};
    unsigned char commands[8127]={0};
    unsigned char time_windows[256]={0};
    unsigned char vaultfile[256];
    int indent, base_indent = -1, n, vlen;
    long int offset;
    uint32_t seconds;
    FILE *fp;
    cmdsched *rcsched;

    if (buf == NULL || *buf == 0) return NULL;

    /* ---- PASS 1: Find record boundaries ---- */
    p = buf;
    while (*p) {
        while (*p == '\n') p++;
        if (*p == 0) break;

        unsigned char *line_start = p;
        while (*p && *p != '\n') p++;

        key = line_start;
        indent = 0;
        while (*key == ' ') { indent++; key++; }

        if (*key == 0 || *key == '#') continue;

        if (*key == '-' && (*(key+1) == ' ' || *(key+1) == 0)) {
            if (record_start == NULL) {
                record_start = line_start;
                base_indent = indent;
            } else {
                record_end = line_start;
                break;
            }
        }
    }
    if (record_start == NULL) return NULL;
    if (record_end == NULL) record_end = p;

    *inbuff = record_end;

    /* ---- PASS 2: Parse key:value pairs within record ---- */
    p = record_start;
    while (p < record_end) {
        while (*p == '\n') { p++; if (p >= record_end) break; }
        if (p >= record_end) break;

        n = 0;
        while (p < record_end && *p != '\n' && n < 1023) {
            line[n++] = *p++;
        }
        line[n] = 0;

        key = line;
        indent = 0;
        while (*key == ' ') { indent++; key++; }
        if (*key == 0 || *key == '#') continue;

        /* Skip list item marker "- " or "-" alone on its line */
        if (*key == '-' && (*(key+1) == ' ' || *(key+1) == 0)) {
            key += 2;
            while (*key == ' ') key++;
            if (*key == 0) continue;
        }

        /* Parse key: value */
        val = key;
        while (*val && *val != ':') val++;
        if (*val != ':') continue;
        *val = 0;
        val++;
        while (*val == ' ') val++;

        /* Trim trailing whitespace */
        vlen = strnlen(val, 255);
        while (vlen > 0 && (val[vlen-1] == ' ' || val[vlen-1] == '\t' || val[vlen-1] == '\r'))
            vlen--;
        val[vlen] = 0;

        if (strcmp(key, "category") == 0)
            strncpy(vault, val, 255);
        else if (strcmp(key, "type") == 0)
            strncpy(keystring, val, 255);
        else if (strcmp(key, "interval") == 0)
            strncpy(seconds_str, val, 31);
        else if (strcmp(key, "script") == 0)
            strncpy(sfname, val, 255);
        else if (strcmp(key, "shell") == 0)
            strncpy(shell, val, 127);
        else if (strcmp(key, "time_windows") == 0)
            strncpy(time_windows, val, 255);
        /* Unknown keys silently ignored — future extensibility */
    }

    /* Validate required fields */
    if (vault[0]==0 || keystring[0]==0 || seconds_str[0]==0 || sfname[0]==0 || shell[0]==0)
        return NULL;

    seconds = atoi(seconds_str);
    if (seconds < 1) return NULL;

    /* Read script */
    if (mode == 0) {
        fp = fopen(sfname, "r+b");
        if (fp == NULL) return NULL;
        n = fread(commands, 1, 8126, fp);
        fclose(fp);
        if (n < 1) return NULL;
    } else {
        snprintf(vaultfile, 256, "%s/.restit.%s.manifest", tpath, vault);
        offset = entropy_search(commands, keystring, securestr, vaultfile, 2);
        if (offset < 0) return NULL;
    }

    rcsched = malloc(sizeof(cmdsched));
    snprintf(vaultfile, 256, "%s/.restit.%s.manifest", tpath, vault);
    memcpy(rcsched->vaultfile, vaultfile, 256);
    memcpy(rcsched->vault, vault, 256);
    memcpy(rcsched->keystring, keystring, 256);
    memcpy(rcsched->commands, commands, 8127);
    memcpy(rcsched->shell, shell, 128);
    memcpy(rcsched->scriptname, sfname, 64);
    if (time_windows[0]==0) strncpy(time_windows,"00:00-23:59",255);
    memcpy(rcsched->time_windows, time_windows, 256);
    rcsched->seconds = seconds;
    rcsched->resultsnum = 0;
    return rcsched;
}
