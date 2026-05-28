/* ymlparse.h
 *
 * Minimal YAML record parser for restit manifests
 *
 * Parses a restricted YAML subset:
 *   - key: value
 *   supports list items with "- " prefix
 *   skips blank lines and # comments
 *   unknown keys silently ignored (future extensibility)
 *
 */

#ifndef YMLPARSE_H
#define YMLPARSE_H

#include "main.h"

cmdsched * yml_next_sched(unsigned char **inbuff, unsigned char *tpath, unsigned char mode);

#endif
