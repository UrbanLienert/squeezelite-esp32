/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.6-dev */

#ifndef PB_PROTOBUF_MERCURY_PB_H_INCLUDED
#define PB_PROTOBUF_MERCURY_PB_H_INCLUDED
#include <pb.h>

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

/* Struct definitions */
typedef struct _Header { 
    bool has_uri;
    char uri[256]; 
    bool has_method;
    char method[64]; 
} Header;


#ifdef __cplusplus
extern "C" {
#endif

/* Initializer values for message structs */
#define Header_init_default                      {false, "", false, ""}
#define Header_init_zero                         {false, "", false, ""}

/* Field tags (for use in manual encoding/decoding) */
#define Header_uri_tag                           1
#define Header_method_tag                        3

/* Struct field encoding specification for nanopb */
#define Header_FIELDLIST(X, a) \
X(a, STATIC,   OPTIONAL, STRING,   uri,               1) \
X(a, STATIC,   OPTIONAL, STRING,   method,            3)
#define Header_CALLBACK NULL
#define Header_DEFAULT NULL

extern const pb_msgdesc_t Header_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define Header_fields &Header_msg

/* Maximum encoded size of messages (where known) */
#define Header_size                              323

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
