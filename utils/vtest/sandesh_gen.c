/*
 * sandesh_gen.c -- parse the sandesh file and generate code that takes
 * the xml node and assigns the value to the corresponding member of
 * the structure
 *
 * Copyright (c) 2015, Juniper Networks, Inc.
 * All rights reserved
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <ctype.h>

#define CHARS   80

static char line[CHARS];
static char nest[] = "    ";

static char header[] = {"\
/*\n\
 * Auto generated file\n\
 */\n"
};

static char includes[] = {"\
#include <string.h>\n\n\
#include <stdbool.h>\n\n\
\
#include <libxml/xmlmemory.h>\n\
#include <libxml/parser.h>\n\n\
\
#include <vr_types.h>\n\
#include <vt_gen_lib.h>\n\
#include <vtest.h>\n\n"
};

static char message_gen[] = {"\
#include <vt_gen_message_modules.h>\n\n\
struct vt_message_module vt_message_modules[] = {\n\
"};

static char vt_message_module_gen[] = {"\
struct vt_message_module {\n\
    char *vmm_name;\n\
    void *(*vmm_node)(xmlNodePtr, struct vtest *);\n\
    bool (*vmm_expect)(xmlNodePtr, struct vtest *, void *);\n\
    unsigned int vmm_size;\n\
};\n\n"
};

static char part_gen[] = {"\
    req = calloc(sizeof(*req), 1);\n\
    if (!req)\n\
        return NULL;\n\n\
    node = node->xmlChildrenNode;\n\
    while (node) {\n\
        if (node->type == XML_TEXT_NODE) {\n\
            node = node->next;\n\
            continue;\n\
        }\n\n\
"
};

static char expect_gen[] = {"\
    node = node->xmlChildrenNode;\n\
    while (node) {\n\
        if (node->type == XML_TEXT_NODE) {\n\
            node = node->next;\n\
            continue;\n\
        }\n\n\
"
};

static unsigned char *
gen_skip_space(unsigned char *string)
{
    unsigned int i = 0, len;

    if (!string)
        return string;

    len = strlen(string);
    if (!len)
        return NULL;

    while ((i < len) && isspace(string[i])) {
        i++;
    }

    if (i == len)
        return NULL;

    return &string[i];
}

static unsigned char *
gen_reach_char(unsigned char *string, unsigned char c)
{
    unsigned int i = 0, len;

    if (!string)
        return string;

    len = strlen(string);
    if (!len)
        return string;

    while ((i < len) && (string[i] != c)) {
        i++;
    }

    return &string[i];
}

static unsigned char *
gen_reach_space(unsigned char *string)
{
    return gen_reach_char(string, ' ');
}


static void
gen_write(FILE *ofp, unsigned int nesting, unsigned char *string)
{
    unsigned int i;

    for (i = 0; i < nesting; i++)
        fwrite(nest, 1, strlen(nest), ofp);

    fwrite(string, 1, strlen(string), ofp);
    return;
}

static void
gen_raw_write(FILE *ofp, unsigned int nesting,
        unsigned char *string, unsigned int len)
{
    unsigned int i;

    for (i = 0; i < nesting; i++)
        fwrite(nest, 1, strlen(nest), ofp);

    fwrite(string, 1, len, ofp);
    return;
}

static void
gen_close(FILE *fp, bool header_file)
{
    if (header_file) {
        gen_write(fp, 0, "\n#endif\n");
    }

    fclose(fp);
    return;
}

static FILE *
gen_open(unsigned char *name, bool header_file)
{
    unsigned char c[105];
    unsigned int i = 0, j = 0;
    FILE *fp;

    if (header_file && (strlen(name) >= 100)) {
        perror(name);
        return NULL;
    }

    fp = fopen(name, "w+");
    if (!fp)
        return fp;

    gen_write(fp, 0, header);

    if (header_file) {
        gen_write(fp, 0, "#ifndef ");
        c[i++] = '_';
        c[i++] = '_';
        while ((c[i] = name[j]) != '\0') {
            if (c[i] == '.') {
                c[i] = '_';
            } else {
                c[i] = toupper(c[i]);
            }
            i++, j++;
        }
        c[i++] = '_';
        c[i++] = '_';

        c[i] = '\0';

        gen_write(fp, 0, c);
        gen_write(fp, 0, "\n");
        gen_write(fp, 0, "#define ");
        gen_write(fp, 0, c);
        gen_write(fp, 0, "\n\n");
    }

    gen_write(fp, 0, includes);

    return fp;
}

static int
gen(FILE *fp)
{
    bool need_else = false;

    unsigned int len, start = 0, end = 0;
    unsigned int type_len, sub_type_len = 0, var_len;
    unsigned int nesting = 0;

    char *marker, *type, *var, *sub_type = NULL;
    FILE *ofp, *fp_expect, *fp_message, *fp_message_hdr;

    ofp = gen_open("vt_gen_sandesh.c", false);
    if (!ofp) {
        perror("vt_gen_sandesh.c");
        return errno;
    }

    fp_expect = gen_open("vt_gen_sandesh_expect.c", false);
    if (!fp_expect) {
        perror("vt_gen_sandesh_expect.c");
        return errno;
    }

    fp_message = gen_open("vt_gen_message_modules.c", false);
    if (!fp_message) {
        perror("vt_message_modules.c");
        return errno;
    }
    gen_write(fp_message, 0, message_gen);

    fp_message_hdr = gen_open("vt_gen_message_modules.h", true);
    if (!fp_message_hdr) {
        perror("vt_gen_message_modules.h");
        return errno;
    }
    gen_write(fp_message_hdr, 0, vt_message_module_gen);

    while (fgets(line, sizeof(line), fp)) {
        if (!strncmp("buffer sandesh", line, strlen("buffer sandesh"))) {
            len = strlen("buffer sandesh");
            marker = gen_skip_space(&line[len]);
            if (!marker)
                break;

            start = marker - line;
            marker = gen_reach_space(marker);
            end = marker - line;

            gen_write(fp_message, 1, "{\n");
            gen_write(fp_message, 2, ".vmm_name");
            gen_write(fp_message, 2, "=");
            gen_write(fp_message, 2, "\"");
            gen_raw_write(fp_message, 0, &line[start], end - start);
            gen_write(fp_message, 0, "\",\n");

            gen_write(fp_message, 2, ".vmm_node");
            gen_write(fp_message, 2, "=");
            gen_raw_write(fp_message, 2, &line[start], end - start);
            gen_write(fp_message, 0, "_node,\n");

            gen_write(fp_message, 2, ".vmm_expect");
            gen_write(fp_message, 2, "=");
            gen_raw_write(fp_message, 2, &line[start], end - start);
            gen_write(fp_message, 0, "_expect,\n");

            gen_write(fp_message, 2, ".vmm_size");
            gen_write(fp_message, 2, "=");
            gen_write(fp_message, 2, "sizeof(");
            gen_raw_write(fp_message, 0, &line[start], end - start);
            gen_write(fp_message, 0, "),\n");
            gen_write(fp_message, 1, "},\n");

            gen_write(fp_message_hdr, 0, "extern void *");
            gen_raw_write(fp_message_hdr, 0, &line[start], end - start);
            gen_write(fp_message_hdr, 0, "_node(xmlNodePtr, struct vtest *);\n");

            gen_write(ofp, nesting, "void *\n");
            gen_raw_write(ofp, nesting, &line[start], end - start);
            gen_write(ofp, nesting, "_node(xmlNodePtr node, struct vtest *test)\n");
            gen_write(ofp, nesting, "{\n");

            gen_write(fp_message_hdr, 0, "extern bool ");
            gen_raw_write(fp_message_hdr, 0, &line[start], end - start);
            gen_write(fp_message_hdr, 0, "_expect(xmlNodePtr, struct vtest *, void *);\n");

            gen_write(fp_expect, nesting, "bool\n");
            gen_raw_write(fp_expect, nesting, &line[start], end - start);
            gen_write(fp_expect, nesting, "_expect(xmlNodePtr node, struct vtest *test, void *buf)\n");
            gen_write(fp_expect, nesting, "{\n");

            gen_write(ofp, ++nesting, "unsigned int list_size;\n");
            gen_raw_write(ofp, nesting, &line[start], end - start);
            gen_write(ofp, 0, " *req;\n\n");
            gen_write(ofp, 0, part_gen);

            gen_write(fp_expect, nesting, "bool result = true;\n");
            gen_write(fp_expect, nesting, "unsigned int list_size;\n");
            gen_raw_write(fp_expect, nesting, &line[start], end - start);
            gen_write(fp_expect, 0, " *req = (");
            gen_raw_write(fp_expect, 0, &line[start], end - start);
            gen_write(fp_expect, 0, " *)buf;\n\n");
            gen_write(fp_expect, 0, expect_gen);

            /* account for nesting inside part_gen */
            nesting++;
            continue;
        }

        if (start) {
            if (!strncmp("}", line, strlen("}"))) {
                start = end = 0;
                gen_write(ofp, 0, "\n");
                gen_write(ofp, nesting, "node = node->next;\n");

                gen_write(fp_expect, 0, "\n\n");
                gen_write(fp_expect, nesting, "if (!result)\n");
                gen_write(fp_expect, nesting + 1, "return result;\n\n");
                gen_write(fp_expect, nesting, "node = node->next;\n");

                gen_write(ofp, --nesting, "}\n\n");
                gen_write(ofp, nesting, "return (void *)req;\n}\n\n");

                gen_write(fp_expect, nesting, "}\n\n");
                gen_write(fp_expect, nesting, "return result;\n}\n\n");

                --nesting;
                need_else = false;
                continue;
            }

            marker = strchr(line, ':');
            if (!marker) {
                return EINVAL;
            }

            marker = gen_skip_space(++marker);
            if (!marker) {
                return EINVAL;
            }

            type = marker;
            marker = gen_reach_space(marker);
            if (!marker) {
                return EINVAL;
            }
            type_len = marker - type;

            if (!strncmp(type, "list", strlen("list"))) {
                marker = type + strlen("list");;
                marker = gen_skip_space(marker);
                if (!marker) {
                    return EINVAL;
                }

                if (*marker != '<') {
                    return EINVAL;
                }

                sub_type = ++marker;
                marker = gen_reach_char(marker, '>');
                if (!marker) {
                    return EINVAL;
                }
                sub_type_len = marker - sub_type;
                marker = gen_reach_space(marker);
                if (!marker) {
                    return EINVAL;
                }
            }

            marker = gen_skip_space(marker);
            if (!marker) {
                return EINVAL;
            }

            var = marker;
            marker = gen_reach_char(marker, ';');
            if (!marker) {
                return EINVAL;
            }
            var_len = marker - var;

            if (need_else) {
                gen_write(ofp, 0, " else ");
                gen_write(fp_expect, 0, " else ");
            } else {
                gen_write(ofp, nesting, "");
                gen_write(fp_expect, nesting, "");
            }

            gen_write(ofp, 0, "if (!strncmp(node->name, ");
            gen_write(ofp, 0, "\"");
            gen_raw_write(ofp, 0, var, var_len);
            gen_write(ofp, 0, "\"");
            gen_write(ofp, 0, ", sizeof(");
            gen_write(ofp, 0, "\"");
            gen_raw_write(ofp, 0, var, var_len);
            gen_write(ofp, 0, "\"");
            gen_write(ofp, 0, "))) {\n");

            gen_write(fp_expect, 0, "if (!strncmp(node->name, ");
            gen_write(fp_expect, 0, "\"");
            gen_raw_write(fp_expect, 0, var, var_len);
            gen_write(fp_expect, 0, "\"");
            gen_write(fp_expect, 0, ", strlen(node->name))) {\n");

            gen_write(ofp, nesting, "if (node->children && node->children->content)\n");

            gen_write(ofp, ++nesting, "req->");
            gen_raw_write(ofp, 0, var, var_len);
            gen_write(ofp, 0, " = ");

            gen_write(fp_expect, nesting, "");

            if (!strncmp(type, "i32", strlen("i32"))) {
                gen_write(ofp, 0, "strtoul(node->children->content, NULL, 0);\n");

                gen_write(fp_expect, 0, "result = vt_gen_int_compare(");
                gen_write(fp_expect, 0, "req->");
                gen_raw_write(fp_expect, 0, var, var_len);
                gen_write(fp_expect, 0, ",\n");
                gen_write(fp_expect, nesting + 4, "strtoul(node->children->content, NULL, 0)");
                gen_write(fp_expect, 0, ");\n");

            } else if (!strncmp(type, "u32", strlen("u32"))) {
                gen_write(ofp, 0, "strtoul(node->children->content, NULL, 0);\n");

                gen_write(fp_expect, 0, "result = vt_gen_int_compare(");
                gen_write(fp_expect, 0, "req->");
                gen_raw_write(fp_expect, 0, var, var_len);
                gen_write(fp_expect, 0, ",\n");
                gen_write(fp_expect, nesting + 4, "strtoul(node->children->content, NULL, 0)");
                gen_write(fp_expect, 0, ");\n");

            } else if ((!strncmp(type, "i64", strlen("i64"))) ||
                      (!strncmp(type, "u64", strlen("u64")))) {
                gen_write(ofp, 0, "strtoull(node->children->content, NULL, 0);\n");

                gen_write(fp_expect, 0, "result = vt_gen_int64_compare(");
                gen_write(fp_expect, 0, "req->");
                gen_raw_write(fp_expect, 0, var, var_len);
                gen_write(fp_expect, 0, ",\n");
                gen_write(fp_expect, nesting + 4, "strtoul(node->children->content, NULL, 0)");
                gen_write(fp_expect, 0, ");\n");

            } else if ((!strncmp(type, "i16", strlen("i16"))) ||
                    (!strncmp(type, "u16", strlen("u16")))) {
                gen_write(ofp, 0, "strtoul(node->children->content, NULL, 0);\n");

                gen_write(fp_expect, 0, "result = vt_gen_short_compare(");
                gen_write(fp_expect, 0, "req->");
                gen_raw_write(fp_expect, 0, var, var_len);
                gen_write(fp_expect, 0, ",\n");
                gen_write(fp_expect, nesting + 4, "strtoul(node->children->content, NULL, 0));\n");

            } else if (!strncmp(type, "byte", strlen("byte"))) {
                gen_write(ofp, 0, "strtoul(node->children->content, NULL, 0);\n");

                gen_write(fp_expect, 0, "result = vt_gen_byte_compare(");
                gen_write(fp_expect, 0, "req->");
                gen_raw_write(fp_expect, 0, var, var_len);
                gen_write(fp_expect, 0, ",\n");
                gen_write(fp_expect, nesting + 4, "strtoul(node->children->content, NULL, 0)");
                gen_write(fp_expect, 0, ");\n");

            } else if (!strncmp(type, "sandesh_op", strlen("sandesh_op"))) {
                gen_write(ofp, 0, "vt_gen_op(node->children->content);\n");

                gen_write(fp_expect, 0, "result = vt_gen_op_compare(");
                gen_write(fp_expect, 0, "req->");
                gen_raw_write(fp_expect, 0, var, var_len);
                gen_write(fp_expect, 0, ", node->children->content);\n");

            } else if (!strncmp(type, "flow_op", strlen("flow_op"))) {
                gen_write(ofp, 0, "vt_gen_flow_op(node->children->content);\n");

                gen_write(fp_expect, 0, "result = vt_gen_flow_op_compare(");
                gen_write(fp_expect, 0, "req->");
                gen_raw_write(fp_expect, 0, var, var_len);
                gen_write(fp_expect, 0, ", node->content);\n");

            } else if (!strncmp(type, "list", strlen("list"))) {
                if (!strncmp(sub_type, "byte", strlen("byte"))) {
                    gen_write(ofp, 0, "vt_gen_list(node->children->content, GEN_TYPE_U8, &list_size);\n");

                    gen_write(fp_expect, 0, "result = vt_gen_list_compare(");
                    gen_write(fp_expect, 0, "req->");
                    gen_raw_write(fp_expect, 0, var, var_len);
                    gen_write(fp_expect, 0, ",\n");
                    gen_write(fp_expect, nesting + 2, "req->");
                    gen_raw_write(fp_expect, 0, var, var_len);
                    gen_write(fp_expect, 0, "_size");
                    gen_write(fp_expect, 0, ", node->children->content, GEN_TYPE_U8);\n");

                } else if (!strncmp(sub_type, "i16", strlen("i16"))) {
                    gen_write(ofp, 0, "vt_gen_list(node->children->content, GEN_TYPE_U16, &list_size);\n");

                    gen_write(fp_expect, 0, "result = vt_gen_list_compare(");
                    gen_write(fp_expect, 0, "req->");
                    gen_raw_write(fp_expect, 0, var, var_len);
                    gen_write(fp_expect, 0, ",\n");
                    gen_write(fp_expect, nesting + 2, "req->");
                    gen_raw_write(fp_expect, 0, var, var_len);
                    gen_write(fp_expect, 0, "_size");
                    gen_write(fp_expect, 0, ", node->children->content, GEN_TYPE_U16);\n");

                } else if (!strncmp(sub_type, "i32", strlen("i32")) ||
                        !strncmp(sub_type, "u32", strlen("u32"))) {
                    gen_write(ofp, 0, "vt_gen_list(node->children->content, GEN_TYPE_U32, &list_size);\n");

                    gen_write(fp_expect, 0, "result = vt_gen_list_compare(");
                    gen_write(fp_expect, 0, "req->");
                    gen_raw_write(fp_expect, 0, var, var_len);
                    gen_write(fp_expect, 0, ",\n");
                    gen_write(fp_expect, nesting + 2, "req->");
                    gen_raw_write(fp_expect, 0, var, var_len);
                    gen_write(fp_expect, 0, "_size");
                    gen_write(fp_expect, 0, ", node->children->content, GEN_TYPE_U32);\n");

                } else if (!strncmp(sub_type, "i64", strlen("i64"))) {
                    gen_write(ofp, 0, "vt_gen_list(node->children->content, GEN_TYPE_U64, &list_size);\n");

                    gen_write(fp_expect, 0, "result = vt_gen_list_compare(");
                    gen_write(fp_expect, 0, "req->");
                    gen_raw_write(fp_expect, 0, var, var_len);
                    gen_write(fp_expect, 0, ",\n");
                    gen_write(fp_expect, nesting + 2, "req->");
                    gen_raw_write(fp_expect, 0, var, var_len);
                    gen_write(fp_expect, 0, "_size");
                    gen_write(fp_expect, 0, ", node->children->content, GEN_TYPE_U64);\n");

                }

                gen_write(ofp, nesting, "req->");
                gen_raw_write(ofp, 0, var, var_len);
                gen_write(ofp, 0, "_size = list_size;\n");
            } else if (!strncmp(type, "string", strlen("string"))) {
                gen_write(ofp, 0, "vt_gen_string(node->children->content);\n");

                gen_write(fp_expect, 0, "result = !strcmp(");
                gen_write(fp_expect, 0, "req->");
                gen_raw_write(fp_expect, 0, var, var_len);
                gen_write(fp_expect, 0, ", node->children->content);\n");

            }

            gen_write(ofp, --nesting, "}");
            gen_write(fp_expect, nesting, "}");
            need_else = true;
        }
    }

    gen_write(fp_message, 1, "{\n");
    gen_write(fp_message, 2, ".vmm_name");
    gen_write(fp_message, 2, "=");
    gen_write(fp_message, 2, "\"return\",\n");
    gen_write(fp_message, 2, ".vmm_node");
    gen_write(fp_message, 2, "=");
    gen_write(fp_message, 2, "vt_return_node,\n");
    gen_write(fp_message, 2, ".vmm_size");
    gen_write(fp_message, 2, "=");
    gen_write(fp_message, 2, "0,\n");
    gen_write(fp_message, 1, "},\n");
    gen_write(fp_message_hdr, 0, "extern void *");
    gen_write(fp_message_hdr, 0, "vt_return_node(xmlNodePtr, struct vtest *);\n");

    gen_write(fp_message, 0, "};\n\n");
    gen_write(fp_message, 0,
            "unsigned int vt_message_modules_num = \n");
    gen_write(fp_message, 2, "sizeof(vt_message_modules) / sizeof(vt_message_modules[0]);\n\n");
    gen_close(fp_message, false);
    gen_close(fp_message_hdr, true);

    return 0;
}

static void
Usage(void)
{
    printf("Usage: sandesh_gen <file name>\n");
    return;
}

int
main(int argc, char *argv[])
{
    int ret;
    FILE *fp;

    if (argc != 2) {
        Usage();
        return EINVAL;
    }

    fp = fopen(argv[1], "r");
    if (!fp) {
        perror(argv[1]);
        return errno;
    }

    ret = gen(fp);
    return ret;
}
