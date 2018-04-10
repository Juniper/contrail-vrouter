#ifndef __ULINUX_H__
#define __ULINUX_H__

#include <time.h>

/*
 * License: GPL-2.0 WITH Linux-syscall-note
 * https://github.com/torvalds/linux
 * http://elixir.free-electrons.com/linux/v4.1.21/source/include/linux/timer.h
 */
struct list_head {
    struct list_head *next, *prev;
};

struct dummy_timer_list {
    /*
     * All fields that change during normal runtime grouped to the
     * same cacheline
     */
    struct list_head entry;
    unsigned long expires;
    struct tvec_base *base;

    void (*function)(unsigned long);
    unsigned long data;

    int slack;

    int start_pid;
    void *start_site;
    char start_comm[16];
};

time_t get_time(void);
void add_timer(struct dummy_timer_list *);
void init_timer(struct dummy_timer_list *);
void ulinux_timer(unsigned long);
#endif
