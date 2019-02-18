/*
 * win_work_item.h
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __WIN_WORK_ITEM_H__
#define __WIN_WORK_ITEM_H__

typedef struct _WIN_WORK_ITEM
    WIN_WORK_ITEM, *PWIN_WORK_ITEM;

typedef void (*WinWorkFunc)(PWIN_WORK_ITEM);

PWIN_WORK_ITEM WinWorkItemCreate(WinWorkFunc Func, void *Context);
void WinWorkItemWaitDestroy(PWIN_WORK_ITEM Work);
void WinWorkItemQueueWork(PWIN_WORK_ITEM Work);

#endif // __WIN_WORK_ITEM_H__
