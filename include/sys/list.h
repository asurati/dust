/*
 * Copyright (c) 2018 Amol Surati
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _SYS_LIST_H_
#define _SYS_LIST_H_

#include <stddef.h>

#define container_of(p, t, m)		(t *)((char *)p - offsetof(t, m))

struct list_head {
	struct list_head *prev;
	struct list_head *next;
};

#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_rev(pos, head) \
	for (pos = (head)->prev; pos != (head); pos = pos->prev)

#define list_entry(p, t, m)             container_of(p, t, m)

void	 init_list_head(struct list_head *head);
char	 list_empty(const struct list_head *head);
void	 list_add(struct list_head *n, struct list_head *head);
void	 list_add_tail(struct list_head *n, struct list_head *head);
void	 list_del(struct list_head *e);
struct list_head
	*list_del_head(struct list_head *head);
#endif
