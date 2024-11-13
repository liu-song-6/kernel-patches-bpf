// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Facebook */

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define FS_CREATE		0x00000100	/* Subfile was created */
#define FS_ISDIR		0x40000000	/* event occurred against dir */

struct __tasks_kfunc_map_value {
	struct inode __kptr * task;
};

struct inode *__some_inode;
struct task_struct *__some_task;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct __tasks_kfunc_map_value);
	__uint(max_entries, 1);
} __tasks_kfunc_map SEC(".maps");

/* struct __inode_kptr_value { */
/* 	struct inode __kptr *task_struct; */
/* }; */

/* struct { */
/* 	__uint(type, BPF_MAP_TYPE_HASH); */
/* 	__type(key, int); */
/* 	__type(value, struct __inode_kptr_value); */
/* 	__uint(max_entries, 1); */
/* } subdir_root SEC(".maps"); */

struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u32);
} inode_storage_map SEC(".maps");

int added_inode_storage;
unsigned long root_ino;
bool initialized;

static void initialize_subdir_root(struct fanotify_fastpath_event *fp_event)
{
	/* struct __inode_kptr_value *v; */
	/* struct inode *inode, *old; */
	/* int zero = 0; */

	if (initialized)
		return;

	/* inode = bpf_fanotify_data_inode(fp_event); */
	/* if (inode) */
	/* 	return; */

	/* if (inode->i_ino != root_ino) { */
	/* 	bpf_iput(inode); */
	/* 	return; */
	/* } */

	/* v = bpf_map_lookup_elem(&subdir_root, &zero); */
	/* if (v) { */
	/* 	old = bpf_kptr_xchg(&v->inode, inode); */
	/* 	if (old) */
	/* 		bpf_iput(old); */
	/* 	initialized = true; */
	/* } */
}

SEC("struct_ops")
int BPF_PROG(bpf_fp_handler,
	     struct fsnotify_group *group,
	     struct fanotify_fastpath_hook *fp_hook,
	     struct fanotify_fastpath_event *fp_event)
{
	struct inode *dir;
	__u32 *value;

	initialize_subdir_root(fp_event);

	dir = fp_event->dir;

	value = bpf_inode_storage_get(&inode_storage_map, dir, 0, 0);

	/* if dir doesn't have the tag, skip the event */
	if (!value)
		return FAN_FP_RET_SKIP_EVENT;

	/* propagate tag to subdir on fsnotify_mkdir */
	if (fp_event->mask == (FS_CREATE | FS_ISDIR) &&
	    fp_event->data_type == FSNOTIFY_EVENT_DENTRY) {
		struct inode *new_inode;

		new_inode = bpf_fanotify_data_inode(fp_event);
		if (!new_inode)
			goto out;

		value = bpf_inode_storage_get(&inode_storage_map, new_inode, 0,
					      BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (value) {
			*value = 1;
			added_inode_storage++;
		}
		bpf_iput(new_inode);
	}
out:
	return FAN_FP_RET_SEND_TO_USERSPACE;
}

SEC("struct_ops")
int BPF_PROG(bpf_fp_init, struct fanotify_fastpath_hook *hook, const char *args)
{
	return 0;
}

SEC("struct_ops")
void BPF_PROG(bpf_fp_free, struct fanotify_fastpath_hook *hook)
{
}

SEC(".struct_ops.link")
struct fanotify_fastpath_ops bpf_fanotify_fastpath_ops = {
	.fp_handler = (void *)bpf_fp_handler,
	.fp_init = (void *)bpf_fp_init,
	.fp_free = (void *)bpf_fp_free,
	.name = "_tmp_test_sub_tree",
};

char _license[] SEC("license") = "GPL";
