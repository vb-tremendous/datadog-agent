#ifndef _RMDIR_H_
#define _RMDIR_H_

#include "syscalls.h"

struct rmdir_event_t {
    struct kevent_t event;
    struct process_context_t process;
    struct container_context_t container;
    struct syscall_t syscall;
    struct file_t file;
    u32 discarder_revision;
    u32 padding;
};

SYSCALL_KPROBE0(rmdir) {
    struct syscall_cache_t syscall = {
        .type = SYSCALL_RMDIR,
    };

    cache_syscall(&syscall, EVENT_RMDIR);

    return 0;
}

SEC("kprobe/security_inode_rmdir")
int kprobe__security_inode_rmdir(struct pt_regs *ctx) {
    struct syscall_cache_t *syscall = peek_syscall(SYSCALL_RMDIR | SYSCALL_UNLINK);
    if (!syscall)
        return 0;

    u64 event_type = 0;
    struct path_key_t key = {};
    struct dentry *dentry = NULL;

    switch (syscall->type) {
        case SYSCALL_RMDIR:
            event_type = EVENT_RMDIR;

            if (syscall->rmdir.path_key.ino) {
                return 0;
            }

            // we resolve all the information before the file is actually removed
            dentry = (struct dentry *)PT_REGS_PARM2(ctx);
            set_path_key_inode(dentry, &syscall->rmdir.path_key, 1);

            syscall->rmdir.overlay_numlower = get_overlay_numlower(dentry);

            // the mount id of path_key is resolved by kprobe/mnt_want_write. It is already set by the time we reach this probe.
            key = syscall->rmdir.path_key;

            break;
        case SYSCALL_UNLINK:
            event_type = EVENT_UNLINK;

            if (syscall->unlink.path_key.ino) {
                return 0;
            }

            // we resolve all the information before the file is actually removed
            dentry = (struct dentry *) PT_REGS_PARM2(ctx);
            set_path_key_inode(dentry, &syscall->unlink.path_key, 1);

            syscall->unlink.overlay_numlower = get_overlay_numlower(dentry);

            // the mount id of path_key is resolved by kprobe/mnt_want_write. It is already set by the time we reach this probe.
            key = syscall->unlink.path_key;

            break;
    }

    if (discarded_by_process(syscall->policy.mode, event_type)) {
        invalidate_inode(ctx, key.mount_id, key.ino, 1);

        return 0;
    }

    if (dentry != NULL) {
        int ret = resolve_dentry(dentry, key, syscall->policy.mode != NO_FILTER ? event_type : 0);
        if (ret == DENTRY_DISCARDED) {
            invalidate_inode(ctx, key.mount_id, key.ino, 1);

            pop_syscall(syscall->type);
        }
    }

    return 0;
}

SYSCALL_KRETPROBE(rmdir) {
    struct syscall_cache_t *syscall = pop_syscall(SYSCALL_RMDIR | SYSCALL_UNLINK);
    if (!syscall)
        return 0;

    int retval = PT_REGS_RC(ctx);

    if (IS_UNHANDLED_ERROR(retval)) {
        invalidate_inode(ctx, syscall->rmdir.path_key.mount_id, syscall->rmdir.path_key.ino, 0);
        return 0;
    }

    int enabled = is_event_enabled(EVENT_RMDIR);
    if (enabled) {
        struct rmdir_event_t event = {
            .syscall.retval = retval,
            .file = {
                .inode = syscall->rmdir.path_key.ino,
                .mount_id = syscall->rmdir.path_key.mount_id,
                .overlay_numlower = syscall->rmdir.overlay_numlower,
                .path_id = syscall->rmdir.path_key.path_id,
            },
            .discarder_revision = bump_discarder_revision(syscall->rmdir.path_key.mount_id),
        };

        struct proc_cache_t *entry = fill_process_context(&event.process);
        fill_container_context(entry, &event.container);

        send_event(ctx, EVENT_RMDIR, event);
    }

    invalidate_inode(ctx, syscall->rmdir.path_key.mount_id, syscall->rmdir.path_key.ino, !enabled);

    return 0;
}

#endif
