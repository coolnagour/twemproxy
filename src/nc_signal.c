/*
 * twemproxy - A fast and lightweight proxy for memcached protocol.
 * Copyright (C) 2011 Twitter, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <nc_core.h>
#include <nc.h>
#include <nc_conf.h>     /* struct conf -- SIGHUP reads global.worker_processes */
#include <nc_signal.h>
#include <nc_process.h>

static struct signal signals[] = {
    { SIGUSR1, "SIGUSR1", 0,                 signal_handler },
    { SIGUSR2, "SIGUSR2", 0,                 signal_handler },
    { SIGTTIN, "SIGTTIN", 0,                 signal_handler },
    { SIGTTOU, "SIGTTOU", 0,                 signal_handler },
    { SIGHUP,  "SIGHUP",  0,                 signal_handler },
    { SIGINT,  "SIGINT",  0,                 signal_handler },
    { SIGTERM, "SIGTERM", 0,                 signal_handler },
    { SIGSEGV, "SIGSEGV", (int)SA_RESETHAND, signal_handler },
    { SIGCHLD, "SIGCHLD", 0,                 signal_handler },
    { SIGPIPE, "SIGPIPE", 0,                 SIG_IGN },
    { SIGALRM, "SIGALRM", 0,                 signal_handler },
    { 0,        NULL,     0,                 NULL }
};

rstatus_t
signal_init(void)
{
    struct signal *sig;

    for (sig = signals; sig->signo != 0; sig++) {
        rstatus_t status;
        struct sigaction sa;

        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sig->handler;
        sa.sa_flags = sig->flags;
        sigemptyset(&sa.sa_mask);

        status = sigaction(sig->signo, &sa, NULL);
        if (status < 0) {
            log_error("sigaction(%s) failed: %s", sig->signame,
                      strerror(errno));
            return NC_ERROR;
        }
    }

    return NC_OK;
}

void
signal_deinit(void)
{
}

/*
 * TODO(async-safety): this handler uses non-async-signal-safe calls (buffered
 * logging via log_safe, localtime in the log path, exit()) and reads/writes
 * pm_* flags that are plain (not volatile sig_atomic_t). That only matters with
 * worker_processes > 0 (real master/worker signalling); this deployment runs
 * single-process, so the rework (volatile sig_atomic_t flags, drop
 * localtime/buffered-logging/exit from the handler) is deferred. Do NOT add new
 * unsafe calls to the multi-process paths here.
 */
void
signal_handler(int signo)
{
    struct signal *sig;
    void (*action)(void);
    char *actionstr;
    bool done;

    for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }
    ASSERT(sig->signo != 0);

    actionstr = "";
    action = NULL;
    done = false;

    switch (signo) {
    case SIGUSR1:
        actionstr = ", reopening log file";
        action = log_reopen;
        if (pm_myrole == ROLE_MASTER) {
            nc_signal_workers(&master_nci->workers, NC_CMD_LOG_REOPEN);
        }
        break;

    case SIGUSR2:
        break;

    case SIGTTIN:
        actionstr = ", up logging level";
        if (pm_myrole == ROLE_MASTER) {
            nc_signal_workers(&master_nci->workers, NC_CMD_LOG_LEVEL_UP);
        }
        action = log_level_up;
        break;

    case SIGTTOU:
        actionstr = ", down logging level";
        action = log_level_down;
        if (pm_myrole == ROLE_MASTER) {
            nc_signal_workers(&master_nci->workers, NC_CMD_LOG_LEVEL_DOWN);
        }
        break;

    case SIGHUP:
        if (pm_myrole == ROLE_MASTER) {
            /*
             * Single-process mode (worker_processes < 1) has no master/worker
             * split, so pm_myrole is still ROLE_MASTER here -- but the single
             * process run loop (nc_single_process_cycle) never consumes
             * pm_reload, so arming nc_reload_config would be a SILENT no-op.
             * Say so plainly instead of pretending the reload happened.
             *
             * Guard the master_nci->ctx->cf chain: a SIGHUP can arrive in the
             * sub-second startup window BEFORE master_nci / its ctx / its cf are
             * wired up (master_nci starts NULL; ctx and cf are filled in during
             * core_start). Dereferencing any of them then is a NULL crash. Treat
             * not-yet-initialised as "not in single-process mode": do nothing --
             * a startup-window SIGHUP becomes a harmless no-op, not a crash, and
             * we do not arm a reload against a half-built process. The real
             * multi-process reload path below is unaffected (by the time workers
             * exist the chain is fully populated).
             */
            if (master_nci != NULL && master_nci->ctx != NULL &&
                master_nci->ctx->cf != NULL) {
                if (master_nci->ctx->cf->global.worker_processes < 1) {
                    log_safe("SIGHUP: config reload is not supported in "
                             "single-process mode (worker_processes < 1); "
                             "restart twemproxy to apply config changes");
                } else {
                    actionstr = ", reload config";
                    action = nc_reload_config;
                }
            }
        }
        break;

    case SIGINT:
        if (pm_myrole == ROLE_MASTER) {
            nc_signal_workers(&master_nci->workers, NC_CMD_QUIT);
            wait(NULL);
            done = true;
        } else {
            pm_quit = true;
        }
        actionstr = ", exiting";
        break;

    case SIGTERM:
        if (pm_myrole == ROLE_MASTER) {
            nc_signal_workers(&master_nci->workers, NC_CMD_TERMINATE);
            wait(NULL);
            done = true;
        } else {
            pm_terminate = true;
        }
        actionstr = ", terminating";
        break;

    case SIGSEGV:
        log_stacktrace();
        actionstr = ", core dumping";
        raise(SIGSEGV);
        break;
    case SIGALRM:
        if (pm_terminate) {
            pm_quit = true;
            pm_terminate = false;
            actionstr = ", time's up, quit";
        }
        break;

    case SIGCHLD:
        ASSERT(pm_myrole == ROLE_MASTER);
        actionstr = ", reaping child";
        action = nc_reap_worker;
        break;

    default:
        NOT_REACHED();
    }

    log_safe("signal %d (%s) received%s", signo, sig->signame, actionstr);

    if (action != NULL) {
        action();
    }

    if (done) {
        nc_post_run(master_nci);
        exit(1);
    }
}
