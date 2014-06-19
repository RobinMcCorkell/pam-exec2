/*
	Copyright (C) 2014 Robin McCorkell <rmccorkell@karoshi.org.uk>
	This file is part of pam_exec2.

	pam_exec2 is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	pam_exec2 is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with pam_exec2.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdarg.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <sys/capability.h>
#include <stdbool.h>
#include <sys/select.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>

#include <pam-once.h>

#define max(x,y) ((x) > (y) ? (x) : (y))

#define ENV_ITEM(n) { (n), #n }
static struct {
	int item;
	const char *name;
} env_items[] = {
	ENV_ITEM(PAM_SERVICE),
	ENV_ITEM(PAM_USER),
	ENV_ITEM(PAM_TTY),
	ENV_ITEM(PAM_RHOST),
	ENV_ITEM(PAM_RUSER),
};

enum type_t {
	AUTH,
	ACCOUNT,
	PASSWORD,
	OPEN_SESSION,
	CLOSE_SESSION
};
struct pam_type {
	enum type_t id;
	char *name;
};

enum flag_t {
/*	PAM_SILENT = 0x8000U,
	PAM_DISALLOW_NULL_AUTHTOK = 0x0001U,
	PAM_ESTABLISH_CRED = 0x0002U,
	PAM_DELETE_CRED = 0x0004U,
	PAM_REINITIALIZE_CRED = 0x0008U,
	PAM_REFRESH_CRED = 0x0010U,
	PAM_CHANGE_EXPIRED_AUTHTOK = 0x0020U,
*/
	DEBUG = 0x0100U,
	SETEUID = 0x0200U,
	DROP_PRIV = 0x0400U,
	SYSLOG = 0x0800U,
	ONCE = 0x1000U
};

struct opts_t {
	pam_handle_t *pamh;
	const char **argv;
	int argc;
	const char *logfile;
	enum flag_t flags;
	struct pam_type type;
};

static int parse_argv(struct opts_t *options, int argc, const char **argv) {
	for (int i = 0; i < argc; ++i) {
		if (argv[i][0] == '/') {
			options->argv = argv + i;
			options->argc = argc - i;
			break;
		} else if (strcasecmp(argv[i], "debug") == 0) {
			options->flags |= DEBUG;
		} else if (strcasecmp(argv[i], "quiet") == 0) {
			options->flags |= PAM_SILENT;
		} else if (strcasecmp(argv[i], "drop_priv") == 0) {
			options->flags |= DROP_PRIV;
			options->flags &= ~SETEUID;
		} else if (strcasecmp(argv[i], "seteuid") == 0) {
			options->flags |= SETEUID;
			options->flags &= ~DROP_PRIV;
		} else if (strcasecmp(argv[i], "syslog") == 0) {
			options->flags |= SYSLOG;
			options->logfile = NULL;
		} else if (strcasecmp(argv[i], "once") == 0) {
			options->flags |= ONCE;
		} else if (strcasecmp(argv[i], "use_first_pass") == 0) {
			/* not implemented */
		} else if (strncasecmp(argv[i], "type=", 5) == 0) {
			const char *type = argv[i] + 5;
			if (strcasecmp(type, "auth") == 0)
				options->type = (struct pam_type) {AUTH, "auth"};
			else if (strcasecmp(type, "account") == 0)
				options->type = (struct pam_type) {ACCOUNT, "account"};
			else if (strcasecmp(type, "password") == 0)
				options->type = (struct pam_type) {PASSWORD, "password"};
			else if (strcasecmp(type, "open_session") == 0)
				options->type = (struct pam_type) {OPEN_SESSION, "open_session"};
			else if (strcasecmp(type, "close_session") == 0)
				options->type = (struct pam_type) {CLOSE_SESSION, "close_session"};
			else {
				pam_syslog(options->pamh, LOG_ERR, "Invalid type %s", type);
				return PAM_SERVICE_ERR;
			}
		} else if (strncasecmp(argv[i], "log=", 4) == 0) {
			options->logfile = argv[i] + 4;
			options->flags &= ~SYSLOG;
		} else {
			pam_syslog(options->pamh, LOG_ERR, "Unknown option %s", argv[i]);
			return PAM_SERVICE_ERR;
		}
	}
	if (!options->argv) {
		pam_syslog(options->pamh, LOG_ERR, "No command given");
		return PAM_SERVICE_ERR;
	}
	return PAM_SUCCESS;
}

static char ** prepare_envlist(struct opts_t *options) {
	char **envlist = pam_getenvlist(options->pamh);
	int envlen;
	for (envlen = 0; envlist[envlen] != NULL; ++envlen);
	int nitems = sizeof(env_items) / sizeof(*env_items);
	/* +2 for PAM_TYPE and NULL */
	envlist = realloc(envlist, (envlen + nitems + 2) * sizeof(*envlist));
	if (envlist == NULL) {
		free(envlist);
		errno = ENOMEM;
		return NULL;
	}
	for (int i = 0; i < nitems; ++i) {
		const void *item;
		if (pam_get_item(options->pamh, env_items[i].item, &item)
		    != PAM_SUCCESS
		    || item == NULL)
			continue;
		char *envstr;
		if (asprintf(&envstr, "%s=%s",
		             env_items[i].name, (const char *)item) < 0) {
			free(envlist);
			errno = ENOMEM;
			return NULL;
		}
		envlist[envlen++] = envstr;
		envlist[envlen] = NULL;
	}

	char *envstr;
	if (asprintf(&envstr, "PAM_TYPE=%s", options->type.name) < 0) {
		free(envlist);
		errno = ENOMEM;
		return NULL;
	}
	envlist[envlen++] = envstr;
	envlist[envlen] = NULL;
	return envlist;
}

static int move_fd(int newfd, int fd) {
	if (newfd != fd) {
		if (dup2(newfd, fd) == -1)
			return -1;
		close(newfd);
	}
	return 0;
}

static int do_exec(struct opts_t *options) {
	struct passwd *pwd;
	bool do_setuid = false, do_setgid = false;
	if (options->flags & DROP_PRIV) {
		const char *user;
		int ret;
		if ((ret = pam_get_user(options->pamh, &user, NULL))
			!= PAM_SUCCESS) {
			pam_syslog(options->pamh, LOG_ERR, "Getting user failed");
			return ret;
		}
		if ((pwd = pam_modutil_getpwnam(options->pamh, user)) == NULL) {
			pam_syslog(options->pamh, LOG_NOTICE, "Invalid user");
			return PAM_USER_UNKNOWN;
		}

		cap_t capabilities = cap_get_proc();
		if (capabilities == NULL) {
			pam_syslog(options->pamh, LOG_CRIT,
			           "Failed to get capabilities: %m");
			return PAM_SYSTEM_ERR;
		}
		cap_flag_value_t cap_setuid, cap_setgid;
		cap_get_flag(capabilities, CAP_SETUID, CAP_EFFECTIVE, &cap_setuid);
		cap_get_flag(capabilities, CAP_SETGID, CAP_EFFECTIVE, &cap_setgid);
		cap_free(capabilities);

		uid_t cur_uid = getuid();
		gid_t cur_gid = getgid();

		if (options->flags & DEBUG) {
			pam_syslog(options->pamh, LOG_DEBUG, "uid: %lu", (unsigned long) cur_uid);
			pam_syslog(options->pamh, LOG_DEBUG, "gid: %lu", (unsigned long) cur_gid);
			pam_syslog(options->pamh, LOG_DEBUG, "capability %s: %s",
			           "CAP_SETUID/CAP_EFFECTIVE",
			           (cap_setuid == CAP_SET) ? "yes" : "no");
			pam_syslog(options->pamh, LOG_DEBUG, "capability %s: %s",
			           "CAP_SETGID/CAP_EFFECTIVE",
			           (cap_setgid == CAP_SET) ? "yes" : "no");
		}

		if (cur_uid == pwd->pw_uid || cap_setuid == CAP_SET) {
			do_setuid = true;
		} else {
			pam_syslog(options->pamh, LOG_ALERT,
			           "Cannot setuid, permission denied");
			return PAM_PERM_DENIED;
		}
		if (cur_gid == pwd->pw_gid || cap_setgid == CAP_SET) {
			do_setgid = true;
		} else {
			pam_syslog(options->pamh, LOG_ALERT,
			           "Cannot setgid, continuing");
		}
	}

	int stdout_fds[2];
	int stderr_fds[2];
	if (options->flags & SYSLOG) {
		if (options->flags & DEBUG)
			pam_syslog(options->pamh, LOG_DEBUG, "Opening pipes to syslog");

		if (pipe(stdout_fds) != 0) {
			pam_syslog(options->pamh, LOG_ERR, "pipe(...) failed: %m");
			return PAM_SYSTEM_ERR;
		}
		if (pipe(stderr_fds) != 0) {
			pam_syslog(options->pamh, LOG_ERR, "pipe(...) failed: %m");
			return PAM_SYSTEM_ERR;
		}
	}

	pid_t pid = fork();
	if (pid == -1)
		return PAM_SYSTEM_ERR;
	if (pid > 0) { /* parent */
		if (options->flags & SYSLOG) {
			close(stdout_fds[1]);
			close(stderr_fds[1]);
			int maxfd = max(stdout_fds[0], stderr_fds[0]);
			while (1) {
				if (options->flags & DEBUG)
					pam_syslog(options->pamh, LOG_DEBUG, "Listening on pipes");
				fd_set fds;
				FD_ZERO(&fds);
				FD_SET(stdout_fds[0], &fds);
				FD_SET(stderr_fds[0], &fds);

				char buffer[4096] = {0};
				int ret = select(maxfd + 1, &fds, NULL, NULL, NULL);

				if (ret < 0) {
					pam_syslog(options->pamh, LOG_CRIT, "select() failed: %m");
					return PAM_SYSTEM_ERR;
				} else if (ret > 0) {
					if (FD_ISSET(stdout_fds[0], &fds)) {
						int bytes = read(stdout_fds[0], buffer, sizeof(buffer) - 1);
						if (options->flags & DEBUG)
							pam_syslog(options->pamh, LOG_DEBUG,
							           "Got %d bytes from stdout pipe: %s",
							           bytes, buffer);
						if (bytes == 0) {
							break;
						} else if (bytes < 0) {
							pam_syslog(options->pamh, LOG_ERR, "read(stdout) failed: %m");
							return -1;
						}
						pam_syslog(options->pamh, LOG_NOTICE, "stdout: %s", buffer);
					}
					if (FD_ISSET(stderr_fds[0], &fds)) {
						int bytes = read(stderr_fds[0], buffer, sizeof(buffer) - 1);
						if (options->flags & DEBUG)
							pam_syslog(options->pamh, LOG_DEBUG,
							           "Got %d bytes from stderr pipe: %s",
							           bytes, buffer);
						if (bytes == 0) {
							break;
						} else if (bytes < 0) {
							pam_syslog(options->pamh, LOG_ERR, "read(stderr) failed: %m");
							return -1;
						}
						pam_syslog(options->pamh, LOG_ERR, "stderr: %s", buffer);
					}
				}
			}
			close(stdout_fds[0]);
			close(stderr_fds[0]);

			if (options->flags & DEBUG)
				pam_syslog(options->pamh, LOG_DEBUG, "Pipes closed");
		}

		pid_t retval;
		int status;
		while ((retval = waitpid(pid, &status, 0)) == -1 && errno == EINTR);
		if (retval == (pid_t)-1) {
			pam_syslog(options->pamh, LOG_ERR, "waitpid returns with -1: %m");
			return PAM_SYSTEM_ERR;
		} else if (status != 0 && ! WIFEXITED(status)) {
			if (WIFSIGNALED(status)) {
				pam_syslog(options->pamh, LOG_ERR, "%s failed: caught signal %d%s",
				           options->argv[0], WTERMSIG(status),
				           WCOREDUMP(status) ? " (core dumped)" : "");
			} else {
				pam_syslog(options->pamh, LOG_ERR, "%s failed: unknown status 0x%x",
				           options->argv[0], status);
			}
			return PAM_SYSTEM_ERR;
		}
		if (options->flags & DEBUG) {
			pam_syslog(options->pamh, LOG_DEBUG, "%s exited with %d",
			           options->argv[0], WEXITSTATUS(status));
		}
		int exit = WEXITSTATUS(status);
		if (exit >= _PAM_RETURN_VALUES)
			exit = PAM_SERVICE_ERR;
		return exit;
	} else { /* child */
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		if (options->logfile) {
			if (options->flags & DEBUG)
				pam_syslog(options->pamh, LOG_DEBUG, "Opening stdout to %s",
				           options->logfile);
			int fd = open(options->logfile, O_CREAT|O_APPEND|O_WRONLY,
			              S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
			if (fd == -1) {
				int err = errno;
				pam_syslog(options->pamh, LOG_CRIT, "open of %s failed: %m",
				           options->logfile);
				_exit(err);
			}
			if (move_fd(fd, STDOUT_FILENO) == -1) {
				int err = errno;
				pam_syslog(options->pamh, LOG_CRIT, "move to stdout failed: %m");
				_exit(err);
			}
			if (dup2(STDOUT_FILENO, STDERR_FILENO) == -1) {
				int err = errno;
				pam_syslog(options->pamh, LOG_CRIT, "dup2 to stderr failed: %m");
				_exit(err);
			}

			time_t tm = time(NULL);
			char *buffer;
			if (asprintf(&buffer, "*** %s", ctime(&tm)) > 0) {
				pam_modutil_write(STDOUT_FILENO, buffer, strlen(buffer));
				free(buffer);
			}
		} else if (options->flags & SYSLOG) {
			close(stdout_fds[0]);
			close(stderr_fds[0]);
			if (move_fd(stdout_fds[1], STDOUT_FILENO) == -1) {
				int err = errno;
				pam_syslog(options->pamh, LOG_CRIT, "move to stdout failed: %m");
				_exit(err);
			}
			if (move_fd(stderr_fds[1], STDERR_FILENO) == -1) {
				int err = errno;
				pam_syslog(options->pamh, LOG_CRIT, "move to stderr failed: %m");
				_exit(err);
			}
		} else {
			if (options->flags & DEBUG)
				pam_syslog(options->pamh, LOG_DEBUG, "Opening stdout to %s",
				           "/dev/null");
			int fd = open("/dev/null", O_WRONLY);
			if (fd == -1) {
				int err = errno;
				pam_syslog(options->pamh, LOG_CRIT, "open of %s failed: %m",
				           "/dev/null");
				_exit(err);
			}
			if (move_fd(fd, STDOUT_FILENO) == -1) {
				int err = errno;
				pam_syslog(options->pamh, LOG_CRIT, "move to stdout failed: %m");
				_exit(err);
			}
			if (dup2(STDOUT_FILENO, STDERR_FILENO) == -1) {
				int err = errno;
				pam_syslog(options->pamh, LOG_CRIT, "dup2 to stderr failed: %m");
				_exit(err);
			}
		}

		/* copy argv */
		char **argv = malloc((options->argc + 1) * sizeof(char *));
		for (int i = 0; i < options->argc; ++i) {
			argv[i] = strdup(options->argv[i]);
		}
		argv[options->argc] = NULL;

		/* set up environment */
		if (options->flags & DEBUG)
			pam_syslog(options->pamh, LOG_DEBUG, "Preparing environment");
		char **envlist = prepare_envlist(options);
		if (envlist == NULL) {
			int err = errno;
			pam_syslog(options->pamh, LOG_CRIT,
			           "prepare environment failed: %m");
			_exit(err);
		}
		if (options->flags & DEBUG) {
			for (int i = 0; envlist[i] != NULL; ++i) {
				pam_syslog(options->pamh, LOG_DEBUG, "env: %s",
				           envlist[i]);
			}
		}

		/* drop privileges */
		if (options->flags & SETEUID) {
			if (options->flags & DEBUG)
				pam_syslog(options->pamh, LOG_DEBUG, "Setting UID to EUID %lu",
				           (unsigned long) geteuid());
			if (setuid(geteuid()) == -1) {
				int err = errno;
				pam_syslog(options->pamh, LOG_ERR, "setuid(%lu) failed: %m",
				           (unsigned long) geteuid());
				_exit(err);
			}
		}

		if (do_setgid) {
			if (options->flags & DEBUG)
				pam_syslog(options->pamh, LOG_DEBUG, "Dropping gid to %lu",
				           (unsigned long) pwd->pw_gid);
			if (setgid(pwd->pw_gid) == -1) {
				int err = errno;
				pam_syslog(options->pamh, LOG_ERR, "setgid(%lu) failed: %m",
				           (unsigned long) pwd->pw_gid);
				_exit(err);
			}
			if (options->flags & DEBUG)
				pam_syslog(options->pamh, LOG_DEBUG,
				           "Resetting supplementary groups");
			if (initgroups(pwd->pw_name, pwd->pw_gid) == -1) {
				int err = errno;
				pam_syslog(options->pamh, LOG_ERR, "initgroups failed: %m");
				_exit(err);
			}
		}

		if (do_setuid) {
			if (options->flags & DEBUG)
				pam_syslog(options->pamh, LOG_DEBUG, "Dropping uid to %lu",
				           (unsigned long) pwd->pw_uid);
			if (setuid(pwd->pw_uid) == -1) {
				int err = errno;
				pam_syslog(options->pamh, LOG_ERR, "setuid(%lu) failed: %m",
				           (unsigned long) pwd->pw_uid);
				_exit(err);
			}
		}

		if (setsid() == -1) {
			int err = errno;
			pam_syslog(options->pamh, LOG_ERR, "setsid failed: %m");
			_exit(err);
		}

		/* execute */
		if (options->flags & DEBUG)
			pam_syslog(options->pamh, LOG_DEBUG, "Calling %s",
			           options->argv[0]);
		execve(options->argv[0], argv, envlist);
		int err = errno;
		pam_syslog(options->pamh, LOG_CRIT, "execve(%s) failed: %m",
		           options->argv[0]);
		free(envlist);
		_exit(err);
	}

	return PAM_SYSTEM_ERR; /* should never be reached */
}

/******************
 *	PAM functions
 ******************/

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
                    int argc, const char **argv) {
	struct opts_t options;
	options.pamh = pamh;
	options.flags = flags;
	options.type.id = AUTH;
	options.type.name = "auth";
	int ret;
	if ((ret = parse_argv(&options, argc, argv)) != PAM_SUCCESS)
		return ret;

	if (options.type.id != AUTH)
		return PAM_IGNORE;

	return do_exec(&options);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
               int argc, const char **argv) {
	return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                 int argc, const char **argv) {
	struct opts_t options;
	options.pamh = pamh;
	options.flags = flags;
	options.type.id = PASSWORD;
	options.type.name = "password";
	int ret;
	if ((ret = parse_argv(&options, argc, argv)) != PAM_SUCCESS)
		return ret;

	if (options.type.id != PASSWORD)
		return PAM_IGNORE;

	return do_exec(&options);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                 int argc, const char **argv) {
	struct opts_t options;
	options.pamh = pamh;
	options.flags = flags;
	options.type.id = ACCOUNT;
	options.type.name = "account";
	int ret;
	if ((ret = parse_argv(&options, argc, argv)) != PAM_SUCCESS)
		return ret;

	if (options.type.id != ACCOUNT)
		return PAM_IGNORE;

	return do_exec(&options);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
                    int argc, const char **argv) {
	struct opts_t options;
	options.pamh = pamh;
	options.flags = flags;
	options.type.id = OPEN_SESSION;
	options.type.name = "open_session";
	int ret;
	if ((ret = parse_argv(&options, argc, argv)) != PAM_SUCCESS)
		return ret;

	if (options.type.id != OPEN_SESSION)
		return PAM_IGNORE;

	if (options.flags & ONCE) {
		int flags = (options.flags & DEBUG) ? PAM_ONCE_DEBUG : 0;
		ret = pam_once_open_session(pamh, flags);
		if (ret == PAM_IGNORE) {
			return PAM_IGNORE;
		} else if (ret != PAM_SUCCESS) {
			pam_syslog(pamh, LOG_ERR, "pam_once_open_session failed: %s",
			           pam_strerror(pamh, ret));
			return ret;
		}
	}

	return do_exec(&options);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
                     int argc, const char **argv) {
	struct opts_t options;
	options.pamh = pamh;
	options.flags = flags;
	options.type.id = CLOSE_SESSION;
	options.type.name = "close_session";
	int ret;
	if ((ret = parse_argv(&options, argc, argv)) != PAM_SUCCESS)
		return ret;

	if (options.type.id != CLOSE_SESSION)
		return PAM_IGNORE;

	if (options.flags & ONCE) {
		int flags = (options.flags & DEBUG) ? PAM_ONCE_DEBUG : 0;
		ret = pam_once_close_session(pamh, flags);
		if (ret == PAM_IGNORE) {
			return PAM_IGNORE;
		} else if (ret != PAM_SUCCESS) {
			pam_syslog(pamh, LOG_ERR, "pam_once_close_session failed: %s",
			           pam_strerror(pamh, ret));
			return ret;
		}
	}

	return do_exec(&options);
}
