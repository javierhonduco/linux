// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <syscall.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define CHECK(condition, tag, format...)                                       \
	({                                                                     \
		int __ret = !!(condition);                                     \
		if (__ret) {                                                   \
			printf("%s:FAIL:%s ", __func__, tag);                  \
			printf(format);                                        \
		} else {                                                       \
			printf("%s:PASS:%s\n", __func__, tag);                 \
		}                                                              \
		__ret;                                                         \
	})

static int bpf_find_map(const char *test, struct bpf_object *obj,
			const char *name)
{
	struct bpf_map *map;

	map = bpf_object__find_map_by_name(obj, name);
	if (!map)
		return -1;
	return bpf_map__fd(map);
}

int main(int argc, char **argv)
{
	const char *probe_name = "syscalls/sys_enter_open";
	const char *file = "test_progenyof_kern.o";
	int err, bytes, efd, prog_fd, pmu_fd;
	int resultmap_fd, pidmap_fd;
	struct perf_event_attr attr = {};
	struct bpf_object *obj;
	__u32 retrieved_ancestor_pid = 0;
	__u32 key = 0, pid;
	int exit_code = EXIT_FAILURE;
	char buf[256];

	int child_pid, ancestor_pid, root_fd, nonexistant = -42;
	__u32 ancestor_key = 1;
	int pipefd[2];
	char marker[1];

	err = bpf_prog_load(file, BPF_PROG_TYPE_TRACEPOINT, &obj, &prog_fd);
	if (CHECK(err, "bpf_prog_load", "err %d errno %d\n", err, errno))
		goto fail;

	resultmap_fd = bpf_find_map(__func__, obj, "resultmap");
	if (CHECK(resultmap_fd < 0, "bpf_find_map", "err %d errno %d\n",
		  resultmap_fd, errno))
		goto close_prog;

	pidmap_fd = bpf_find_map(__func__, obj, "pidmap");
	if (CHECK(pidmap_fd < 0, "bpf_find_map", "err %d errno %d\n", pidmap_fd,
		  errno))
		goto close_prog;

	pid = getpid();
	bpf_map_update_elem(pidmap_fd, &key, &pid, 0);
	bpf_map_update_elem(pidmap_fd, &ancestor_key, &pid, 0);

	snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/events/%s/id",
		 probe_name);
	efd = open(buf, O_RDONLY, 0);
	if (CHECK(efd < 0, "open", "err %d errno %d\n", efd, errno))
		goto close_prog;
	bytes = read(efd, buf, sizeof(buf));
	close(efd);
	if (CHECK(bytes <= 0 || bytes >= sizeof(buf), "read",
		  "bytes %d errno %d\n", bytes, errno))
		goto close_prog;

	attr.config = strtol(buf, NULL, 0);
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;

	pmu_fd = syscall(__NR_perf_event_open, &attr, getpid(), -1, -1, 0);
	if (CHECK(pmu_fd < 0, "perf_event_open", "err %d errno %d\n", pmu_fd,
		  errno))
		goto close_prog;

	err = ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0);
	if (CHECK(err, "perf_event_ioc_enable", "err %d errno %d\n", err,
		  errno))
		goto close_pmu;

	err = ioctl(pmu_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
	if (CHECK(err, "perf_event_ioc_set_bpf", "err %d errno %d\n", err,
		  errno))
		goto close_pmu;

	// Test on ourselve: progenyof(current->pid) is true
	bpf_map_update_elem(pidmap_fd, &key, &pid, 0);
	bpf_map_update_elem(pidmap_fd, &ancestor_key, &pid, 0);
	bpf_map_update_elem(resultmap_fd, &key, &nonexistant, 0);

	root_fd = open("/", O_RDONLY);
	if (CHECK(efd < 0, "open", "errno %d\n", errno))
		goto close_prog;
	close(root_fd);

	err = bpf_map_lookup_elem(resultmap_fd, &key, &retrieved_ancestor_pid);
	if (CHECK(err, "bpf_map_lookup_elem", "err %d errno %d\n", err, errno))
		goto close_pmu;
	if (CHECK(retrieved_ancestor_pid != pid,
		  "progenyof is true with same pid", "%d == %d\n",
		  retrieved_ancestor_pid, pid))
		goto close_pmu;

	// Test that PID 1 is among our progeny
	bpf_map_update_elem(pidmap_fd, &key, &pid, 0);
	ancestor_pid = 1;
	bpf_map_update_elem(pidmap_fd, &ancestor_key, &ancestor_pid, 0);
	bpf_map_update_elem(resultmap_fd, &key, &nonexistant, 0);

	root_fd = open("/", O_RDONLY);
	if (CHECK(efd < 0, "open", "errno %d\n", errno))
		goto close_prog;
	close(root_fd);

	err = bpf_map_lookup_elem(resultmap_fd, &key, &retrieved_ancestor_pid);
	if (CHECK(err, "bpf_map_lookup_elem", "err %d errno %d\n", err, errno))
		goto close_pmu;
	if (CHECK(retrieved_ancestor_pid != ancestor_pid,
		  "progenyof reaches init", "%d == %d\n",
		  retrieved_ancestor_pid, ancestor_pid))
		goto close_pmu;

	// Test that PID 0 is among our progeny
	bpf_map_update_elem(pidmap_fd, &key, &pid, 0);
	ancestor_pid = 0;
	bpf_map_update_elem(pidmap_fd, &ancestor_key, &ancestor_pid, 0);
	bpf_map_update_elem(resultmap_fd, &key, &nonexistant, 0);

	root_fd = open("/", O_RDONLY);
	if (CHECK(efd < 0, "open", "errno %d\n", errno))
		goto close_prog;
	close(root_fd);

	err = bpf_map_lookup_elem(resultmap_fd, &key, &retrieved_ancestor_pid);
	if (CHECK(err, "bpf_map_lookup_elem", "err %d errno %d\n", err, errno))
		goto close_pmu;
	if (CHECK(retrieved_ancestor_pid != ancestor_pid,
		  "progenyof does not go over init", "%d == %d\n",
		  retrieved_ancestor_pid, ancestor_pid))
		goto close_pmu;

	// Test that we don't go over PID 0
	bpf_map_update_elem(pidmap_fd, &key, &pid, 0);
	ancestor_pid = -1;
	bpf_map_update_elem(pidmap_fd, &ancestor_key, &ancestor_pid, 0);
	bpf_map_update_elem(resultmap_fd, &key, &nonexistant, 0);

	root_fd = open("/", O_RDONLY);
	if (CHECK(efd < 0, "open", "errno %d\n", errno))
		goto close_prog;
	close(root_fd);

	err = bpf_map_lookup_elem(resultmap_fd, &key, &retrieved_ancestor_pid);
	if (CHECK(err, "bpf_map_lookup_elem", "err %d errno %d\n", err, errno))
		goto close_pmu;
	if (CHECK(retrieved_ancestor_pid != nonexistant,
		  "progenyof does not go over init", "%d == %d\n",
		  retrieved_ancestor_pid, nonexistant))
		goto close_pmu;

	// Test that we are among the progeny our child
	pipe(pipefd);
	child_pid = fork();
	if (child_pid == -1) {
		printf("fork failed\n");
		goto close_pmu;
	} else if (child_pid == 0) {
		close(pipefd[1]);
		read(pipefd[0], &marker, 1);

		root_fd = open("/", O_RDONLY);
		if (CHECK(efd < 0, "open", "errno %d\n", errno))
			goto close_prog;
		close(root_fd);

		close(pipefd[0]);
		_exit(EXIT_SUCCESS);
	} else {
		close(pipefd[0]);
		bpf_map_update_elem(resultmap_fd, &key, &nonexistant, 0);
		bpf_map_update_elem(pidmap_fd, &key, &child_pid, 0);
		bpf_map_update_elem(pidmap_fd, &ancestor_key, &pid, 0);

		write(pipefd[1], &marker, 1);
		wait(NULL);
		close(pipefd[1]);

		err = bpf_map_lookup_elem(resultmap_fd, &key,
					  &retrieved_ancestor_pid);
		if (CHECK(err, "bpf_map_lookup_elem", "err %d errno %d\n", err,
			  errno))
			goto close_pmu;
		if (CHECK(retrieved_ancestor_pid != pid, "progenyof of parent",
			  "%d == %d\n", retrieved_ancestor_pid, pid))
			goto close_pmu;
	}

	// Test that a child of ours doesn't belong to our progeny
	bpf_map_update_elem(pidmap_fd, &key, &pid, 0);
	bpf_map_update_elem(resultmap_fd, &key, &nonexistant, 0);

	pipe(pipefd);
	child_pid = fork();
	if (child_pid == -1) {
		printf("fork failed\n");
		goto close_pmu;
	} else if (child_pid == 0) {
		close(pipefd[1]);
		read(pipefd[0], marker, 1);
		close(pipefd[0]);
		_exit(EXIT_SUCCESS);
	} else {
		close(pipefd[0]);

		bpf_map_update_elem(pidmap_fd, &ancestor_key, &child_pid, 0);

		root_fd = open("/", O_RDONLY);
		if (CHECK(efd < 0, "open", "errno %d\n", errno))
			goto close_prog;
		close(root_fd);

		write(pipefd[1], marker, 1);
		wait(NULL);
		close(pipefd[1]);

		err = bpf_map_lookup_elem(resultmap_fd, &key,
					  &retrieved_ancestor_pid);
		if (CHECK(err, "bpf_map_lookup_elem", "err %d errno %d\n", err,
			  errno))
			goto close_pmu;
		if (CHECK(retrieved_ancestor_pid != nonexistant, "progenyof of child",
			  "%d == %d\n", retrieved_ancestor_pid, 0))
			goto close_pmu;
	}

	exit_code = EXIT_SUCCESS;
	printf("%s:PASS\n", argv[0]);

close_pmu:
	close(pmu_fd);
close_prog:
	bpf_object__close(obj);
fail:
	return exit_code;
}
