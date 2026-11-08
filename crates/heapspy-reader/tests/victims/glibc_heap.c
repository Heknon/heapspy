/* The victim of tests/native_heap_live.rs in C, for glibc releases that
 * CPython no longer runs on (the glibc workflow builds it inside each
 * distro image and passes it as HEAPSPY_VICTIM).
 *
 * Like the Python victim: mallocs buffers on the brk heap, mmapped chunks
 * and in a second thread's arena, fills them, writes "addr size kind"
 * lines to argv[1] (through a rename, so the file appears whole) and
 * sleeps. It frees a few small chunks first, so the tcache (2.26+) and
 * the fastbins hold entries.
 *
 *   gcc -O0 -o victim glibc_heap.c -lpthread
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static FILE *out;
static pthread_mutex_t ready = PTHREAD_MUTEX_INITIALIZER;

static void grab(size_t size, const char *where)
{
	void *p = malloc(size);

	memset(p, 0xab, size);
	fprintf(out, "%lu %lu %s\n", (unsigned long)p, (unsigned long)size, where);
}

static void *worker(void *arg)
{
	(void)arg;
	grab(3000, "thread");
	pthread_mutex_unlock(&ready);
	for (;;)
		sleep(1);
	return NULL;
}

int main(int argc, char **argv)
{
	char tmp[4096];
	pthread_t t;
	void *junk[16];
	size_t i;

	if (argc != 2)
		return 2;
	snprintf(tmp, sizeof tmp, "%s.tmp", argv[1]);
	out = fopen(tmp, "w");
	if (!out)
		return 1;
	for (i = 0; i < 16; i++)
		junk[i] = malloc(24 + 16 * (i % 4));
	for (i = 0; i < 16; i += 2)
		free(junk[i]);
	/* brk heap (below the 128 KiB mmap threshold), then mmapped chunks. */
	grab(24, "main");
	grab(200, "main");
	grab(5000, "main");
	grab(100000, "main");
	grab(1 << 20, "mmap");
	grab(8 << 20, "mmap");
	/* The worker writes its line, then unlocks; the second lock waits. */
	pthread_mutex_lock(&ready);
	if (pthread_create(&t, NULL, worker, NULL) != 0)
		return 1;
	pthread_mutex_lock(&ready);
	fclose(out);
	rename(tmp, argv[1]);
	for (;;)
		sleep(1);
}
