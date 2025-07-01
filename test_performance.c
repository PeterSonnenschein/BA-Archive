#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>

double run_test(void)
{
	clock_t start = clock();
	size_t page_size = 1 << 12;
	size_t block_size = 1UL << 34;
	char *buf = malloc(page_size);
	char filename[] = "testfile_XXXXXX";

	memset(buf, 0xAA, page_size);
	
	int fd = mkstemp(filename);
	if (fd < 0) {
		printf("error creating file\n");
		return -1;
	}

	size_t written = 0;
	while (written < block_size) {
		written += write(fd, buf, page_size);
	}

	lseek(fd, 0, SEEK_SET);
	
	size_t read_total = 0;
	while (read_total < block_size) {
		read_total += read(fd, buf, page_size);
	}
	close(fd);
	remove(filename);
	
	clock_t end = clock();

	double time = (double) (end - start) / CLOCKS_PER_SEC;

	printf("Program took: %lf seconds to execute \n", time);

	posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);

	return time;
}

int main(void)
{
	double res;

	for (int i = 0; i < 20; i++) {
		double temp = run_test();
		if (temp < 0){
			printf("error received\n");
			return 0;
		} else {
			res += temp;
		}
	}

	printf("The execution time average of 20 runs: %lf seconds\n", (res / 20));

	return 0;
}