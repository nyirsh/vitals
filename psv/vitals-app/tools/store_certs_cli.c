/* make update-certs' merge (shared/tools/update_certs.py): Mozilla's bundle without the certificates Sony's
 * list already has, with the code the app writes the store with (../../../shared/src/store_certs.c).
 * Arguments: sony.pem mozilla.pem output; nothing is written when it fails */

#include "vitals/store_certs.h"

#include <stdio.h>
#include <stdlib.h>

static char *read_all(const char *path, size_t *length)
{
	FILE *file = fopen(path, "rb");
	char *data = NULL;
	long size;
	if (file != NULL && fseek(file, 0, SEEK_END) == 0 && (size = ftell(file)) >= 0 && fseek(file, 0, SEEK_SET) == 0 &&
	    (data = malloc((size_t)size + 1)) != NULL && fread(data, 1, (size_t)size, file) == (size_t)size) {
		data[size] = '\0';
		*length = (size_t)size;
	} else {
		free(data);
		data = NULL;
	}
	if (file != NULL)
		fclose(file);
	return data;
}

int main(int argc, char **argv)
{
	size_t sony_length = 0, mozilla_length = 0, length = 0;
	if (argc != 4)
		return 2;
	char *sony = read_all(argv[1], &sony_length), *mozilla = read_all(argv[2], &mozilla_length);
	char *out = mozilla != NULL ? malloc(mozilla_length + 1) : NULL;
	VitalsStoreFilter filter;
	int rc = 1;
	if (sony != NULL && out != NULL &&
	    vitals_store_mozilla(mozilla, mozilla_length, sony, sony_length, out, mozilla_length + 1, &length, &filter) == 0) {
		FILE *file = fopen(argv[3], "wb");
		if (file != NULL) {
			rc = fwrite(out, 1, length, file) == length ? 0 : 1;
			if (fclose(file) != 0)
				rc = 1;
		}
		printf("kept=%u sony=%u\n", filter.kept, filter.sony);
	}
	free(sony);
	free(mozilla);
	free(out);
	return rc;
}
