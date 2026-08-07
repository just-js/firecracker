// Builds a joos-fire "slot" file: 8-byte little-endian length prefix +
// the input file's bytes + zero padding out to a fixed capacity. Must
// match write_slot() in build/firecracker-*/src/joos-fire/build.rs exactly
// - this exists so tools/patch_fire2.sh can rebuild a slot without needing
// cargo at all, for the objcopy --update-section hot-patch path.
//
// usage: pad_slot <input-file> <capacity> <output-file>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s <input-file> <capacity> <output-file>\n", argv[0]);
    return 1;
  }
  const char *in_path = argv[1];
  long capacity = atol(argv[2]);
  const char *out_path = argv[3];

  FILE *in = fopen(in_path, "rb");
  if (!in) { perror(in_path); return 1; }
  fseek(in, 0, SEEK_END);
  long size = ftell(in);
  fseek(in, 0, SEEK_SET);
  if (size < 0) { perror(in_path); return 1; }
  if (size > capacity) {
    fprintf(stderr, "%s: %ld bytes exceeds slot capacity of %ld bytes\n", in_path, size, capacity);
    return 1;
  }

  FILE *out = fopen(out_path, "wb");
  if (!out) { perror(out_path); return 1; }

  unsigned char len_bytes[8];
  for (int i = 0; i < 8; i++) {
    len_bytes[i] = (unsigned char)((size >> (i * 8)) & 0xff);
  }
  fwrite(len_bytes, 1, 8, out);

  char buf[65536];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
    fwrite(buf, 1, n, out);
  }
  fclose(in);

  long padding = capacity - size;
  memset(buf, 0, sizeof(buf));
  while (padding > 0) {
    size_t chunk = padding < (long)sizeof(buf) ? (size_t)padding : sizeof(buf);
    fwrite(buf, 1, chunk, out);
    padding -= chunk;
  }
  fclose(out);
  return 0;
}
