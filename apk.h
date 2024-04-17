#include <stdint.h>


typedef struct {
    int32_t  id;
    int32_t  files_offset;
    int32_t  file_count;
    int32_t  dir_offset;
} APKHeader;


// starting from header.dir_offset
typedef struct {
    uint32_t  path_len;
    char     *path;  // read path_len bytes; zero terminated
    uint32_t  data_offset;
    uint32_t  data_size;
    uint32_t  next_entry_offset;
    uint32_t  unknown;  // crc hash?
} APKEntry;
