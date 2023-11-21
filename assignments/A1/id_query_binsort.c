#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include "record.h"
#include "id_query.h"

struct index_record {
int64_t osm_id;
const struct record *record;
};

struct indexed_data {
    struct index_record *irs;
    int n;
};


int sortq(const void* a, const void* b) {
    struct index_record* ar = (struct index_record* )a;
    struct index_record* br = (struct index_record* )b;

    if (ar->osm_id == br->osm_id) {
        return 0;
    }
    else if (ar->osm_id > br->osm_id) {
        return 1;
    }
    else if (ar->osm_id < br->osm_id) {
        return -1;
    }
    assert(0);
}


struct indexed_data* mk_indexed(struct record* rs, int n) {
    struct indexed_data* data = (struct indexed_data*)malloc(sizeof(struct indexed_data));
    if (data == NULL) {
        perror("Failed to allocate memory for indexed_data");
        exit(EXIT_FAILURE);
    }
    data -> irs = (struct index_record*)malloc(n*sizeof(struct index_record));
    if (data -> irs == NULL) {
        perror("Failed to allocate memory for index_record array in indexed_data");
        free(data);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < n; i++) {
        data -> irs[i].osm_id = rs[i].osm_id;
        data -> irs[i].record = &rs[i]; 
    }

    qsort(data->irs, n, sizeof(struct index_record), sortq);

    data ->n = n; 
    return data;
}

void free_indexed(struct indexed_data* data){
    free(data -> irs);
    free(data);
}

const struct record* lookup_indexed(struct indexed_data *data,int64_t needle) {
    // Initializing left and right in the binary search
    int lb = 0;
    int rb = data -> n - 1;
    
    while (lb <= rb) {
        // Initializing the middle value in the binary search
        int mb = lb + (rb - lb)/2;

        if (data -> irs[mb].osm_id == needle) {
            return data -> irs[mb].record;
        }

        if (data -> irs[mb].osm_id > needle) {
            rb = mb - 1;
        }

        else {
            lb = mb + 1;
        }
    }
    
    return NULL;
}



int main(int argc, char** argv) {
  return id_query_loop(argc, argv,
                    (mk_index_fn)mk_indexed,
                    (free_index_fn)free_indexed,
                    (lookup_fn)lookup_indexed);
}
