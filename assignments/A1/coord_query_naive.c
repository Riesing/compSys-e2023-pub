#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h> 
#include "record.h" 
#include "coord_query.h"

struct naive_data {
    struct record* records;
    int n;
};

// Function to calculate Euclidean distance between two points
double calculate_distance(double lon1, double lat1, double lon2, double lat2) {
    double dx = lon1 - lon2;
    double dy = lat1 - lat2;
    return sqrt(dx * dx + dy * dy);
}

struct naive_data* mk_naive(struct record* rs, int n) {
    struct naive_data* data = (struct naive_data*)malloc(sizeof(struct naive_data));
    if (data == NULL) {
        perror("Failed to allocate memory for naive_data");
        exit(EXIT_FAILURE);
    }
    data->records = rs;
    data->n = n;
    return data;
}


void free_naive(struct naive_data* data) {
    //free(data -> records);
    free(data);
}

// Find the closest record to the given coordinates
const struct record* lookup_naive(struct naive_data* data, double lon, double lat) {
    if (data == NULL || data->n == 0) {
        return NULL; 
    }

    const struct record* closest_record = &data->records[0];
    double closest_distance = calculate_distance(lon, lat, closest_record->lon, closest_record->lat);

    for (int i = 1; i < data->n; i++) {
        double distance = calculate_distance(lon, lat, data->records[i].lon, data->records[i].lat);
        if (distance < closest_distance) {
            closest_distance = distance;
            closest_record = &data->records[i];
        }
    }

    return closest_record;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <dataset_file>\n", argv[0]);
        return EXIT_FAILURE;
    }
    return coord_query_loop(argc, argv,
                                  (mk_index_fn)mk_naive,
                                  (free_index_fn)free_naive,
                                  (lookup_fn)lookup_naive);
}