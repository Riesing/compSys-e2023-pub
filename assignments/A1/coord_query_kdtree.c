#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h> 
#include "record.h" 
#include "coord_query.h"

struct kd_node {
    struct record* point;
    int axis;
    struct kd_node* left;
    struct kd_node* right;
};

// Function to calculate Euclidean distance between two points
double calculate_distance(double lon1, double lat1, double lon2, double lat2) {
    double dx = lon1 - lon2;
    double dy = lat1 - lat2;
    return sqrt(dx * dx + dy * dy);
}

// Function to create a kd_node for the k-d tree
struct kd_node* create_kd_node(struct record* point, int axis) {
    struct kd_node* node = (struct kd_node*)malloc(sizeof(struct kd_node));
    if (node == NULL) {
        perror("Failed to allocate memory for kd_node");
        exit(EXIT_FAILURE);
    }
    node->point = point;
    node->axis = axis;
    node->left = NULL;
    node->right = NULL;
    return node;
}

// Function to build the k-d tree recursively
struct kd_node* build_kd_tree(struct record* points, int n, int depth) {
    if (n == 0) {
        return NULL;
    }

    int axis = depth % 2; // Alternating between longitude (axis 0) and latitude (axis 1)
    int median_index = n / 2;

    // Sort points along the current axis
    qsort(points, n, sizeof(struct record), compare_records_by_axis(axis));

    // Create a kd_node for the median point
    struct kd_node* node = create_kd_node(&points[median_index], axis);

    // Recursively build left and right subtrees
    node->left = build_kd_tree(points, median_index, depth + 1);
    node->right = build_kd_tree(points + median_index + 1, n - median_index - 1, depth + 1);

    return node;
}

void kd_tree_lookup(struct kd_node* node, struct record** closest, double lon, double lat) {
    if (node == NULL) {
        return;
    }

    double current_distance = calculate_distance(lon, lat, node->point->lon, node->point->lat);
    double closest_distance = calculate_distance(lon, lat, (*closest)->lon, (*closest)->lat);

    if (current_distance < closest_distance) {
        *closest = node->point;
    }

    int axis = node->axis;
    double distance_to_splitting_plane = (axis == 0) ? (lon - node->point->lon) : (lat - node->point->lat);

    if (distance_to_splitting_plane <= 0) {
        kd_tree_lookup(node->left, closest, lon, lat);
    }

    if (distance_to_splitting_plane >= 0) {
        kd_tree_lookup(node->right, closest, lon, lat);
    }
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <dataset_file>\n", argv[0]);
        return EXIT_FAILURE;
    }
    return coord_query_loop(argc, argv,
                                  (mk_index_fn)NULL, // Pass NULL for mk_index_fn
                                  (free_index_fn)NULL, // Pass NULL for free_index_fn
                                  (lookup_fn)kd_tree_lookup);  
}
