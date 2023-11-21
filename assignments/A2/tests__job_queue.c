#include <stdio.h>
#include <assert.h>
#include <pthread.h>
#include "job_queue.h"
#include "job_queue.c"

// Function to test the job_queue initialization
void test_job_queue_init() {
    struct job_queue job_q;
    int capacity = 10;

    int result = job_queue_init(&job_q, capacity);

    assert(result == 0);
    assert(job_q.capacity == capacity);
    assert(job_q.size == 0);

    job_queue_destroy(&job_q);
}

// Function to test job_queue_push and job_queue_pop
void test_job_queue_push_pop() {
    struct job_queue job_q;
    int capacity = 5;
    job_queue_init(&job_q, capacity);

    int data[] = {1, 2, 3, 4, 5};
    int* popped_data;

    for (int i = 0; i < capacity; i++) {
        job_queue_push(&job_q, &data[i]);
    }

    // Test pushing when the queue is full
    int result = job_queue_push(&job_q, &data[0]);
    assert(result == -1);

    for (int i = 0; i < capacity; i++) {
        job_queue_pop(&job_q, (void**)&popped_data);
        assert(*popped_data == data[i]);
    }

    // Test popping when the queue is empty
    result = job_queue_pop(&job_q, (void**)&popped_data);
    assert(result == -1);

    job_queue_destroy(&job_q);
}

int main() {
    test_job_queue_init();
    test_job_queue_push_pop();
    
    printf("All tests passed!\n");

    return 0;
}
