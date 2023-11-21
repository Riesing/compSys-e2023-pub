#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "job_queue.h"




int job_queue_init(struct job_queue *job_queue, int capacity) {
  
  if (capacity <= 0) {
    return -1;
  }

  job_queue -> data = malloc(sizeof(void*) * capacity);

  if (job_queue -> data == NULL) {
    return -1;
  }

  job_queue-> capacity = capacity;
  job_queue -> size = 0;
  job_queue -> dest = 0;

  pthread_mutex_init(&job_queue -> mutex, NULL);

  pthread_cond_init(&job_queue -> not_empty, NULL);

  pthread_cond_init(&job_queue -> not_full, NULL);

  pthread_cond_init(&job_queue -> destroy, NULL);

  return 0;
}



int job_queue_destroy(struct job_queue *job_queue) {
  
  pthread_mutex_lock(&job_queue -> mutex);

  job_queue -> dest = 1;

  while (job_queue -> size > 0) {
    pthread_cond_broadcast(&job_queue -> not_empty);
    pthread_cond_wait(&job_queue -> destroy, &job_queue -> mutex);
  }

  pthread_cond_destroy(&job_queue -> not_empty);

  pthread_cond_destroy(&job_queue -> not_full);

  pthread_mutex_unlock(&job_queue -> mutex);

  pthread_mutex_destroy(&job_queue -> mutex);

  free(job_queue -> data);

  return 0;
}



int job_queue_push(struct job_queue *job_queue, void *data) {

  pthread_mutex_lock(&job_queue -> mutex);
  
  while (job_queue -> size >= job_queue -> capacity) {
    pthread_cond_wait(&job_queue -> not_full, &job_queue -> mutex);
  }

  if (data == NULL) {
    pthread_cond_signal(&job_queue -> destroy);
  } else {
    job_queue -> data[job_queue -> size] = data; 
    job_queue -> size++;
    pthread_cond_signal(&job_queue -> not_empty);
  }

  pthread_mutex_unlock(&job_queue -> mutex);

  return 0;
}

int job_queue_pop(struct job_queue *job_queue, void **data) {

  pthread_mutex_lock(&job_queue -> mutex);

  while (job_queue -> size <= 0) {
    if (job_queue -> dest == 1) {
      break;
    }
    pthread_cond_wait(&job_queue -> not_empty, &job_queue -> mutex);
  }

  if (job_queue -> size > 0) {
    *data = job_queue -> data[0];

    for (int i = 0; i < job_queue -> size; i++) {
      job_queue -> data[i] = job_queue -> data[i+1];
    }
    
    job_queue -> size--;
  }

  if (job_queue -> size <= 0 && job_queue -> dest == 1) {
    pthread_mutex_unlock(&job_queue -> mutex);
    pthread_cond_signal(&job_queue -> destroy);
    return -1;
  }
  
  pthread_mutex_unlock(&job_queue -> mutex);
  
  pthread_cond_signal(&job_queue -> not_full);

  return 0;
}