#include <unistd.h>

#include "config.h"
#include <applog.h>

#include "sendd_local.h"
#include "misc.h"

int ptr_index_init(struct s_ptr_index *index, unsigned int len)
{
  int i;

  index->len = len;
	if ((index->arr = malloc(sizeof(void *) * index->len)) == NULL) {
    index->len = 0;
		APPLOG_NOMEM();
		return FAILURE;
	}
  for(i = 0; i < index->len; ++i)
    index->arr[i] = NULL;

  //printf("%s: len = %d\n", __FUNCTION__, index->len);
  return SUCCESS;
}

int ptr_index_free(struct s_ptr_index *index)
{
  free(index->arr);
  return SUCCESS;
}

int ptr_index_set(struct s_ptr_index *index, unsigned int i, void *data)
{
  if(i >= index->len) {
    index->len = i * PTR_INDEX_INC;
  	if ((index->arr = realloc(index->arr, sizeof(void *) * index->len)) == NULL) {
      index->len = 0;
  		APPLOG_NOMEM();
  		return FAILURE;
  	}    
  }
  index->arr[i] = data;
  //printf("%s: len = %d, set = %d\n", __FUNCTION__, index->len, i);
  return SUCCESS;
}

void *ptr_index_get(struct s_ptr_index *index, unsigned int i)
{
  if(i >= index->len) {
    return NULL;
  }
  return index->arr[i];
}
