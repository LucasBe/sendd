#ifndef _SEND_MISC_H
#define _SEND_MISC_H

#define PTR_INDEX_INC 2

struct s_ptr_index {
  unsigned int len;
  void **arr;
};

int ptr_index_init(struct s_ptr_index *index, unsigned int len);
int ptr_index_free(struct s_ptr_index *index);
int ptr_index_set(struct s_ptr_index *index, unsigned int i, void *data);
void *ptr_index_get(struct s_ptr_index *index, unsigned int i);

#endif /* _SEND_ADDR_H */
