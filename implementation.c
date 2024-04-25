#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>


/* Definitions and type declarations */

#define MYFS_MAGIC ((uint32_t)0xcafebebe)
#define BLOCK_SIZE ((size_t)1024)

typedef unsigned int u_int;

// END of definitions and type declarations

/* Definitions and type declarations */

//#define ((size_t)255) ((size_t)255)

typedef size_t __myfs_off_t;



typedef struct {
  size_t size_left;
  __myfs_off_t next_space;
} node_struct_t;

typedef struct {
  __myfs_off_t first_space;
} list_node_t;


typedef struct {
  uint32_t magic;
  size_t size;
  __myfs_off_t root_dir;
  __myfs_off_t free_memory;
 
} myfs_handle_struct_t;

typedef struct {
  size_t size;
  size_t allocated;
  __myfs_off_t data;
  __myfs_off_t next_file_block;
} myfs_file_block_struct_t;

typedef struct {
  size_t total_size;
  __myfs_off_t first_file_block;  // This is an offset to the first myfs_file_block_struct_t
} file_t;

typedef struct {
  // Max number of children is given at the children array location -
  // sizeof(size_t) divided by the sizeof(__myfs_off_t)
  size_t max_num_children;
  // children is an offset to an array of offsets to folders and files. Children
  // starts with '..' offsets
  __myfs_off_t children;
} directory_t;

typedef struct {
  char name[((size_t)255) + ((size_t)1)];
  char is_file;
  // times[0]: last access date, times[1]: last modification date
  struct timespec times[2];
  union {
    file_t file;
    directory_t directory;
  } type;
} node_t;

// END OF STRUCTS

/* START memory allocation helper functions declarations */

void *__malloc_impl(void *fsptr, void *pref_ptr, size_t *size);
void *__realloc_impl(void *fsptr, void *orig_ptr, size_t *size);
void __free_impl(void *fsptr, void *ptr);

// END memory allocation functions

/* START fuse helper functions */

void *off_to_ptr(void *reference, __myfs_off_t offset);
__myfs_off_t ptr_to_off(void *reference, void *ptr);
void update_time(node_t *node, int new_node);
void *get_free_memory_ptr(void *fsptr);
void initilaize_check(void *fsptr, size_t fssize);
char *get_last_token(const char *path, unsigned long *token_len);
char **tokenize(const char token, const char *path, int skip_n_tokens);
void free_tokens(char **tokens);
node_t *get_node(void *fsptr, directory_t *dict, const char *child);
node_t *path_solver(void *fsptr, const char *path, int skip_n_tokens);
node_t *make_inode(void *fsptr, const char *path, int *errnoptr, int isfile);
void free_file_info(void *fsptr, file_t *file);
void remove_node(void *fsptr, directory_t *dict, node_t *node);
void remove_data(void *fsptr, myfs_file_block_struct_t *block, size_t size);
int add_data(void *fsptr, file_t *file, size_t size, int *errnoptr);

/* START memory allocation implementations */

void add_allocation_space(void *fsptr, list_node_t *LL, node_struct_t *alloc) {
    // Initialize variables
    node_struct_t *temp = NULL;
    __myfs_off_t curr_off = LL->first_space;
    __myfs_off_t alloc_off = ptr_to_off(fsptr, alloc);

    // Find the correct position to insert alloc
    while (curr_off != 0 && curr_off < alloc_off) {
        temp = off_to_ptr(fsptr, curr_off);
        curr_off = temp->next_space;
    }

    // Merge if possible
    if (temp != NULL && (curr_off == alloc_off + sizeof(size_t) + alloc->size_left)) {
        alloc->size_left += sizeof(size_t) + temp->size_left;
        alloc->next_space = temp->next_space;
    } else {
        alloc->next_space = curr_off;
    }

    // If temp exists, update its next_space
    if (temp != NULL) {
        temp->next_space = ptr_to_off(fsptr, alloc);
    } else {
        LL->first_space = ptr_to_off(fsptr, alloc);
    }
}

void extend_pref_block(void *fsptr, node_struct_t *before_pref,
                       node_struct_t *org_pref, __myfs_off_t pref_off,
                       size_t *size) {
  node_struct_t *pref = off_to_ptr(fsptr, pref_off);
  node_struct_t *temp;

  // Check if you can get all size bytes from the prefer block
  if (pref->size_left >= *size) {
    // Check if we can make an node_struct_t object with the size_left space
    if (pref->size_left > *size + sizeof(node_struct_t)) {
      // Make the new node_struct_t object
      temp = ((void *)pref) + *size;
      temp->size_left = pref->size_left - *size;
      temp->next_space = pref->next_space;

      // Set original pref with final total size
      org_pref->size_left += *size;

      // Update pointers to add temp into list of free blocks
      before_pref->next_space = pref_off + *size;
    }
    // We can't make an node_struct_t object
    else {
      // Add everything that the prefer block have into the original one
      org_pref->size_left += pref->size_left;

      // Update pointers so the one that was pointing to the prefer free block
      // is now pointing to the next free
      before_pref->next_space = pref->next_space;
    }
    *size = ((__myfs_off_t)0);
  }
  // We couldn't got everything from the prefer block so we get as much as we
  // can from it
  else {
    // Add everything that the prefer block have into the original one
    org_pref->size_left += pref->size_left;

    // Update pointers so the one that was pointing to the prefer free block is
    // now pointing to the next free
    before_pref->next_space = pref->next_space;

    // Update size because we have gotten some space
    *size -= pref->size_left;
  }
}

/* Check if the offset for pref_ptr is 0, if so we get any block for size,
 * otherwise we try to find the block after it and get as much from it as
 * possible and get the rest from the largest block
 */
void *get_allocation(void *fsptr, list_node_t *LL, node_struct_t *org_pref,
                     size_t *size) {
  // There is no guarantee that its offset is not 0, if so, we don't consider it
  __myfs_off_t pref_off = ((__myfs_off_t)0);

  // Before current space
  __myfs_off_t before_temp_off;
  node_struct_t *before_temp;

  // current space
  __myfs_off_t temp_off;
  node_struct_t *temp;

  // Largest block variables
  node_struct_t *before_largest = NULL;
  __myfs_off_t largest_off;
  node_struct_t *largest;
  size_t largest_size;

  // Use this ptr if a new block needs to be return
  node_struct_t *ptr = NULL;

  // Save first space
  before_temp_off = LL->first_space;

  // If before_temp have an offset of zero we have use all possible space in
  // memory
  if (!before_temp_off) {
    return NULL;
  }

  // Check that size is at least a sizeof(__myfs_off_t)
  if (*size < sizeof(node_struct_t)) {
    *size = sizeof(node_struct_t);
  }

  if (((void *)org_pref) != fsptr) {
    pref_off =
        ptr_to_off(fsptr, org_pref) + sizeof(size_t) + org_pref->size_left;
    // Check that the first block is the prefer one or not
    if (pref_off == before_temp_off) {
      extend_pref_block(fsptr, ((void *)LL) - sizeof(size_t), org_pref,
                        pref_off, size);
      if (*size == ((size_t)0)) {
        return NULL;
      }
    }
  }

  // We currently have before_temp as our largest block
  before_temp_off = LL->first_space;
  before_temp = off_to_ptr(fsptr, before_temp_off);
  largest_off = before_temp_off;
  largest = before_temp;
  largest_size = before_temp->size_left;

  // Get next space
  temp_off = before_temp->next_space;

  // Iterate the list until the first block that can hold size and the block
  // after pref_ptr is found (or pass because it is not there)
  while (temp_off != ((__myfs_off_t)0)) {
    // The offset is to get after the size_t so we readjust it
    temp = off_to_ptr(fsptr, temp_off);
    // Check if temp_off is the prefer block that we are looking for or if temp
    // have more space available than the previous largest
    if ((pref_off == temp_off) || (temp->size_left > largest_size)) {
      // If temp_off is pref we would not like to update largest space so we
      // have two places to get space from
      if (pref_off == temp_off) {
        // pref_found was successfully found
        extend_pref_block(fsptr, before_temp, org_pref, pref_off, size);
        if (size == ((__myfs_off_t)0)) {
          break;
        }
      }
      // Update largest space
      else {
        before_largest = before_temp;
        largest_off = temp_off;
        largest = temp;
        largest_size = temp->size_left;
      }
    }
    // Update pointers to next space
    before_temp_off = temp_off;
    before_temp = temp;
    temp_off = temp->next_space;
  }

  // If size is still not 0 we get as much as we can from it or until size is 0
  if ((*size != ((__myfs_off_t)0)) && (largest != NULL)) {
    ptr = largest;
    // Check if the largest block can give everything that we are missing
    if (largest->size_left >= *size) {
      // Check if we can make an node_struct_t object after getting size bytes
      // from it
      if (largest->size_left > *size + sizeof(node_struct_t)) {
        // Make the new node_struct_t object
        temp = ((void *)largest) + sizeof(size_t) + *size;  //
        temp->size_left = largest->size_left - *size - sizeof(size_t);
        temp->next_space = largest->next_space;
        // Update before_largest pointer, it may be the LL or a node_struct_t
        if (before_largest == NULL) {
          // before_largest is the LL
          LL->first_space = largest_off + *size + sizeof(size_t);
        } else {
          // Update pointers to add temp list of free blocks
          before_largest->next_space = largest_off + *size + sizeof(size_t);
        }
        // Set original pref with final total size
        ptr->size_left = *size;
      }
      // We can't make an node_struct_t object so we get everything
      else {
        // Use everything that the largest block have
        if (before_largest != NULL) {
          before_largest->next_space = largest->next_space;
        } else {
          // Because largest is the first block and we use everything, it means
          // that the system have no memory left
          LL->first_space = ((__myfs_off_t)0);
        }
      }
      *size = ((__myfs_off_t)0);
    }
    // We couldn't got everything from the largest block so we get as much as we
    // can from it
    else {
      // Update pointers
      if (before_largest == NULL) {
        // We had use everything and we still didn't got enough size
        return NULL;
      } else {
        before_largest->next_space = largest->next_space;
        // Update size
        *size -= largest->size_left;
      }
    }
  }

  // We suppose to return the new block address if a new block outside the
  // prefer one was needed
  if (ptr == NULL) {
    return NULL;
  }
  return ((void *)ptr) + sizeof(size_t);  // ptr was set to the largest which is
                                          // at the size_t header so we resize
}

/* If size is zero, return NULL. Otherwise, call get_allocation with size. */
void *__malloc_impl(void *fsptr, void *pref_ptr, size_t *size) {
      //null size
      if (*size == ((size_t)0)) {
            return NULL;
      }

      // null preference
      if (pref_ptr == NULL) {
            pref_ptr = fsptr + sizeof(size_t);
      }

      //allocation size 
      return get_allocation(fsptr, get_free_memory_ptr(fsptr),
                              pref_ptr - sizeof(size_t), size);
}

/* If size is less than what already assign to *ptr just lock what is after size
 * and add it using add_allocation_space. */
void *__realloc_impl(void *fsptr, void *orig_ptr, size_t *size) {
  // If size is 0, we free the ptr and return NULL
  if (*size == ((size_t)0)) {
    __free_impl(fsptr, orig_ptr);
    return NULL;
  }

  list_node_t *LL = get_free_memory_ptr(fsptr);

  // If ptr is fsptr if the offset was 0 (kind of pointing to null), realloc()
  // is identical to a call to malloc() for size bytes.
  if (orig_ptr == fsptr) {
    // fsptr because we don't have a preference over the location of the pointer
    // that would be returned, (offset of 0).
    return get_allocation(fsptr, LL, fsptr, size);
  }

  node_struct_t *alloc =
      (node_struct_t *)(((void *)orig_ptr) - sizeof(size_t));
  node_struct_t *temp;
  void *new_ptr = NULL;

  // If the new size is less than before but not enough to make an
  // node_struct_t object
  if ((alloc->size_left >= *size) &&
      (alloc->size_left < (*size + sizeof(node_struct_t)))) {
    // No new ptr was created
    new_ptr = orig_ptr;
  }
  // If the new size is less than before and we can create an node_struct_t
  // element to add to LL
  else if (alloc->size_left > *size) {
    // Save what is left in temp and add it to the LL
    temp = (node_struct_t *)(orig_ptr + *size);
    temp->size_left = alloc->size_left - *size - sizeof(size_t);
    temp->next_space = 0;  // Offset of zero
    add_allocation_space(fsptr, LL, temp);
    // Update size_left space
    alloc->size_left = *size;
    // No new ptr was created
    new_ptr = orig_ptr;
  }
  // If we are asking for more than what we have in alloc
  else {
    // Get new space to copy to
    new_ptr = get_allocation(fsptr, LL, fsptr, size);
    // We couldn't get enough space
    if (*size != 0) {
      return NULL;
    }
    // Copy what was inside orig_ptr into new_ptr
    memcpy(new_ptr, orig_ptr, alloc->size_left);  // memcpy(dst,src,len)
    // Free the space of the original pointer
    add_allocation_space(fsptr, LL, alloc);
  }

  return new_ptr;
}

//Free Implementation
//Adds memory to the list using add_allocation
void __free_impl(void *fsptr, void *ptr) {
      //if already null do not need to free
      if (ptr == NULL) {
            return;
      }

      //creates new block with adjusted pointer size
      add_allocation_space(fsptr, get_free_memory_ptr(fsptr), ptr - sizeof(size_t));
}


/* END memory allocation implementation */

/* START of FUSE implementation */

/* HELPER FUNCTIONS implementations */
void *off_to_ptr(void *fsptr, __myfs_off_t offset) {
  // Cast the void pointer to a character pointer for byte-level arithmetic
  char *base_ptr = (char *)fsptr;
  char *result_ptr = base_ptr + offset;

  // check to make sure it is in bounds (overflow detection)
  if (result_ptr < base_ptr || result_ptr > base_ptr + offset) {
    return NULL; 
  }

  return result_ptr;
}

__myfs_off_t ptr_to_off(void *fsptr, void *ptr) {
  // Check that the reference point is before the pass pointer
  if (fsptr > ptr) {
    return 0;
  }

  return ((__myfs_off_t)(ptr - fsptr));
}

void update_time(node_t *node, int set_mod) {
  if (node == NULL) {
    return;
  }

  struct timespec ts;

  if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
    node->times[0] = ts;
    if (set_mod) {
      node->times[1] = ts;
    }
  }
}

void *get_free_memory_ptr(void *fsptr) {
  return &((myfs_handle_struct_t *)fsptr)->free_memory;
}

void initilaize_check(void *fsptr, size_t fssize) {
  myfs_handle_struct_t *handle = ((myfs_handle_struct_t *)fsptr);

  // If we are mounting the file system for the first time
  if (handle->magic != MYFS_MAGIC) {
    // Set general stats
    handle->magic = MYFS_MAGIC;
    handle->size = fssize;

    // Save space for root directory
    // root directory is a node_t variable that starts after the myfs_handle_struct_t
    // object at the beginning of our file system
    handle->root_dir = sizeof(myfs_handle_struct_t);  // Only store the offset
    node_t *root = off_to_ptr(fsptr, handle->root_dir);

    // Set the root directory to be name '/' with 4 children where the parent is
    // NULL
    memset(root->name, '\0',
           ((size_t)255) + ((size_t)1));  // File all name characters to '\0'
    memcpy(
        root->name, "/",
        strlen(
            "/"));  // Copy given name into node->name, memcpy(dst,src,n_bytes)
    update_time(root, 1);
    root->is_file = 0;
    directory_t *dict = &root->type.directory;
    dict->max_num_children =
        ((size_t)1);  // We use the first child space for '..'

    // Root children start after the root node and we first set the header of
    // the block with the amount of children
    size_t *children_size =
        off_to_ptr(fsptr, handle->root_dir + sizeof(node_t));
    *children_size = 4 * sizeof(__myfs_off_t);
    dict->children =
        ptr_to_off(fsptr, ((void *)children_size) + sizeof(size_t));
    __myfs_off_t *ptr = off_to_ptr(fsptr, dict->children);
    // Root parent doesn't exist so we set it to 0
    *ptr = 0;

    // Set the initilaize_check free_block pointer
    handle->free_memory = dict->children + *children_size;
    list_node_t *LL = get_free_memory_ptr(fsptr);
    node_struct_t *fb = (off_to_ptr(fsptr, LL->first_space));

    // Set everything on memory to be 0 starting at the first free block +
    // sizeof(size_t)
    fb->size_left = fssize - handle->free_memory - sizeof(size_t);
    memset(((void *)fb) + sizeof(size_t), 0, fb->size_left);
  }
}

char *get_last_token(const char *path, unsigned long *token_len) {
  unsigned long len = strlen(path);
  unsigned long index;

  // Find last '/' in path, worst case scenario, the first '/' is the root
  // directory at idx = 0
  for (index = len - 1; index > 0; index--) {
    if (path[index] == '/') break;
  }

  // index is at '/' but we want to start a character after it
  index++;

  // Set the length of the last node
  *token_len = len - index;

  // Make a copy of the last token
  void *ptr = malloc((*token_len + 1) * sizeof(char));

  // Check that malloc was successful
  if (ptr == NULL) {
    return NULL;
  }

  char *copy = (char *)ptr;
  strcpy(copy, &path[index]);  // strcpy(dst,src)

  // Add null character to terminate the string
  copy[*token_len] = '\0';

  return copy;
}

char **tokenize(const char token, const char *path, int skip_n_tokens) {
  int n_tokens = 0;
  for (const char *c = path; *c != '\0'; c++) {
    if (*c == token) {
      n_tokens++;
    }
  }
  // n_tokens value would be of at least 1 because of root directory
  // Do not tokenize the last skip_n_tokens
  n_tokens -= skip_n_tokens;

  char **tokens = (char **)malloc(((u_int)(n_tokens + 1)) * sizeof(char *));
  const char *start = &path[1];  // Jump the first character which is '\'
  const char *end = start;
  char *t;

  // Populate tokens
  for (int i = 0; i < n_tokens; i++) {
    while ((*end != token) && (*end != '\0')) {
      end++;
    }
    // Make space for the token
    t = (char *)malloc((((u_int)(end - start)) + ((u_int)1)) * sizeof(char));
    // Copy token
    memcpy(t, start, ((size_t)(end - start)));
    t[end - start] = '\0';
    tokens[i] = t;
    start = ++end;
  }
  // Make array null terminated
  tokens[n_tokens] = NULL;

  return tokens;
}

void free_tokens(char **tokens) {
  for (char **p = tokens; *p; p++) free(*p);
  free(tokens);
}

node_t *get_node(void *fsptr, directory_t *dict, const char *child) {
  size_t n_children = dict->max_num_children;
  __myfs_off_t *children = off_to_ptr(fsptr, dict->children);
  node_t *node = NULL;

  // Check if we need to go the parent directory
  if (strcmp(child, "..") == 0) {
    return ((node_t *)off_to_ptr(fsptr, children[0]));
  }

  // We start from the second children because the first one is ".." (parent)
  for (size_t i = ((size_t)1); i < n_children; i++) {
    node = ((node_t *)off_to_ptr(fsptr, children[i]));
    if (strcmp(node->name, child) == 0) {
      return node;
    }
  }
  return NULL;
}

node_t *path_solver(void *fsptr, const char *path, int skip_n_tokens) {
  // Check if the path start at the root directory
  if (*path != '/') {
    return NULL;
  }

  // Get root directory
  node_t *node = off_to_ptr(fsptr, ((myfs_handle_struct_t *)fsptr)->root_dir);

  // If we only have "/" as the path, we return the root
  if (path[1] == '\0') {
    return node;
  }

  // Break path into tokens
  char **tokens = tokenize('/', path, skip_n_tokens);

  for (char **token = tokens; *token; token++) {
    // Files cannot have children
    if (node->is_file) {
      free_tokens(tokens);
      return NULL;
    }
    // If token is "." we stay on the same directory
    if (strcmp(*token, ".") != 0) {
      node = get_node(fsptr, &node->type.directory, *token);
      // Check that the child was successfully retrieved
      if (node == NULL) {
        free_tokens(tokens);
        return NULL;
      }
    }
  }

  free_tokens(tokens);

  return node;
}

node_t *make_inode(void *fsptr, const char *path, int *errnoptr, int isfile) {
  // Call path solver without the last node name because that is the file name
  // if valid path name is given
  node_t *parent_node = path_solver(fsptr, path, 1);

  // Check that the file parent exist
  if (parent_node == NULL) {
    *errnoptr = ENOENT;
    return NULL;
  }

  // Check that the node returned is a directory
  if (parent_node->is_file) {
    *errnoptr = ENOTDIR;
    return NULL;
  }

  // Get directory from node
  directory_t *dict = &parent_node->type.directory;

  // Get last token which have the filename
  unsigned long len;
  char *new_node_name = get_last_token(path, &len);

  // Check that the parent doesn't contain a node with the same name as the one
  // we are about to create
  if (get_node(fsptr, dict, new_node_name) != NULL) {
    *errnoptr = EEXIST;
    return NULL;
  }

  if (len == 0) {
    *errnoptr = ENOENT;
    return NULL;
  }

  if (len > ((size_t)255)) {
    *errnoptr = ENAMETOOLONG;
    return NULL;
  }

  __myfs_off_t *children = off_to_ptr(fsptr, dict->children);
  node_struct_t *block = (((void *)children) - sizeof(size_t));

  // Make the node and put it in the directory child list
  //  First check if the directory list have free places to added nodes to
  //   Amount of memory allocated doesn't count the sizeof(size_t) as withing
  //   the available size
  size_t max_children = (block->size_left) / sizeof(__myfs_off_t);
  size_t ask_size;
  if (max_children == dict->max_num_children) {
    ask_size = block->size_left * 2;
    // Make more space for another children
    void *new_children = __realloc_impl(fsptr, children, &ask_size);

    //__realloc_impl() always returns a new pointer if ask_size == 0, otherwise
    // we don't have enough space in memory
    if (ask_size != 0) {
      *errnoptr = ENOSPC;
      return NULL;
    }

    // Update offset to access the children
    dict->children = ptr_to_off(fsptr, new_children);
    children = ((__myfs_off_t *)new_children);
  }

  ask_size = sizeof(node_t);
  node_t *new_node = (node_t *)__malloc_impl(fsptr, NULL, &ask_size);
  if ((ask_size != 0) || (new_node == NULL)) {
    __free_impl(fsptr, new_node);
    *errnoptr = ENOSPC;
    return NULL;
  }
  memset(new_node->name, '\0',
         ((size_t)255) + ((size_t)1));  // File all name characters to '\0'
  memcpy(new_node->name, new_node_name,
         len);  // Copy given name into node->name, memcpy(dst,src,n_bytes)
  update_time(new_node, 1);

  // Add file node to directory children
  children[dict->max_num_children] = ptr_to_off(fsptr, new_node);
  dict->max_num_children++;
  update_time(parent_node, 1);

  if (isfile) {
    // Make a node for the file with size of 0
    new_node->is_file = 1;
    file_t *file = &new_node->type.file;
    file->total_size = 0;
    file->first_file_block = 0;
  } else {
    // Make a node for the file with size of 0
    new_node->is_file = 0;
    dict = &new_node->type.directory;
    dict->max_num_children =
        ((size_t)1);  // We use the first child space for '..'

    // Call __malloc_impl() to get enough space for 4 children
    ask_size = 4 * sizeof(__myfs_off_t);
    __myfs_off_t *ptr = ((__myfs_off_t *)__malloc_impl(fsptr, NULL, &ask_size));
    if ((ask_size != 0) || (ptr == NULL)) {
      __free_impl(fsptr, ptr);
      *errnoptr = ENOSPC;
      return NULL;
    }
    // Save the offset to get to the children
    dict->children = ptr_to_off(fsptr, ptr);
    // Set first children to point to its parent
    *ptr = ptr_to_off(fsptr, parent_node);
  }

  return new_node;
}

void free_file_info(void *fsptr, file_t *file) {
  myfs_file_block_struct_t *block = off_to_ptr(fsptr, file->first_file_block);
  myfs_file_block_struct_t *next;

  // Iterate over all blocks until a block is pointing to fsptr meaning that we
  // are done
  while (((void *)block) != fsptr) {
    // Free block data information
    __free_impl(fsptr, off_to_ptr(fsptr, block->data));
    // Save next block pointer
    next = off_to_ptr(fsptr, block->next_file_block);
    // Free current block
    __free_impl(fsptr, block);
    // Update current block with the next file_t for the next iteration
    block = next;
  }
}

void remove_node(void *fsptr, directory_t *dict, node_t *node) {
  // Iterate over the files in dict and remove the file_node which we assume to
  // be already free by calling free_file_info with &file_node->type.file
  size_t n_children = dict->max_num_children;
  __myfs_off_t *children = off_to_ptr(fsptr, dict->children);
  size_t index;
  __myfs_off_t node_off = ptr_to_off(fsptr, node);

  // Find the index where the node is at
  for (index = 1; index < n_children; index++) {
    if (children[index] == node_off) {
      break;
    }
  }

  // File must be at index
  __free_impl(fsptr, node);

  // Move the size_left nodes one to the left to cover the node remove
  for (; index < n_children - 1; index++) {
    children[index] = children[index + 1];
  }

  // Set the last to have offset of zero and update number of children
  children[index] = ((__myfs_off_t)0);
  dict->max_num_children--;

  // See if we can free some memory by half while keeping at least 4 offsets
  size_t new_n_children =
      (*((size_t *)children) - 1) /
      sizeof(__myfs_off_t);  // Get the maximum number of children offset
  new_n_children <<= 1;      // Divide the maximum number by two

  // Check if the new number of children is greater or equal than the current
  // number, check that we always have 4 or more children spaces
  //  and that we can actually made an node_struct_t object before making it
  if ((new_n_children >= dict->max_num_children) &&
      (new_n_children * sizeof(__myfs_off_t) >= sizeof(node_struct_t)) &&
      (new_n_children >= 4)) {
    // Every condition is meet, so we proceed to make an AlloacteFrom object and
    // sent it to be added into the linked list of free blocks
    node_struct_t *temp = ((node_struct_t *)&children[new_n_children]);
    temp->size_left = new_n_children * sizeof(__myfs_off_t) - sizeof(size_t);
    temp->next_space = 0;
    __free_impl(fsptr, temp);

    // Update the new size of the current directory children array of offsets
    size_t *new_size = (((size_t *)children) - 1);
    *new_size -= (temp->size_left - sizeof(size_t));
  }
}

void remove_data(void *fsptr, myfs_file_block_struct_t *block, size_t size) {
  // Check that there is somewhere to remove bytes from
  if (block == NULL) {
    return;
  }

  size_t idx = 0;

  // Find where we need to cut the file and free the rest
  while (size != 0) {
    // If we are not cutting on this block
    if (size > block->allocated) {
      size -= block->allocated;
      block = off_to_ptr(fsptr, block->next_file_block);
    } else {
      idx = size;
      size = 0;
    }
  }

  // Free the data starting at the idx, first you need to set the header with
  // block->allocated - idx - sizeof(size_t). Make the header, if possible, and
  // free it
  if ((idx + sizeof(node_struct_t)) < block->allocated) {
    size_t *temp = (size_t *)(&((char *)off_to_ptr(fsptr, block->data))[idx]);
    *temp = block->allocated - idx - sizeof(size_t);
    // Our offset to the beginning is 0
    __free_impl(fsptr, ((void *)temp) + sizeof(size_t));
  }

  // Free all date and block after this one
  block = off_to_ptr(fsptr, block->next_file_block);
  myfs_file_block_struct_t *temp;

  while (block != fsptr) {
    // Free the data block
    __free_impl(fsptr, off_to_ptr(fsptr, block->data));

    // Get the next block before freeing the current block
    temp = off_to_ptr(fsptr, block->next_file_block);
    // Free the file_block
    __free_impl(fsptr, block);

    // Update the block pointer to the next one
    block = temp;
  }
}

int add_data(void *fsptr, file_t *file, size_t size, int *errnoptr) {
  myfs_file_block_struct_t *block = off_to_ptr(fsptr, file->first_file_block);

  // Some extra variables needed for later
  myfs_file_block_struct_t *prev_temp_block = NULL;
  myfs_file_block_struct_t *temp_block;
  size_t new_data_block_size;
  size_t ask_size;
  size_t append_n_bytes;
  size_t initial_file_size = file->total_size;
  void *data_block;

  // If our file have 0 bytes, we append the first one manually
  if (((void *)block) == fsptr) {
    ask_size = sizeof(myfs_file_block_struct_t);
    block = __malloc_impl(fsptr, NULL, &ask_size);
    if (ask_size != 0) {
      *errnoptr = ENOSPC;
      return -1;
    }
    // Append the first file_block
    file->first_file_block = ptr_to_off(fsptr, block);
    // Add the first data block
    ask_size = size;
    data_block = __malloc_impl(fsptr, NULL, &ask_size);

    // Set file_block characteristics
    block->size = size - ask_size;
    block->allocated = block->size;
    block->data = ptr_to_off(fsptr, data_block);
    block->next_file_block = 0;
    size -= block->size;
  }
  // Extend the last block by appending 0's
  else {
    // Get the last block while keeping track of how many bytes are missing
    while (block->next_file_block != 0) {
      size -= block->allocated;
      block = off_to_ptr(fsptr, block->next_file_block);
    }

    // Get how many 0's you can append by only bringing the allocated and size
    // attributes of the myfs_file_block_struct_t closer
    append_n_bytes = (block->size - block->allocated) > size
                         ? size
                         : (block->size - block->allocated);
    data_block = &((char *)off_to_ptr(fsptr, block->data))[block->allocated];

    // Add 0's to the end of the block by extending the allocated bytes to the
    // total size
    memset(data_block, 0, append_n_bytes);
    block->allocated += append_n_bytes;
    size -= append_n_bytes;
  }

  // If we are done with getting the extra space we exit
  if (size == ((size_t)0)) {
    return 0;
  }

  // Otherwise append blocks from __maloc_impl() until we have size bytes
  size_t prev_size = block->allocated;
  ask_size = size;
  data_block = ((char *)off_to_ptr(fsptr, block->data));
  void *new_data_block = __malloc_impl(fsptr, data_block, &ask_size);
  block->size = *(((size_t *)data_block) -
                  1);  // Update total size available in the data block

  // If we don't get a block back and the ask_size is not 0, it means that our
  // file system don't have enough memory to even return one small block
  if (new_data_block == NULL) {
    // If we are not with the space and didn't got a block back it means that we
    // cannot get the size requested
    if (ask_size != 0) {
      *errnoptr = ENOSPC;
      return -1;
    }
    // If ask_size is 0 it means that we got the space we wanted by extending
    // the initial data block
    else {
      // Get how many out of the bytes appended are needed
      append_n_bytes = (block->size - block->allocated >= size
                            ? size
                            : block->size - block->allocated);
      memset(&((char *)off_to_ptr(fsptr, block->data))[prev_size], 0,
             append_n_bytes);
      block->allocated += append_n_bytes;
      size = 0;
    }
  }
  // We did got a block back so we must append it
  else {
    // If the data block got extended, we didn't got everything from it
    append_n_bytes = block->size - block->allocated;
    memset(&((char *)off_to_ptr(fsptr, block->data))[prev_size], 0,
           append_n_bytes);
    block->allocated += append_n_bytes;
    size -= append_n_bytes;

    size_t temp_size;
    temp_block = block;

    // Start connecting and collecting blocks until we are done collecting bytes
    // or we fail to collect them all so we free them and fail
    while (1) {
      // Get the size of the block returned by __malloc_impl()
      new_data_block_size = *(((size_t *)new_data_block) - 1);

      // Save temp_block
      if (prev_temp_block != NULL) {
        prev_temp_block->next_file_block = ptr_to_off(fsptr, temp_block);
      }

      // Set the temp_block information
      temp_block->size = new_data_block_size;
      temp_block->allocated = ask_size == 0 ? size : new_data_block_size;
      temp_block->data = ptr_to_off(fsptr, new_data_block);
      temp_block->next_file_block = ((__myfs_off_t)0);

      memset(new_data_block, 0, temp_block->allocated);
      size -= temp_block->allocated;

      prev_temp_block = temp_block;

      // If we are done connecting block we exit it
      if (size == 0) {
        break;
      }

      // Call malloc to get another block of data
      ask_size = size;
      new_data_block = __malloc_impl(fsptr, NULL, &ask_size);
      temp_size = sizeof(myfs_file_block_struct_t);
      temp_block = __malloc_impl(fsptr, NULL, &temp_size);

      // Make sure that we got something out of the call
      if ((new_data_block == NULL) || (temp_block == NULL) ||
          (temp_size != 0)) {
        // Need to remove everything that got store, even the block extended
        remove_data(fsptr, off_to_ptr(fsptr, file->first_file_block),
                    initial_file_size);

        *errnoptr = ENOSPC;
        return -1;
      }
    }
  }

  return 0;
}
/* End of helper functions */

/* Implements an emulation of the stat system call on the filesystem of size
   fssize pointed to by fsptr.

   If path can be followed and describes a file or directory that exists and is
   accessable, the access information is put into stbuf.

   On success, 0 is returned. On failure, -1 is returned and the appropriate
   error code is put into *errnoptr.

   man 2 stat documents all possible error codes and gives more detail on what
   fields of stbuf need to be filled in. Essentially, only the following fields
   need to be supported:

   st_uid      the value passed in argument
   st_gid      the value passed in argument
   st_mode     (as fixed values S_IFDIR | 0755 for directories,
                                S_IFREG | 0755 for files)
   st_nlink    (as many as there are subdirectories (not files) for directories
                (including . and ..),
                1 for files)
   st_size     (supported only for files, where it is the real file size)
   st_atim
   st_mtim
*/
int __myfs_getattr_implem(void *fsptr, size_t fssize, int *errnoptr, uid_t uid,
                          gid_t gid, const char *path, struct stat *stbuf) {
  initilaize_check(fsptr, fssize);

  node_t *node = path_solver(fsptr, path, 0);

  // Path could not be solved
  if (node == NULL) {
    *errnoptr = ENOENT;
    return -1;
  }

  stbuf->st_uid = uid;
  stbuf->st_gid = gid;

  if (node->is_file) {
    stbuf->st_mode = S_IFREG;
    stbuf->st_nlink = ((nlink_t)1);
    stbuf->st_size = ((off_t)node->type.file.total_size);
    stbuf->st_atime = node->times[0].tv_sec;
    stbuf->st_mtime = node->times[1].tv_sec;
  } else {
    stbuf->st_mode = S_IFDIR;
    directory_t *dict = &node->type.directory;
    __myfs_off_t *children = off_to_ptr(fsptr, dict->children);
    stbuf->st_nlink = ((nlink_t)2);
    for (size_t i = 1; i < dict->max_num_children; i++) {
      if (!((node_t *)off_to_ptr(fsptr, children[i]))->is_file) {
        stbuf->st_nlink++;
      }
    }
  }

  return 0;
}

/* Implements an emulation of the readdir system call on the filesystem of size
   fssize pointed to by fsptr.

   If path can be followed and describes a directory that exists and is
   accessable, the names of the subdirectories and files contained in that
   directory are output into *namesptr. The . and .. directories must not be
   included in that listing.

   If it needs to output file and subdirectory names, the function starts by
   allocating (with calloc) an array of pointers to characters of the right size
   (n entries for n names). Sets *namesptr to that pointer. It then goes over
   all entries in that array and allocates, for each of them an array of
   characters of the right size (to hold the i-th name, together with the
   appropriate '\0' terminator). It puts the pointer into that i-th array entry
   and fills the allocated array of characters with the appropriate name. The
   calling function will call free on each of the entries of *namesptr and on
   *namesptr.

   The function returns the number of names that have been put into namesptr.

   If no name needs to be reported because the directory does not contain any
   file or subdirectory besides . and .., 0 is returned and no allocation takes
   place.

   On failure, -1 is returned and the *errnoptr is set to the appropriate error
   code.

   The error codes are documented in man 2 readdir.

   In the case memory allocation with malloc/calloc fails, failure is indicated
   by returning -1 and setting *errnoptr to EINVAL.
*/
int __myfs_readdir_implem(void *fsptr, size_t fssize, int *errnoptr,
                          const char *path, char ***namesptr) {
  initilaize_check(fsptr, fssize);

  node_t *node = path_solver(fsptr, path, 0);

  // Path could not be solved
  if (node == NULL) {
    *errnoptr = ENOENT;
    return -1;
  }

  // Check that the node is a directory
  if (node->is_file) {
    *errnoptr = ENOTDIR;
    return -1;
  }

  // Check that directory have more than ".", ".." nodes inside
  directory_t *dict = &node->type.directory;
  if (dict->max_num_children == 1) {
    return 0;
  }

  size_t n_children = dict->max_num_children;
  // Allocate space for all children, except "." and ".."
  void **ptr = (void **)calloc(n_children - ((size_t)1), sizeof(char *));
  __myfs_off_t *children = off_to_ptr(fsptr, dict->children);

  // Check that calloc call was successful
  if (ptr == NULL) {
    *errnoptr = EINVAL;
    return -1;
  }

  char **names = ((char **)ptr);
  // Fill array of names
  size_t len;
  for (size_t i = ((size_t)1); i < n_children; i++) {
    node = ((node_t *)off_to_ptr(fsptr, children[i]));
    len = strlen(node->name);
    names[i - 1] = (char *)malloc(len + 1);
    strcpy(names[i - 1], node->name);  // strcpy(dst,src)
    names[i - 1][len] = '\0';
  }

  *namesptr = names;
  return ((int)(n_children - 1));
}

/* Implements an emulation of the mknod system call for regular files on the
   filesystem of size fssize pointed to by fsptr.

   This function is called only for the creation of regular files.

   If a file gets created, it is of size zero and has default ownership and mode
   bits.

   The call creates the file indicated by path.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 mknod.
*/
int __myfs_mknod_implem(void *fsptr, size_t fssize, int *errnoptr,
                        const char *path) {
  initilaize_check(fsptr, fssize);

  // Make a directory, 1 because it is a file
  node_t *node = make_inode(fsptr, path, errnoptr, 1);

  // Check if the node was successfully created, if it wasn't the errnoptr was
  // already set so we just return failure with -1
  if (node == NULL) {
    return -1;
  }

  return 0;
}

/* Implements an emulation of the unlink system call for regular files on the
   filesystem of size fssize pointed to by fsptr.

   This function is called only for the deletion of regular files.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 unlink.
*/
int __myfs_unlink_implem(void *fsptr, size_t fssize, int *errnoptr,
                         const char *path) {
  initilaize_check(fsptr, fssize);

  // Call path_solver with a 1 because we want the directory node where the
  // filename belongs to
  node_t *node = path_solver(fsptr, path, 1);

  // Check that the file parent exist
  if (node == NULL) {
    *errnoptr = ENOENT;
    return -1;
  }

  // Check that the node returned is a directory
  if (node->is_file) {
    *errnoptr = ENOTDIR;
    return -1;
  }

  // Get directory from node
  directory_t *dict = &node->type.directory;

  // Get last token which have the filename
  unsigned long len;
  char *filename = get_last_token(path, &len);

  // Check that the parent don't contain a node with the same name as the one we
  // are about to create
  node_t *file_node = get_node(fsptr, dict, filename);

  if (file_node == NULL) {
    *errnoptr = ENOENT;
    return -1;
  }
  // Check that file_node is actually a file
  if (!file_node->is_file) {
    // Path given lead to a directory not a file
    *errnoptr = EISDIR;
    return -1;
  }

  // Free file information
  file_t *file = &file_node->type.file;
  if (file->total_size != 0) {
    free_file_info(fsptr, file);
  }

  // Remove file_node from parent directory
  remove_node(fsptr, dict, file_node);

  return 0;
}

/* Implements an emulation of the rmdir system call on the filesystem of size
   fssize pointed to by fsptr.

   The call deletes the directory indicated by path.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The function call must fail when the directory indicated by path is not empty
   (if there are files or subdirectories other than . and ..).

   The error codes are documented in man 2 rmdir.
*/
int __myfs_rmdir_implem(void *fsptr, size_t fssize, int *errnoptr,
                        const char *path) {
  initilaize_check(fsptr, fssize);

  // We can access the parent directory as the first children of the return
  // directory
  node_t *node = path_solver(fsptr, path, 0);

  // Check that the node exist
  if (node == NULL) {
    *errnoptr = ENOENT;
    return -1;
  }

  // Check that the node returned is not a file
  if (node->is_file) {
    *errnoptr = ENOTDIR;
    return -1;
  }

  // Check that the directory is empty (only the parent can be there "..")
  directory_t *dict = &node->type.directory;
  if (dict->max_num_children != 1) {
    *errnoptr = ENOTEMPTY;
    return -1;
  }

  // Get parent directory
  __myfs_off_t *children = off_to_ptr(fsptr, dict->children);
  node_t *parent_node = off_to_ptr(fsptr, *children);

  // Free children of node and the node itself
  __free_impl(fsptr, children);
  remove_node(fsptr, &parent_node->type.directory, node);

  return 0;
}

/* Implements an emulation of the mkdir system call on the filesystem of size
   fssize pointed to by fsptr.

   The call creates the directory indicated by path.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 mkdir.
*/
int __myfs_mkdir_implem(void *fsptr, size_t fssize, int *errnoptr,
                        const char *path) {
  initilaize_check(fsptr, fssize);

  // Make a directory, 0 because it is not a file
  node_t *node = make_inode(fsptr, path, errnoptr, 0);

  // Check if the node was successfully created, if it wasn't the errnoptr was
  // already set so we just return failure with -1
  if (node == NULL) {
    return -1;
  }

  return 0;
}

/* Implements an emulation of the rename system call on the filesystem of size
   fssize pointed to by fsptr.

   The call moves the file or directory indicated by from to to.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   Caution: the function does more than what is hinted to by its name. In cases
   the from and to paths differ, the file is moved out of the from path and
   added to the to path.

   The error codes are documented in man 2 rename.
*/
int __myfs_rename_implem(void *fsptr, size_t fssize, int *errnoptr,
                         const char *from, const char *to) {
  initilaize_check(fsptr, fssize);

  /* STUB */
  return -1;
}

/* Implements an emulation of the truncate system call on the filesystem of size
   fssize pointed to by fsptr.

   The call changes the size of the file indicated by path to offset bytes.

   When the file becomes smaller due to the call, the extending bytes are
   removed. When it becomes larger, zeros are appended.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 truncate.
*/
int __myfs_truncate_implem(void *fsptr, size_t fssize, int *errnoptr,
                           const char *path, off_t offset) {
  initilaize_check(fsptr, fssize);

  if (offset < 0) {
    *errnoptr = EFAULT;
    return -1;
  }

  size_t size = ((size_t)offset);

  // Get the node where the file is located
  node_t *node = path_solver(fsptr, path, 0);

  // Checks if path is valid, if not valid return -1
  if (node == NULL) {
    *errnoptr = ENOENT;
    return -1;
  }

  // If node is not a file we cannot truncated
  if (!node->is_file) {
    *errnoptr = EISDIR;
    return -1;
  }

  file_t *file = &node->type.file;
  myfs_file_block_struct_t *block = off_to_ptr(fsptr, file->first_file_block);
  size_t final_file_size = size;

  // If the new size is the same we do nothing
  if (file->total_size == size) {
    // File has not been modify, only access
    update_time(node, 0);
    return 0;
  }
  // If the new size is less, we make an node_struct_t object (if possible)
  // and send it to __free_impl()
  else if (file->total_size > size) {
    // File would be access and modify
    update_time(node, 1);

    // Update total size of the file once the removal is done
    file->total_size = size;

    // Remove what is after the size byte starting at block
    remove_data(fsptr, block, size);
  }
  // Otherwise, the new size is greater than current size, so we append 0's to
  // it by calling __malloc_impl()
  else {
    // File would be access and modify
    update_time(node, 1);

    // Add size bytes into the end of our block
    if (add_data(fsptr, file, size, errnoptr) != 0) {
      return -1;
    }
  }

  file->total_size = final_file_size;

  return 0;
}

/* Implements an emulation of the open system call on the filesystem  of size
   fssize pointed to by fsptr, without actually performing the opening of the
   file (no file descriptor is returned).

   The call just checks if the file (or directory) indicated by path can be
   accessed, i.e. if the path can be followed to an existing object for which
   the access rights are granted.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The two only interesting error codes are

   * EFAULT: the filesystem is in a bad state, we can't do anything

   * ENOENT: the file that we are supposed to open doesn't exist (or a subpath).

   It is possible to restrict ourselves to only these two error conditions. It
   is also possible to implement more detailed error condition answers.

   The error codes are documented in man 2 open.
*/
int __myfs_open_implem(void *fsptr, size_t fssize, int *errnoptr,
                       const char *path) {
  initilaize_check(fsptr, fssize);

  // Get the node where the file is located
  node_t *node = path_solver(fsptr, path, 0);

  // Checks if path is valid, if not valid return -1
  if (node == NULL) {
    *errnoptr = ENOENT;
    return -1;
  }

  // Checks if node is a file, if it is a file return 0
  return node->is_file ? 0 : -1;
}

/* Implements an emulation of the read system call on the filesystem of size
   fssize pointed to by fsptr.

   The call copies up to size bytes from the file indicated by path into the
   buffer, starting to read at offset. See the man page for read for the details
   when offset is beyond the end of the file etc.

   On success, the appropriate number of bytes read into the buffer is returned.
   The value zero is returned on an end-of-file condition.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 read.
*/
int __myfs_read_implem(void *fsptr, size_t fssize, int *errnoptr,
                       const char *path, char *buf, size_t size, off_t offset) {
  initilaize_check(fsptr, fssize);

  // Check that the offset is positive
  if (offset < 0) {
    *errnoptr = EFAULT;
    return -1;
  }

  // off_t is signed but we already know that it is positive so we change it to
  // size_t
  size_t size_left = ((size_t)offset);

  // Getting file node
  node_t *node = path_solver(fsptr, path, 0);

  // Check if path is valid
  if (node == NULL) {
    *errnoptr = ENOENT;
    return -1;
  }

  // Check that node is a file
  if (!node->is_file) {
    *errnoptr = EISDIR;
    return -1;
  }

  // Check that the file have more bytes than the size_left so we don't have to
  // iterate it
  file_t *file = &node->type.file;

  // If we are trying to read outside the file size
  if (size_left > file->total_size) {
    *errnoptr = EFAULT;
    return -1;
  }

  if (file->total_size == 0) {
    return 0;
  }

  myfs_file_block_struct_t *block = off_to_ptr(fsptr, file->first_file_block);
  size_t index = 0;

  while (size_left != 0) {
    // If we are not getting information from this block
    if (size_left > block->size) {
      size_left -= block->size;
      block = off_to_ptr(fsptr, block->next_file_block);
    } else {
      index = size_left;
      size_left = 0;
    }
  }

  // We have the index to where to start reading so we start populating the
  // buffer
  size_t tot_read_bytes = 0;
  size_t read_n_bytes =
      size > (block->allocated - index) ? (block->allocated - index) : size;
  memcpy(buf, &((char *)off_to_ptr(fsptr, block->data))[index], read_n_bytes);
  size -= read_n_bytes;
  index = read_n_bytes;
  tot_read_bytes += read_n_bytes;
  block = off_to_ptr(fsptr, block->next_file_block);

  while ((size > ((size_t)0)) && (block != fsptr)) {
    read_n_bytes = size > block->allocated ? block->allocated : size;
    memcpy(&buf[index], off_to_ptr(fsptr, block->data), read_n_bytes);
    // Update size to subtract what you already read
    size -= read_n_bytes;
    // Keeps track of where in the buffer we last wrote
    index += read_n_bytes;
    tot_read_bytes += read_n_bytes;
    block = off_to_ptr(fsptr, block->next_file_block);
  }

  return ((int)tot_read_bytes);
}

/* Implements an emulation of the write system call on the filesystem of size
   fssize pointed to by fsptr.

   The call copies up to size bytes to the file indicated by path into the
   buffer, starting to write at offset. See the man page for write for the
   details when offset is beyond the end of the file etc.

   On success, the appropriate number of bytes written into the file is
   returned. The value zero is returned on an end-of-file condition.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 write.
*/
int __myfs_write_implem(void *fsptr, size_t fssize, int *errnoptr,
                        const char *path, const char *buf, size_t size,
                        off_t offset) {
  initilaize_check(fsptr, fssize);

  // Check that the offset is positive
  if (offset < 0) {
    *errnoptr = EFAULT;
    return -1;
  }

  size_t size_left = ((size_t)offset);
  node_t *node = path_solver(fsptr, path, 0);

  // Checks if path is valid, if not valid return -1
  if (node == NULL) {
    *errnoptr = ENOENT;
    return -1;
  }

  // If node is not a file we cannot read
  if (!node->is_file) {
    *errnoptr = EISDIR;
    return -1;
  }

  // Check that the file have more bytes than the size_left so we don't have to
  // iterate it
  file_t *file = &node->type.file;
  if (file->total_size < size_left) {
    *errnoptr = EFBIG;
    return -1;
  }

  // File would be access and modify
  update_time(node, 1);
  // Add size bytes into the end of our block
  if (add_data(fsptr, file, size + 1, errnoptr) != 0) {
    return -1;
  }

  // Traverse offset bytes to start writing
  myfs_file_block_struct_t *block = off_to_ptr(fsptr, file->first_file_block);
  size_t data_idx = 0;

  // Find where we need start writing
  while (size_left != 0) {
    // If we are not cutting on this block
    if (size_left > block->allocated) {
      size_left -= block->allocated;
      block = off_to_ptr(fsptr, block->next_file_block);
    } else {
      data_idx = size_left;
      size_left = 0;
    }
  }

  char *data_block = ((char *)off_to_ptr(fsptr, block->data));
  size_t buf_idx = 0;
  char copy[size + 1];
  char c;

  memcpy(copy, buf, size);
  copy[size] = '\0';
  // Start writing at index on the data block saving what is currently on it to
  // later be push forward
  while ((buf[buf_idx] != '\0') && (((void *)block) != fsptr)) {
    while (buf_idx != size) {
      // Swap characters from buffer to data block
      c = copy[buf_idx];
      copy[buf_idx] = data_block[data_idx];
      data_block[data_idx] = c;
      // If we had copy the last '\0' we are done copying
      if (copy[++buf_idx] == '\0') {
        // Check that the null character is not the last character of this block
        if (data_idx + 1 == block->size) {
          block = off_to_ptr(fsptr, block->next_file_block);
          data_block = ((char *)off_to_ptr(fsptr, block->data));
          data_block[0] = '\0';
        }
        // We put the last character on the current data block
        else {
          data_block[++data_idx] = '\0';
        }
        // We don't count the null character as a character use
        block->allocated = data_idx;
        goto end;
      }

      // Update data_idx
      if (++data_idx == block->size) {
        data_idx = 0;
        block = off_to_ptr(fsptr, block->next_file_block);
        if (block->next_file_block == ((__myfs_off_t)0)) {
          break;
        }
        data_block = ((char *)off_to_ptr(fsptr, block->data));
      }
    }
    // Restart buffer index to continue copying characters
    buf_idx = 0;
  }

end:
  // Update file total size
  file->total_size += size;

  return ((int)size);
}


int __myfs_utimens_implem(void *fsptr, size_t fssize, int *errnoptr,
                          const char *path, const struct timespec ts[2]) {
    // Check if fsptr is initialized
      if (fsptr == NULL) {
            *errnoptr = EINVAL;
            return -1;
      }

      // Find the node corresponding to the given path
      node_t *node = path_solver(fsptr, path, 0);
      if (node == NULL) {
            *errnoptr = EINVAL;
            return -1;
      }

    // Update access time and modification time
    node->times[0] = ts[0];
    node->times[1] = ts[1];

    return 0; 
}


int __myfs_statfs_implem(void *fsptr, size_t fssize, int *errnoptr,
                         struct statvfs *stbuf) {
      // Check if stbuf is NULL
      if (stbuf == NULL) {
            *errnoptr = EFAULT;
            return -1;
      }

  
      stbuf->f_bsize = BLOCK_SIZE;

      //number of blocks in the filesystem
      stbuf->f_blocks = fssize / BLOCK_SIZE;

      // number of free blocks
      size_t bytes_free = *((size_t *)fsptr + 1); // Assuming free memory offset is at 2nd position because it starts with ..
      stbuf->f_bfree = bytes_free / BLOCK_SIZE;

      // f_bavail is same as f_bfree
      stbuf->f_bavail = stbuf->f_bfree;

      // Set maximum file/directory name length
      stbuf->f_namemax = 255;

      return 0;
}
