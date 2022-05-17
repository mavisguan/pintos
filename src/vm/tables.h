#ifndef TABLES_H
#define TABLES_H

#include <hash.h>
#include "threads/thread.h"
#include "devices/block.h"


enum page_type
{
  /* Page types. */
  IN_PHYS_MEM,           /**< Already resides in physical memory. */
  IN_SWAP,               /**< In swap space. */
  IN_FILE,               /**< In a file. */
  ALL_ZEROS,             /**< All zeros. */
};


/* Frame table entry. */
struct frame
{
  struct hash_elem hash_elem;  // Hash table element. 
  void* vaddr;  // Virtual address.
  void* paddr;  // Physical address. (Key value)
  struct thread* thr;  // Which thread (process) held this frame?
  struct lock frame_entry_lock;
};

struct hash frame_table;  // Frame table. (Global for whole pintos)
struct lock frame_table_lock;  // Frame table's lock.


/* Used by supplmental page table. */
struct file_info
{
  struct file* f; // Pointer to file.
  int32_t offset;
  size_t zeros; // last zeros bytes should be zero. (page alignment)
};

/* SPT entry. */
struct page
{
  struct hash_elem hash_elem;  // Hash table element. 
  void* vaddr;  // Virtual address. (Key value)
  void* paddr;  // Physical address. 
  size_t index;  // index in swap space.
  enum page_type pagetype;  // Where is this page?
  struct file_info fileinfo;  // If the page is in a file, record the file pointer.
  bool writable;  // Indicate if the page is writable.
};

/* Returns a hash value for page p. */
unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED);
unsigned frame_hash (const struct hash_elem *p_, void *aux UNUSED);

/* Returns true if page a precedes page b. */
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED);
bool frame_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED);

/* Returns the page containing the given virtual address,
   or a null pointer if no such page exists. */
struct page* page_lookup (void *address, struct hash* page_table_addr);
struct frame* frame_lookup (void *address);

/* Functions to free data structures when a thread terminates
   or pintos is shutdown. */
void destroy_page_table(struct hash* page_table_addr);
void delete_page(struct hash_elem *e, void* aux);
void destroy_frame_table(void);
void delete_frame(struct hash_elem *e, void* aux);
void reclaim_frame(struct hash_elem *e, void* aux);

struct frame* choose_page_to_evict(void);
struct frame* page_eviction(void);



///////////////////////////////////////////
//----------Swap related stuff-----------//
///////////////////////////////////////////
struct bitmap* swap_table; // Swap table. (Global for whole pintos)
struct block* swap_space;  // Get and store the block device.
struct lock swap_lock;
block_sector_t allocated_swap_no;  // how many swap slots have been allocated?
block_sector_t max_swap_no;

/* Life cycle of swap space. */
void init_swap(void);
void free_swap_on_termination(struct hash_elem *e, void* aux UNUSED);
void destroy_swap_table(void);

/* Functions to read from or write to swap space. */
void read_from_swap(size_t index, struct frame* f);
void write_to_swap(struct frame* f, struct page* p);

#endif /**< vm/tables.h */