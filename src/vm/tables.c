#include "vm/tables.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "lib/random.h"
#include "lib/kernel/bitmap.h"

/* Basic functions needed to construct hash tables. */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes (&p->vaddr, sizeof p->vaddr);
}

unsigned
frame_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct frame *f = hash_entry (p_, struct frame, hash_elem);
  return hash_bytes (&f->paddr, sizeof f->paddr);
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);

  return a->vaddr < b->vaddr;
}

bool
frame_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct frame *a = hash_entry (a_, struct frame, hash_elem);
  const struct frame *b = hash_entry (b_, struct frame, hash_elem);

  return a->paddr < b->paddr;
}

/* Returns the page containing the given virtual address,
   or a null pointer if no such page exists. */
struct page* page_lookup (void *address, struct hash* page_table_addr)
{
  struct page p;
  struct hash_elem *e;

  p.vaddr = address;
  e = hash_find (page_table_addr, &p.hash_elem);
  return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
}

struct frame* frame_lookup (void *address)
{
  struct frame f;
  struct hash_elem *e;

  f.paddr = address;
  e = hash_find (&frame_table, &f.hash_elem);
  return e != NULL ? hash_entry (e, struct frame, hash_elem) : NULL;
}

/* Destroy the table. */
void destroy_page_table(struct hash* page_table_addr)
{
  hash_destroy(page_table_addr, delete_page);
}

void delete_page(struct hash_elem *e, void* aux UNUSED)
{
  struct page *p = hash_entry (e, struct page, hash_elem);
  free(p);    
}

void destroy_frame_table()
{
  hash_destroy(&frame_table, delete_frame);
}

// Free the malloced struct frame.
void delete_frame(struct hash_elem *e, void* aux UNUSED)
{
  struct frame *f = hash_entry (e, struct frame, hash_elem);
  free(f);    
}

// Other helper routines.
/* Reclaim a frame when its process terminates. */ // TODO: bug?
void reclaim_frame(struct hash_elem *e, void* aux UNUSED)
{
  struct page *p = hash_entry (e, struct page, hash_elem);  // Get a page from current thread's SPT.
  if (p->pagetype == IN_PHYS_MEM)  // Free the frame table entries. (No need to free frame---OS will take care)
  {
    struct frame* f = frame_lookup(p->paddr);  
    ASSERT(f != NULL);
    hash_delete(&frame_table, &f->hash_elem);
  }
}

/* Use clock algorithm to choose a page to evict. 
   Use the accessed bit of pagedir as "used bit". */
struct frame* choose_page_to_evict()
{
  struct hash_iterator iter;
  struct frame* f;
  bool found = false;
  while(!found)  
  {
    hash_first(&iter, &frame_table);
    while(hash_next(&iter))
    {
      f = hash_entry(hash_cur(&iter), struct frame, hash_elem);
      // Need to check & modify two accessed bits to handle aliases.
      if (pagedir_is_accessed(f->thr->pagedir, f->vaddr) ||
      pagedir_is_accessed(f->thr->pagedir, ptov((uintptr_t)f->paddr))) 
      {
        pagedir_set_accessed(f->thr->pagedir, f->vaddr, false);
        pagedir_set_accessed(f->thr->pagedir, ptov((uintptr_t)f->paddr), false);
      }
      else  // Found a page whose used bit = 0, return true.
      {
        found = true;
        break;    
      }    
    }    
  }
  ASSERT(f != NULL);
  return f;
}

/* Do page eviction. */
struct frame* page_eviction()
{
  // 1. Choose a frame to evict.
  struct frame* f = choose_page_to_evict();
  // 2. Remove reference to the frame from any page table.
  lock_acquire(&f->thr->page_table_lock);
  struct page* page_to_remove = page_lookup(f->vaddr, &f->thr->page_table);
  
  // 3. If the evicted page is modified, write it to swap.
  if (pagedir_is_dirty(f->thr->pagedir, f->vaddr) ||
      pagedir_is_dirty(f->thr->pagedir, ptov((uintptr_t)f->paddr)))  // aliasing!!!!
  {
    write_to_swap(f, page_to_remove);
  }
  else // Mark the page as "in file"--can be loaded again from executable.
  {
    page_to_remove->pagetype = IN_FILE;  
  }
  lock_release(&f->thr->page_table_lock);
  pagedir_clear_page(f->thr->pagedir, f->vaddr);  // Mark the evicted page as "not present".  
  // 4. Return the free frame.
  return f;
}

///////////////////////////////////////////
//----------Swap-related stuff-----------//
///////////////////////////////////////////

/* Initialize swap table. */
void init_swap()
{
  swap_space = block_get_role(BLOCK_SWAP);
  max_swap_no = block_size(swap_space);
  swap_table = bitmap_create(max_swap_no);
  allocated_swap_no = 0;
  lock_init(&swap_lock);
}

// Read the content of swapspace[index, index + 8) into frame f.
void read_from_swap(size_t index, struct frame* f)
{
  lock_acquire(&f->frame_entry_lock);   
  lock_acquire(&swap_lock);
  ASSERT(bitmap_all(swap_table, index, 8));
  void* ofs = ptov((uintptr_t)f->paddr);
  bitmap_set_multiple(swap_table, index, 8, false);  // Mark as available.
  for (size_t i = 0; i < 8; i++)
  {
    block_read(swap_space, index + i, (uint8_t*)ofs + i * BLOCK_SECTOR_SIZE);     
  }   
  lock_release(&swap_lock);
  lock_release(&f->frame_entry_lock);  
}

// Write frame f to swap, and record the related information.
void write_to_swap(struct frame* f, struct page* p)
{
  lock_acquire(&f->frame_entry_lock);   
  lock_acquire(&swap_lock);
  if (bitmap_contains(swap_table, 0, max_swap_no, false))
  {
    size_t index = bitmap_scan(swap_table, 0, 8, false);
    void* ofs = ptov((uintptr_t)f->paddr);
    bitmap_set_multiple(swap_table, index, 8, true);  // Mark as occupied.
    for (size_t i = 0; i < 8; i++)
    {
      block_write(swap_space, index + i, (uint8_t*)ofs + i * BLOCK_SECTOR_SIZE);     
    } 
    // Record the index of swap in the page.
    p->pagetype = IN_SWAP;
    p->index = index;
  }
  else
  {
    PANIC("The swap is full.\n");
  }
  lock_release(&swap_lock);
  lock_release(&f->frame_entry_lock); 
}

// When a thread terminates, free the swap slots that it occupied.
void free_swap_on_termination(struct hash_elem *e, void* aux UNUSED)
{  
  const struct page *p = hash_entry (e, struct page, hash_elem);
  if (p->pagetype == IN_SWAP)
  {
    // Mark the slots as available.  
    bitmap_set_multiple(swap_table, p->index, 8, false);   
  }
}

// Destroy swap table when pintos is shutdown.
void destroy_swap_table(void)
{
  bitmap_destroy(swap_table);
}
