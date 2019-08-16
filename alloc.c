#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void debug(const char *fmt, ...);
extern void *sbrk(intptr_t increment);

typedef enum {false, true} bool;

typedef struct _allocatedChunk{
    uint64_t prev_size;
    uint64_t size;
} allocatedChunk;

typedef struct _freeChunk{
    uint64_t prev_size;
    uint64_t size;
    struct freeChunk* fd;
    struct freeChunk* bk;
} freeChunk;

allocatedChunk* topChunk;
freeChunk* fastBins[10];
freeChunk* unsortedBins;

bool isMallocInited = false;

// initalize Bins & topChunk
void isFirst(){
    if(isMallocInited)
        return;
    //debug("malloc is initalized!\n");
    isMallocInited = true;
    
    // initalize fastBins
    for (int i = 0; i < 10; i++){
        fastBins[i] = NULL;
    }

    // initalize unsortedBins
    unsortedBins = NULL;

    // allocate topChunk
    topChunk = (allocatedChunk*)sbrk(0x10000);
    topChunk->size = 0x10000;
    topChunk->prev_size = 0;
    return; 
}

// find in fastBins
freeChunk* findInFastBins(size_t size){
    freeChunk* tmp = fastBins[(size-0x20)>>4];
    //debug("fastBin[%d]: 0x%p\n", (size-0x20)>>4, tmp);
    while(tmp != NULL){
        // when find
        if(tmp->size == size) return tmp;
        tmp = tmp->fd;
    }
    //debug("finish search\n");
    return NULL;
}

// find in unsortedBins 
// not implemented
freeChunk* findInUnsortedBins(size_t size){
    return NULL;
}

// allocate using topChunk 
allocatedChunk* allocateInTopChunk(size_t size){
    uint64_t topChunkSize = topChunk->size;
    allocatedChunk* p = topChunk;
    topChunk = (allocatedChunk*)((char*)topChunk + size);
    p->size = size;
    topChunk->size = topChunkSize - size;
    return p;
}

// expand topChunk
bool reallocTopChunk(size_t size){
    if(sbrk(size) == -1) return false;
    topChunk->size += size;
    return true;
}

void *myalloc(size_t size)
{
    if(!size) return NULL;
    isFirst();
    // alignment by 8bytes
    size = ((size & 15) > 0) ? (size & -16) + 0x10 : size; 
    size += 0x10;

    //debug("Allocated size: 0x%x\n", size);

    void* p;
    if(size <= 0x80){
        p = findInFastBins(size);
    }else{
        p = findInUnsortedBins(size);
    }    
    if(p != NULL) return p;

    //debug("alloc(%x): %p\n", (unsigned int)size, (char*)p + 0x10); 

    if(topChunk->size >= size){
        p = allocateInTopChunk(size);
    }else{
        while(topChunk->size <= size)
            if(reallocTopChunk(0x10000) == false)
                return NULL;
        p = allocateInTopChunk(size);
    }

    //debug("max: %u\n", max_size);
    //debug("allcated: %p\nsize: 0x%x\n\n", p, size);
    return (char*)p + 0x10;
}

void *myrealloc(void *ptr, size_t size)
{
    void *p = NULL;
    if (size != 0)
    {
        p = sbrk(size);
        if (ptr)
            memcpy(p, ptr, size);
        //max_size += size;
        //debug("max: %u\n", max_size);
    }
    //debug("realloc(%p, %u): %p\n", ptr, (unsigned int)size, p);
    return p;
}

void myfree(void *ptr)
{
    //debug("free(%p)\n", ptr);
    struct freeChunk* chunk = (struct freeChunk*)ptr;
    //if(chunk->size <= 0x80)


}
