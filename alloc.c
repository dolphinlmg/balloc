#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void debug(const char *fmt, ...);
extern void *sbrk(intptr_t increment);

void myfree(void* ptr);
void *myrealloc(void *ptr, size_t size);
void *myalloc(size_t size);

typedef enum {false, true} bool;

typedef struct _allocatedChunk{
    size_t prev_size;
    size_t size;
} allocatedChunk;

typedef struct _freeChunk{
    size_t prev_size;
    size_t size;
    struct _freeChunk* fd;
    struct _freeChunk* bk;
} freeChunk;

allocatedChunk* topChunk;
freeChunk fastBins[10];
freeChunk unsortedBins;

bool isMallocInited = false;

void dumpChunk(void* chunk){
    debug("dumpChunk:\n0x%p 0x%p\n0x%p 0x%p\n", *((uint64_t*)chunk), *((uint64_t*)chunk+1), *((uint64_t*)chunk+2), *((uint64_t*)chunk+3));
}

// initalize Bins & topChunk
void isFirst(){
    if(isMallocInited)
        return;
    //debug("malloc is initalized!\n");
    isMallocInited = true;
    
    // initalize fastBins
    for (int i = 0; i < 10; i++){
        memset(&fastBins[i], 0, sizeof(freeChunk));
    }

    // initalize unsortedBins
    memset(&unsortedBins, 0, sizeof(freeChunk));

    // allocate topChunk
    topChunk = (allocatedChunk*)sbrk(0x10000);
    topChunk->size = 0x10000 | 1;
    topChunk->prev_size = 0;
    return; 
}

// find in fastBins
// get size without inuse bit
freeChunk* findInFastBins(size_t size){
    freeChunk* FD = &fastBins[(size-0x20)>>4];
    debug("fastBin[%d].fd: 0x%p\n", (size-0x20)>>4, FD->fd);
    if(FD->fd != NULL && (FD->size&-2) == size){
        dumpChunk(FD->fd);
        // when find
        debug("FD->fd: %p\n", FD->fd);
        freeChunk* ret = FD->fd;
        FD->fd = FD->fd->fd;
        debug("FD->fd: %p\n", FD->fd);
        debug("found chunk in fastBins: %p\n", ret);
        return ret;
    }
    return NULL;
}

// find in unsortedBins 
// not implemented
// get size without inuse bit
freeChunk* findInUnsortedBins(size_t size){
    return NULL;
}

// allocate using topChunk 
// get size without inuse bit
allocatedChunk* allocateInTopChunk(size_t size){
    size_t topChunkSize = topChunk->size;
    allocatedChunk* p = topChunk;
    topChunk = (allocatedChunk*)((char*)topChunk + size);
    p->size = size;
    topChunk->size = topChunkSize - size;
    debug("AllocUsingTopChunk:0x%x\tTopChunk: %p\tSize: 0x%x\treturn: %p\n", size, topChunk, topChunk->size, p);
    return p;
}

// expand topChunk
// get size without inuse bit
bool reallocTopChunk(size_t size){
    if(sbrk(size) == -1) return false;
//    debug("reallocTopChunk: 0x%x\n", topChunk->size);
    topChunk->size = topChunk->size + size;
   debug("reallocedTopChunk: 0x%x\n\n", topChunk->size);
    return true;
}

void pushInFastBins(freeChunk* p){
    freeChunk* chk = &fastBins[(p->size-0x20)>>4];
    debug("fastBin[%d].fd: %p\n",(p->size-0x20)>>4, chk->fd);
    // when next chunk is topChunkSize 
    if( ((char*)p+(p->size&-2)) == ((char*)topChunk) ){
        debug("fastBins: next chunk is topChunk!\n");
        p->size = topChunk->size + (p->size&-2);
        debug("make topChunk size to:0x%lx\n", p->size);
        topChunk = p;
        return;
    }
    p->fd = NULL;
    if(chk->fd != NULL)
        p->fd = chk;
    fastBins[(p->size-0x20)>>4].fd = p;
    debug("fastBin[%d].fd: %p\tp->fd: 0x%p\n",(p->size-0x20)>>4, fastBins[(p->size-0x20)>>4].fd, p->fd);
}

void pushInUnsortedBins(freeChunk* p){
    freeChunk* chk = &unsortedBins;
    debug("unsortedBins is at: %p\tunsortedBin.fd: %p\tunsortedBin.bk: %p\n", chk, chk->fd, chk->bk);
    if( ((char*)p+(p->size&-2)) == ((char*)topChunk) ){
        debug("unsortedBins: next chunk is topChunk!\n");
        p->size = topChunk->size + (p->size&-2);
        debug("make topChunk size to:0x%lx\n", p->size);
        topChunk = p;
        return;
    }
}

// update for inuse bit
void *myalloc(size_t size)
{
    if(!size) return NULL;
    debug("\nmyalloc called: 0x%x\n", size);
    isFirst();
    // alignment by 8bytes
    size = ((size & 15) > 0) ? (size & -16) + 0x10 : size; 
    size += 0x10;
    size |= 1;

    debug("aligned size: 0x%x\n", size);

    void* p = NULL;
    if((size&-2) <= 0x80){
        p = findInFastBins(size&-2);
    }else{
        p = findInUnsortedBins(size&-2);
    }    
    if(p != NULL){
       debug("alloc(0x%x): %p\n", size, (char*)p+0x10);
       return (char*)p+0x10;
    }

    debug("Can't find in bins\n");
    /*
    */
    if(topChunk->size > size){
        p = allocateInTopChunk(size&-2);
    }else{
        while((topChunk->size&-2) <= (size&-2))
            if(reallocTopChunk(0x10000) == false)
                return NULL;
        
        p = allocateInTopChunk(size&-2);
    }
    debug("alloc(0x%x): %p\n", (unsigned int)size, (char*)p + 0x10); 
    /*
    */
//    p = sbrk(size);

    //debug("max: %u\n", max_size);
    //debug("allcated: %p\nsize: 0x%x\n\n", p, size);
    if(p != NULL)
        return (char*)p + 0x10;
    return NULL;
}

// update for inuse bit
void *myrealloc(void *ptr, size_t size)
{
    debug("\nmyrealloc called:%p 0x%x\n",ptr, size);
    void *p = NULL;
    size_t alignedSize = ((size & 15) > 0) ? (size & -16) + 0x10 : size; 
    alignedSize += 0x10;
    alignedSize |= 1;

    if(ptr == NULL) {
        p = myalloc(size);
        return p;
        //debug("myrealloc2: 0x%x\n", size);
    } else if (size != 0) {
        if((((allocatedChunk*)(ptr-0x10))->size&-2) == (alignedSize&-2)) return ptr;
        if((size&-2) <= 0x80){
            p = findInFastBins(alignedSize&-2);
        }else{
            p = findInUnsortedBins(alignedSize&-2);
        }
        if(p != NULL){
            memcpy(p+0x10, ptr, size);
        }else{
            while((topChunk->size&-2) <= (alignedSize&-2))
                if(reallocTopChunk(0x10000) == false)
                    return NULL;
            
            p = allocateInTopChunk(alignedSize&-2);
            memcpy(p+0x10, ptr, size);
            myfree(ptr+0x10);
        }
        //max_size += size;
        //debug("max: %u\n", max_size);
    }
    //debug("realloc(%p, 0x%x): %p\n\n", ptr, size, p);
    if(p != NULL)
        return p+0x10;
    return NULL;
}

void myfree(void *ptr)
{
    debug("\nmyfree called: %p\n", ptr);
    if(!ptr) return;
    freeChunk* chk = (freeChunk*)((char*)ptr-0x10);
    debug("prev_size: 0x%x, size: 0x%x, data: 0x%x\n", chk->prev_size, chk->size, *(uint64_t*)((char*)(chk)+0x10));
    if((chk->size&-2) <= 0x80){
        pushInFastBins(chk);
    }else{
        pushInUnsortedBins(chk);
    }
    //if(chunk->size <= 0x80)


}
