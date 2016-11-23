/*
 * Memory pool defines.
 *
 * Copyright 1996 by Gray Watson.
 *
 * This file is part of the ks_mpool package.
 *
 * Permission to use, copy, modify, and distribute this software for
 * any purpose and without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies, and that the name of Gray Watson not be used in advertising
 * or publicity pertaining to distribution of the document or software
 * without specific, written prior permission.
 *
 * Gray Watson makes no representations about the suitability of the
 * software described herein for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * The author may be reached via http://256.com/gray/
 *
 * $Id: ks_mpool.h,v 1.4 2006/05/31 20:26:11 gray Exp $
 */

#ifndef __KS_MPOOL_H__
#define __KS_MPOOL_H__

#include "ks.h"
#include <sys/types.h>

/*
 * ks_mpool flags to ks_mpool_alloc or ks_mpool_set_attr
 */

typedef enum {
	KS_MPOOL_FLAG_DEFAULT = 0,

	KS_MPOOL_FLAG_BEST_FIT = (1 << 0),
/*
 * Choose a best fit algorithm not first fit.  This takes more CPU
 * time but will result in a tighter heap.
 */

	KS_MPOOL_FLAG_HEAVY_PACKING = (1 << 1)
/*
 * This enables very heavy packing at the possible expense of CPU.
 * This affects a number of parts of the library.
 *
 * By default the 1st page of memory is reserved for the main ks_mpool
 * structure.  This flag will cause the rest of the 1st block to be
 * available for use as user memory.
 *
 * By default the library looks through the memory when freed looking
 * for a magic value.  There is an internal max size that it will look
 * and then it will give up.  This flag forces it to look until it
 * finds it.
 */
} ks_mpool_flag_t;


/*
 * Ks_Mpool error codes
 */
#define KS_MPOOL_ERROR_NONE 1	/* no error */
#define KS_MPOOL_ERROR_ARG_NULL 2	/* function argument is null */
#define KS_MPOOL_ERROR_ARG_INVALID 3	/* function argument is invalid */
#define KS_MPOOL_ERROR_PNT  4	/* invalid ks_mpool pointer */
#define KS_MPOOL_ERROR_POOL_OVER 5	/* ks_mpool structure was overwritten */
#define KS_MPOOL_ERROR_PAGE_SIZE 6	/* could not get system page-size */
#define KS_MPOOL_ERROR_OPEN_ZERO 7	/* could not open /dev/zero */
#define KS_MPOOL_ERROR_NO_MEM 8	/* no memory available */
#define KS_MPOOL_ERROR_MMAP 9	/* problems with mmap */
#define KS_MPOOL_ERROR_SIZE 10	/* error processing requested size */
#define KS_MPOOL_ERROR_TOO_BIG 11	/* allocation exceeded max size */
#define KS_MPOOL_ERROR_MEM  12	/* invalid memory address */
#define KS_MPOOL_ERROR_MEM_OVER 13	/* memory lower bounds overwritten */
#define KS_MPOOL_ERROR_NOT_FOUND 14	/* memory block not found in pool */
#define KS_MPOOL_ERROR_IS_FREE 15	/* memory block already free */
#define KS_MPOOL_ERROR_BLOCK_STAT 16	/* invalid internal block status */
#define KS_MPOOL_ERROR_FREE_ADDR 17	/* invalid internal free address */
#define KS_MPOOL_ERROR_UNUSED  18	/* UNUSED */
#define KS_MPOOL_ERROR_NO_PAGES 19	/* ran out of pages in pool */
#define KS_MPOOL_ERROR_ALLOC 20	/* calloc,malloc,free,realloc failed */
#define KS_MPOOL_ERROR_PNT_OVER 21	/* pointer structure was overwritten */
#define KS_MPOOL_ERROR_INVALID_POINTER 22	/* address is not valid */
/*
 * Ks_Mpool function IDs for the ks_mpool_log_func callback function.
 */
#define KS_MPOOL_FUNC_CLOSE 1	/* ks_mpool_close function called */
#define KS_MPOOL_FUNC_CLEAR 2	/* ks_mpool_clear function called */
#define KS_MPOOL_FUNC_ALLOC 3	/* ks_mpool_alloc function called */
#define KS_MPOOL_FUNC_CALLOC 4	/* ks_mpool_calloc function called */
#define KS_MPOOL_FUNC_FREE  5	/* ks_mpool_free function called */
#define KS_MPOOL_FUNC_RESIZE 6	/* ks_mpool_resize function called */

/*
 * void ks_mpool_log_func_t
 *
 * DESCRIPTION:
 *
 * Ks_Mpool transaction log function.
 *
 * RETURNS:
 *
 * None.
 *
 * ARGUMENT:
 *
 * mp_p -> Associated ks_mpool address.
 *
 * func_id -> Integer function ID which identifies which ks_mpool
 * function is being called.
 *
 * byte_size -> Optionally specified byte size.
 *
 * ele_n -> Optionally specified element number.  For ks_mpool_calloc
 * only.
 *
 * new_addr -> Optionally specified new address.  For ks_mpool_alloc,
 * ks_mpool_calloc, and ks_mpool_resize only.
 *
 * old_addr -> Optionally specified old address.  For ks_mpool_resize and
 * ks_mpool_free only.
 *
 * old_byte_size -> Optionally specified old byte size.  For
 * ks_mpool_resize only.
 */
typedef void (*ks_mpool_log_func_t) (const void *mp_p,
									 const int func_id,
									 const unsigned long byte_size,
									 const unsigned long ele_n, const void *old_addr, const void *new_addr, const unsigned long old_byte_size);

/*
 * ks_mpool_t *ks_mpool_raw_open
 *
 * DESCRIPTION:
 *
 * Open/allocate a new memory pool.
 *
 * RETURNS:
 *
 * Success - Pool pointer which must be passed to ks_mpool_close to
 * deallocate.
 *
 * Failure - NULL
 *
 * ARGUMENTS:
 *
 * flags -> Flags to set attributes of the memory pool.  See the top
 * of ks_mpool.h.
 *
 * page_size -> Set the internal memory page-size.  This must be a
 * multiple of the getpagesize() value.  Set to 0 for the default.
 *
 * start_addr -> Starting address to try and allocate memory pools.
 * This is ignored if the KS_MPOOL_FLAG_USE_SBRK is enabled.
 *
 * error_p <- Pointer to integer which, if not NULL, will be set with
 * a ks_mpool error code.
 */
//KS_DECLARE(ks_mpool_t *) ks_mpool_raw_open(const unsigned int flags, const unsigned int page_size,
//                  void *start_addr, int *error_p);



/*
 * ks_mpool_t *ks_mpool_open
 *
 * DESCRIPTION:
 *
 * Open/allocate a new memory pool.
 *
 * RETURNS:
 *
 * Success - KS_STATUS_SUCCESS
 *
 * Failure - KS_STATUS_FAIL
 *
 * ARGUMENTS:
 *
 * poolP <- pointer to new pool that will be set on success
 *
 * error_p <- Pointer to integer which, if not NULL, will be set with
 * a ks_mpool error code.
 */

KS_DECLARE(ks_status_t) ks_mpool_open(ks_mpool_t **poolP, int *error_p);


/*
 * int ks_mpool_raw_close
 *
 * DESCRIPTION:
 *
 * Close/free a memory allocation pool previously opened with
 * ks_mpool_open.
 *
 * RETURNS:
 *
 * Success - KS_MPOOL_ERROR_NONE
 *
 * Failure - Ks_Mpool error code
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to our memory pool.
 */
//static int ks_mpool_raw_close(ks_mpool_t *mp_p);

/*
 * ks_status_t ks_mpool_close
 *
 * DESCRIPTION:
 *
 * Close/free a memory allocation pool previously opened with
 * ks_mpool_open.
 *
 * RETURNS:
 *
 * Success - KS_MPOOL_ERROR_NONE
 *
 * Failure - Ks_Mpool error code
 *
 * ARGUMENTS:
 *
 * mp_pp <-> Pointer to pointer of our memory pool.
 * error_p <- Pointer to error
 */

KS_DECLARE(ks_status_t) ks_mpool_close(ks_mpool_t **mp_pP, int *error_p);

/*
 * int ks_mpool_clear
 *
 * DESCRIPTION:
 *
 * Wipe an opened memory pool clean so we can start again.
 *
 * RETURNS:
 *
 * Success - KS_MPOOL_ERROR_NONE
 *
 * Failure - Ks_Mpool error code
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to our memory pool.
 */
KS_DECLARE(int) ks_mpool_clear(ks_mpool_t *mp_p);

/*
 * void *ks_mpool_alloc
 *
 * DESCRIPTION:
 *
 * Allocate space for bytes inside of an already open memory pool.
 *
 * RETURNS:
 *
 * Success - Pointer to the address to use.
 *
 * Failure - NULL
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to the memory pool.  If NULL then it will do a
 * normal malloc.
 *
 * byte_size -> Number of bytes to allocate in the pool.  Must be >0.
 *
 * error_p <- Pointer to integer which, if not NULL, will be set with
 * a ks_mpool error code.
 */
KS_DECLARE(void *) ks_mpool_alloc(ks_mpool_t *mp_p, const unsigned long byte_size, int *error_p);

/*
 * void *ks_mpool_calloc
 *
 * DESCRIPTION:
 *
 * Allocate space for elements of bytes in the memory pool and zero
 * the space afterwards.
 *
 * RETURNS:
 *
 * Success - Pointer to the address to use.
 *
 * Failure - NULL
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to the memory pool.  If NULL then it will do a
 * normal calloc.
 *
 * ele_n -> Number of elements to allocate.
 *
 * ele_size -> Number of bytes per element being allocated.
 *
 * error_p <- Pointer to integer which, if not NULL, will be set with
 * a ks_mpool error code.
 */
KS_DECLARE(void *) ks_mpool_calloc(ks_mpool_t *mp_p, const unsigned long ele_n, const unsigned long ele_size, int *error_p);

/*
 * int ks_mpool_free
 *
 * DESCRIPTION:
 *
 * Free an address from a memory pool.
 *
 * RETURNS:
 *
 * Success - KS_MPOOL_ERROR_NONE
 *
 * Failure - Ks_Mpool error code
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to the memory pool.  If NULL then it will do a
 * normal free.
 *
 * addr <-> Address to free.
 *
 */

KS_DECLARE(int) ks_mpool_free(ks_mpool_t *mp_p, void *addr);

/*
 * void *ks_mpool_resize
 *
 * DESCRIPTION:
 *
 * Reallocate an address in a mmeory pool to a new size.  
 *
 * RETURNS:
 *
 * Success - Pointer to the address to use.
 *
 * Failure - NULL
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to the memory pool.  If NULL then it will do a
 * normal realloc.
 *
 * old_addr -> Previously allocated address.
 *
 * new_byte_size -> New size of the allocation.
 *
 * error_p <- Pointer to integer which, if not NULL, will be set with
 * a ks_mpool error code.
 */
KS_DECLARE(void *) ks_mpool_resize(ks_mpool_t *mp_p, void *old_addr, const unsigned long new_byte_size, int *error_p);

/*
 * int ks_mpool_stats
 *
 * DESCRIPTION:
 *
 * Return stats from the memory pool.
 *
 * RETURNS:
 *
 * Success - KS_MPOOL_ERROR_NONE
 *
 * Failure - Ks_Mpool error code
 *
 * ARGUMENTS:
 *
 * mp_p -> Pointer to the memory pool.
 *
 * page_size_p <- Pointer to an unsigned integer which, if not NULL,
 * will be set to the page-size of the pool.
 *
 * num_alloced_p <- Pointer to an unsigned long which, if not NULL,
 * will be set to the number of pointers currently allocated in pool.
 *
 * user_alloced_p <- Pointer to an unsigned long which, if not NULL,
 * will be set to the number of user bytes allocated in this pool.
 *
 * max_alloced_p <- Pointer to an unsigned long which, if not NULL,
 * will be set to the maximum number of user bytes that have been
 * allocated in this pool.
 *
 * tot_alloced_p <- Pointer to an unsigned long which, if not NULL,
 * will be set to the total amount of space (including administrative
 * overhead) used by the pool.
 */
KS_DECLARE(int) ks_mpool_stats(const ks_mpool_t *mp_p, unsigned int *page_size_p,
							   unsigned long *num_alloced_p, unsigned long *user_alloced_p, unsigned long *max_alloced_p, unsigned long *tot_alloced_p);

/*
 * int ks_mpool_set_log_func
 *
 * DESCRIPTION:
 *
 * Set a logging callback function to be called whenever there was a
 * memory transaction.  See ks_mpool_log_func_t.
 *
 * RETURNS:
 *
 * Success - KS_MPOOL_ERROR_NONE
 *
 * Failure - Ks_Mpool error code
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to the memory pool.
 *
 * log_func -> Log function (defined in ks_mpool.h) which will be called
 * with each ks_mpool transaction.
 */
KS_DECLARE(int) ks_mpool_set_log_func(ks_mpool_t *mp_p, ks_mpool_log_func_t log_func);

/*
 * int ks_mpool_set_max_pages
 *
 * DESCRIPTION:
 *
 * Set the maximum number of pages that the library will use.  Once it
 * hits the limit it will return KS_MPOOL_ERROR_NO_PAGES.
 *
 * NOTE: if the KS_MPOOL_FLAG_HEAVY_PACKING is set then this max-pages
 * value will include the page with the ks_mpool header structure in it.
 * If the flag is _not_ set then the max-pages will not include this
 * first page.
 *
 * RETURNS:
 *
 * Success - KS_MPOOL_ERROR_NONE
 *
 * Failure - Ks_Mpool error code
 *
 * ARGUMENTS:
 *
 * mp_p <-> Pointer to the memory pool.
 *
 * max_pages -> Maximum number of pages used by the library.
 */
KS_DECLARE(int) ks_mpool_set_max_pages(ks_mpool_t *mp_p, const unsigned int max_pages);

/*
 * const char *ks_mpool_strerror
 *
 * DESCRIPTION:
 *
 * Return the corresponding string for the error number.
 *
 * RETURNS:
 *
 * Success - String equivalient of the error.
 *
 * Failure - String "invalid error code"
 *
 * ARGUMENTS:
 *
 * error -> Error number that we are converting.
 */
KS_DECLARE(const char *) ks_mpool_strerror(const int error);

KS_DECLARE(ks_status_t) ks_mpool_set_cleanup(ks_mpool_t *mp_p, void *ptr, void *arg, int type, ks_mpool_cleanup_fn_t fn);

#define ks_mpool_safe_free(_p, _a) ks_mpool_free(_p, _a); _a = NULL

/*<<<<<<<<<<   This is end of the auto-generated output from fillproto. */

#endif /* ! __KS_MPOOL_H__ */

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
