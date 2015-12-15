/*
 * Copyright (C) 2013-2016 Red Hat, Inc.
 *
 * bus1 is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/compat.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "main.h"
#include "util.h"

/**
 * bus1_import_fixed_ioctl() - copy fixed-size ioctl payload from user
 * @arg:	user-provided ioctl argument
 * @size:	exact size of the ioctl payload
 *
 * Copy ioctl payload from user-space into kernel-space. Backing memory is
 * dynamically allocated, alignment restrictions are checked.
 *
 * Return: Pointer to dynamically allocated payload, ERR_PTR on failure.
 */
void *bus1_import_fixed_ioctl(unsigned long arg, size_t size)
{
	if (arg & 0x7)
		return ERR_PTR(-EFAULT);

	return memdup_user((void __user *)arg, size);
}

/**
 * bus1_import_dynamic_ioctl() - copy dynamic-size ioctl payload from user
 * @arg:	user-provided ioctl argument
 * @min_size:	minimum size of the ioctl payload
 *
 * Copy ioctl payload from user-space into kernel-space. The first 8 bytes of
 * the ioctl payload must contain the actual size of the payload. Data is thus
 * copied in two steps: First the size is copied into kernel-space, then the
 * whole payload is copied into an allocated buffer.
 *
 * Alignment restrictions are checked.
 *
 * Return: Pointer to dynamically allocated payload, ERR_PTR on failure.
 */
void *bus1_import_dynamic_ioctl(unsigned long arg, size_t min_size)
{
	void *param;
	u64 size;

	if (WARN_ON(min_size < sizeof(u64)))
		return ERR_PTR(-EFAULT);
	if ((arg & 0x7) || get_user(size, (u64 __user *)arg))
		return ERR_PTR(-EFAULT);
	if (size < min_size || size > BUS1_IOCTL_MAX_SIZE)
		return ERR_PTR(-EMSGSIZE);

	param = bus1_import_fixed_ioctl(arg, size);
	if (IS_ERR(param))
		return ERR_CAST(param);

	/* size might have changed, fix it up if it did */
	*(u64 *)param = size;
	return param;
}

/**
 * bus1_import_vecs() - import vectors from user
 * @out_vecs:		kernel memory to store vecs, preallocated
 * @out_length:		output storage for sum of all vectors lengths
 * @vecs:		user pointer for vectors
 * @n_vecs:		number of vectors to import
 * @is_compat:		whether this should use compat paths
 *
 * This copies the given vectors from user memory into the preallocated kernel
 * buffer. Sanity checks are performed on the memory of the vector-array, the
 * memory pointed to by the vectors and on the overall size calculation.
 *
 * If @is_compat is true, then the compat paths are used.
 *
 * If the vectors were copied successfully, @out_length will contain the sum of
 * all vector-lengths.
 *
 * Unlike most other functions, this function might modify its output buffer
 * even if it fails. That is, @out_vecs might contain garbage if this function
 * fails. This is done for performance reasons.
 *
 * Return: 0 on success, negative error code on failure.
 */
int bus1_import_vecs(struct iovec *out_vecs,
		     size_t *out_length,
		     const void __user *vecs,
		     size_t n_vecs,
		     bool is_compat)
{
	size_t i, length = 0;

	if (n_vecs > UIO_MAXIOV)
		return -EMSGSIZE;
	if (n_vecs == 0) {
		*out_length = 0;
		return 0;
	}

	if (IS_ENABLED(CONFIG_COMPAT) && is_compat) {
		/*
		 * Compat types and macros are protected by CONFIG_COMPAT,
		 * rather than providing a fallback. We want compile-time
		 * coverage, so provide fallback types. The IS_ENABLED(COMPAT)
		 * condition guarantees this is collected by the dead-code
		 * elimination, anyway.
		 */
#if IS_ENABLED(CONFIG_COMPAT)
		const struct compat_iovec __user *uvecs = vecs;
		compat_uptr_t v_base;
		compat_size_t v_len;
		compat_ssize_t v_slen;
#else
		const struct iovec __user *uvecs = vecs;
		void __user *v_base;
		size_t v_len;
		ssize_t v_slen;
#endif
		void __user *v_ptr;

		if (unlikely(!access_ok(VERIFY_READ, vecs,
					sizeof(*uvecs) * n_vecs)))
			return -EFAULT;

		for (i = 0; i < n_vecs; ++i) {
			if (unlikely(__get_user(v_base, &uvecs[i].iov_base) ||
				     __get_user(v_len, &uvecs[i].iov_len)))
				return -EFAULT;

#if IS_ENABLED(CONFIG_COMPAT)
			v_ptr = compat_ptr(v_base);
#else
			v_ptr = v_base;
#endif
			v_slen = v_len;

			if (unlikely(v_slen < 0 ||
				     (typeof(v_len))v_slen != v_len))
				return -EMSGSIZE;
			if (unlikely(!access_ok(VERIFY_READ, v_ptr, v_len)))
				return -EFAULT;
			if (unlikely((size_t)v_len > MAX_RW_COUNT - length))
				return -EMSGSIZE;

			out_vecs[i].iov_base = v_ptr;
			out_vecs[i].iov_len = v_len;
			length += v_len;
		}
	} else {
		void __user *v_base;
		size_t v_len;

		if (copy_from_user(out_vecs, vecs, sizeof(*out_vecs) * n_vecs))
			return -EFAULT;

		for (i = 0; i < n_vecs; ++i) {
			v_base = out_vecs[i].iov_base;
			v_len = out_vecs[i].iov_len;

			if (unlikely((ssize_t)v_len < 0))
				return -EMSGSIZE;
			if (unlikely(!access_ok(VERIFY_READ, v_base, v_len)))
				return -EFAULT;
			if (unlikely(v_len > MAX_RW_COUNT - length))
				return -EMSGSIZE;

			length += v_len;
		}
	}

	*out_length = length;
	return 0;
}
