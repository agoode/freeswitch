#include "ks_dht.h"
#include "ks_dht-int.h"

/**
 *
 */
KS_DECLARE(ks_status_t) ks_dht2_endpoint_alloc(ks_dht2_endpoint_t **endpoint, ks_pool_t *pool)
{
	ks_dht2_endpoint_t *ep;

	ks_assert(endpoint);
	ks_assert(pool);
	
	*endpoint = ep = ks_pool_alloc(pool, sizeof(ks_dht2_endpoint_t));
	ep->pool = pool;
	ep->sock = KS_SOCK_INVALID;

	return KS_STATUS_SUCCESS;
}

/**
 *
 */
KS_DECLARE(ks_status_t) ks_dht2_endpoint_prealloc(ks_dht2_endpoint_t *endpoint, ks_pool_t *pool)
{
	ks_assert(endpoint);
	ks_assert(pool);

	endpoint->pool = pool;
	endpoint->sock = KS_SOCK_INVALID;

	return KS_STATUS_SUCCESS;
}

/**
 *
 */
KS_DECLARE(ks_status_t) ks_dht2_endpoint_free(ks_dht2_endpoint_t *endpoint)
{
	ks_assert(endpoint);

	ks_dht2_endpoint_deinit(endpoint);
	ks_pool_free(endpoint->pool, endpoint);

	return KS_STATUS_SUCCESS;
}


/**
 *
 */
KS_DECLARE(ks_status_t) ks_dht2_endpoint_init(ks_dht2_endpoint_t *endpoint, const ks_sockaddr_t *addr, ks_socket_t sock)
{
	ks_assert(endpoint);
	ks_assert(endpoint->pool);
	ks_assert(addr);
	ks_assert(addr->family == AF_INET || addr->family == AF_INET6);

	endpoint->addr = *addr;
	endpoint->sock = sock;
	
	return KS_STATUS_SUCCESS;
}

/**
 *
 */
KS_DECLARE(ks_status_t) ks_dht2_endpoint_deinit(ks_dht2_endpoint_t *endpoint)
{
	ks_assert(endpoint);

	if (endpoint->sock != KS_SOCK_INVALID) {
		ks_socket_close(&endpoint->sock);
		endpoint->sock = KS_SOCK_INVALID;
	}

	return KS_STATUS_SUCCESS;
}


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