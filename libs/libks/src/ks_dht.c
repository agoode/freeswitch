/*
Copyright (c) 2009-2011 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

/* Please, please, please.

   You are welcome to integrate this code in your favourite Bittorrent
   client.  Please remember, however, that it is meant to be usable by
   others, including myself.  This means no C++, no relicensing, and no
   gratuitious changes to the coding style.  And please send back any
   improvements to the author. */

#include "ks.h"
#include "sodium.h"

#ifndef MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

//usr/src/freeswitch.git/libs/libks/.libs/libks.so: undefined reference to `dht_random_bytes'
//usr/src/freeswitch.git/libs/libks/.libs/libks.so: undefined reference to `dht_blacklisted'
//usr/src/freeswitch.git/libs/libks/.libs/libks.so: undefined reference to `dht_hash'

int dht_blacklisted(const struct sockaddr *sa, int salen)
{
	return 0;
}
void dht_hash(void *hash_return, int hash_size, const void *v1, int len1, const void *v2, int len2, const void *v3, int len3)
{
	return;
}
int dht_random_bytes(void *buf, size_t size)
{
	return 0;
}


#ifdef _WIN32

#undef EAFNOSUPPORT
#define EAFNOSUPPORT WSAEAFNOSUPPORT

static int
set_nonblocking(int fd, int nonblocking)
{
    int rc;

    unsigned long mode = !!nonblocking;
    rc = ioctlsocket(fd, FIONBIO, &mode);
    if (rc != 0) {
        errno = WSAGetLastError();
	}
    return (rc == 0 ? 0 : -1);
}

static int
random(void)
{
    return rand();
}

/* Windows Vista and later already provide the implementation. */
#if _WIN32_WINNT < 0x0600
extern const char *inet_ntop(int, const void *, char *, socklen_t);
#endif

#else

static int
set_nonblocking(int fd, int nonblocking)
{
    int rc;
    rc = fcntl(fd, F_GETFL, 0);
    if (rc < 0) return -1;

    rc = fcntl(fd, F_SETFL, nonblocking?(rc | O_NONBLOCK):(rc & ~O_NONBLOCK));
    if (rc < 0) return -1;

    return 0;
}

#endif

/* We set sin_family to 0 to mark unused slots. */
#if AF_INET == 0 || AF_INET6 == 0
#error You lose
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
/* nothing */
#elif defined(__GNUC__)
#define inline __inline
#if  (__GNUC__ >= 3)
#define restrict __restrict
#else
#define restrict /**/
#endif
#else
#define inline /**/
#define restrict /**/
#endif

#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#define MIN(x, y) ((x) <= (y) ? (x) : (y))

struct node {
    unsigned char id[20];
    struct sockaddr_storage ss;
    int sslen;
    time_t time;                /* time of last message received */
    time_t reply_time;          /* time of last correct reply received */
    time_t pinged_time;         /* time of last request */
    int pinged;                 /* how many requests we sent since last reply */
    struct node *next;
};

struct bucket {
    int af;
    unsigned char first[20];
    int count;                  /* number of nodes */
    time_t time;                /* time of last reply in this bucket */
    struct node *nodes;
    struct sockaddr_storage cached;  /* the address of a likely candidate */
    int cachedlen;
    struct bucket *next;
};

struct search_node {
    unsigned char id[20];
    struct sockaddr_storage ss;
    int sslen;
    time_t request_time;        /* the time of the last unanswered request */
    time_t reply_time;          /* the time of the last reply */
    int pinged;
    unsigned char token[40];
    int token_len;
    int replied;                /* whether we have received a reply */
    int acked;                  /* whether they acked our announcement */
};

/* When performing a search, we search for up to SEARCH_NODES closest nodes
   to the destination, and use the additional ones to backtrack if any of
   the target 8 turn out to be dead. */
#define SEARCH_NODES 14

struct search {
    unsigned short tid;
    int af;
    time_t step_time;           /* the time of the last search_step */
    unsigned char id[20];
    unsigned short port;        /* 0 for pure searches */
    int done;
    struct search_node nodes[SEARCH_NODES];
    int numnodes;
    struct search *next;
};

struct peer {
    time_t time;
    unsigned char ip[16];
    unsigned short len;
    unsigned short port;
};

/* The maximum number of peers we store for a given hash. */
#ifndef DHT_MAX_PEERS
#define DHT_MAX_PEERS 2048
#endif

/* The maximum number of hashes we're willing to track. */
#ifndef DHT_MAX_HASHES
#define DHT_MAX_HASHES 16384
#endif

/* The maximum number of searches we keep data about. */
#ifndef DHT_MAX_SEARCHES
#define DHT_MAX_SEARCHES 1024
#endif

/* The time after which we consider a search to be expirable. */
#ifndef DHT_SEARCH_EXPIRE_TIME
#define DHT_SEARCH_EXPIRE_TIME (62 * 60)
#endif

struct storage {
    unsigned char id[20];
    int numpeers, maxpeers;
    struct peer *peers;
    struct storage *next;
};

static struct storage * find_storage(dht_handle_t *h, const unsigned char *id);
static void flush_search_node(struct search_node *n, struct search *sr);

static int send_ping(dht_handle_t *h, const struct sockaddr *sa, int salen,
                     const unsigned char *tid, int tid_len);
static int send_pong(dht_handle_t *h, const struct sockaddr *sa, int salen,
                     const unsigned char *tid, int tid_len);
static int send_find_node(dht_handle_t *h, const struct sockaddr *sa, int salen,
                          const unsigned char *tid, int tid_len,
                          const unsigned char *target, int want, int confirm);
static int send_nodes_peers(dht_handle_t *h, const struct sockaddr *sa, int salen,
                            const unsigned char *tid, int tid_len,
                            const unsigned char *nodes, int nodes_len,
                            const unsigned char *nodes6, int nodes6_len,
                            int af, struct storage *st,
                            const unsigned char *token, int token_len);
static int send_closest_nodes(dht_handle_t *h, const struct sockaddr *sa, int salen,
                              const unsigned char *tid, int tid_len,
                              const unsigned char *id, int want,
                              int af, struct storage *st,
                              const unsigned char *token, int token_len);
static int send_get_peers(dht_handle_t *h, const struct sockaddr *sa, int salen,
                          unsigned char *tid, int tid_len,
                          unsigned char *infohash, int want, int confirm);
static int send_announce_peer(dht_handle_t *h, const struct sockaddr *sa, int salen,
                              unsigned char *tid, int tid_len,
                              unsigned char *infohas, unsigned short port,
                              unsigned char *token, int token_len, int confirm);
static int send_peer_announced(dht_handle_t *h, const struct sockaddr *sa, int salen,
                               unsigned char *tid, int tid_len);
static int send_error(dht_handle_t *h, const struct sockaddr *sa, int salen,
                      unsigned char *tid, int tid_len,
                      int code, const char *message);

typedef enum {
	DHT_MSG_INVALID = 0,
	DHT_MSG_ERROR = 1,
	DHT_MSG_REPLY = 2,
	DHT_MSG_PING = 3,
	DHT_MSG_FIND_NODE = 4,
	DHT_MSG_GET_PEERS = 5,
	DHT_MSG_ANNOUNCE_PEER = 6,
	DHT_MSG_STORE_PUT = 7
} dht_msg_type_t;

#define WANT4 1
#define WANT6 2

static dht_msg_type_t parse_message(struct bencode *bencode_p,
									unsigned char *tid_return, int *tid_len,
									unsigned char *id_return);

static const unsigned char zeroes[20] = {0};
static const unsigned char v4prefix[16] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0
};

#define MAX_TOKEN_BUCKET_TOKENS 400

/* The maximum number of nodes that we snub.  There is probably little
   reason to increase this value. */
#ifndef DHT_MAX_BLACKLISTED
#define DHT_MAX_BLACKLISTED 10
#endif

struct ks_dht_store_entry_s {
    const char *key;

	ks_time_t received; /* recieved timestamp */
	ks_time_t last_announce;
	ks_time_t expiration; /* When should 'my' message be automatically expired. If not set will be expired after 10 minutes */

	/* Top level struct pointers. Will need to be freed */
	struct bencode *bencode_message_raw;
	struct bencode *payload_bencode;
	cJSON *body;

	/* Short cut accessor pointers. Do not free these. */
	const char *content_type;
	const char *payload_raw;

	unsigned int serial;
	ks_bool_t mine;
	ks_pool_t *pool;
};

struct ks_dht_store_s {
    ks_time_t next_expiring;
	ks_hash_t *hash;
	ks_pool_t *pool;
};

struct dht_handle_s {
	int dht_socket;
	int dht_socket6;

	time_t search_time;
	time_t confirm_nodes_time;
	time_t rotate_secrets_time;

	unsigned char myid[20];
	int have_v;
	unsigned char my_v[9];
	unsigned char secret[8];
	unsigned char oldsecret[8];

	struct bucket *buckets;
	struct bucket *buckets6;
	struct storage *storage;
	int numstorage;

	struct search *searches;
	int numsearches;
	unsigned short search_id;

	struct sockaddr_storage blacklist[DHT_MAX_BLACKLISTED];
	int next_blacklisted;

	ks_time_t now;
	time_t mybucket_grow_time, mybucket6_grow_time;
	time_t expire_stuff_time;

	time_t token_bucket_time;
	int token_bucket_tokens;

	ks_pool_t *pool;
	struct ks_dht_store_s *store;
};

static unsigned char *debug_printable(const unsigned char *buf, unsigned char *out, int buflen)
{
    int i;
	for (i = 0; i < buflen; i++) {
		out[i] = (buf[i] >= 32 && buf[i] <= 126) ? buf[i] : '.';
	}
	return out;
}

static void print_hex(FILE *f, const unsigned char *buf, int buflen)
{
    int i;
    for (i = 0; i < buflen; i++) {
        fprintf(f, "%02x", buf[i]);
	}
}

static int is_martian(const struct sockaddr *sa)
{
    switch(sa->sa_family) {
    case AF_INET: {
        struct sockaddr_in *sin = (struct sockaddr_in*)sa;
        const unsigned char *address = (const unsigned char*)&sin->sin_addr;
        return sin->sin_port == 0 ||
            (address[0] == 0) ||
            (address[0] == 127) ||
            ((address[0] & 0xE0) == 0xE0);
    }
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
        const unsigned char *address = (const unsigned char*)&sin6->sin6_addr;
        return sin6->sin6_port == 0 ||
            (address[0] == 0xFF) ||
            (address[0] == 0xFE && (address[1] & 0xC0) == 0x80) ||
            (memcmp(address, zeroes, 15) == 0 &&
             (address[15] == 0 || address[15] == 1)) ||
            (memcmp(address, v4prefix, 12) == 0);
    }

    default:
        return 0;
    }
}

/* Forget about the ``XOR-metric''.  An id is just a path from the
   root of the tree, so bits are numbered from the start. */

static int id_cmp(const unsigned char *restrict id1, const unsigned char *restrict id2)
{
    /* Memcmp is guaranteed to perform an unsigned comparison. */
    return memcmp(id1, id2, 20);
}

/* Find the lowest 1 bit in an id. */
static int lowbit(const unsigned char *id)
{
    int i, j;

    for (i = 19; i >= 0; i--) {
        if (id[i] != 0) {
			break;
		}
	}

    if (i < 0) return -1;

    for (j = 7; j >= 0; j--) {
        if ((id[i] & (0x80 >> j)) != 0) {
			break;
		}
	}

    return 8 * i + j;
}

/* Find how many bits two ids have in common. */
static int common_bits(const unsigned char *id1, const unsigned char *id2)
{
    int i, j;
    unsigned char xor;
    for (i = 0; i < 20; i++) {
        if (id1[i] != id2[i]) {
            break;
		}
    }

    if (i == 20) {
        return 160;
	}

    xor = id1[i] ^ id2[i];

    j = 0;
    while ((xor & 0x80) == 0) {
        xor <<= 1;
        j++;
    }

    return 8 * i + j;
}

/* Determine whether id1 or id2 is closer to ref */
static int xorcmp(const unsigned char *id1, const unsigned char *id2, const unsigned char *ref)
{
    int i;
    for (i = 0; i < 20; i++) {
        unsigned char xor1, xor2;
        if (id1[i] == id2[i]) {
            continue;
		}
        xor1 = id1[i] ^ ref[i];
        xor2 = id2[i] ^ ref[i];
        if (xor1 < xor2) {
            return -1;
		}
		return 1;
    }
    return 0;
}

/* We keep buckets in a sorted linked list.  A bucket b ranges from
   b->first inclusive up to b->next->first exclusive. */
static int in_bucket(const unsigned char *id, struct bucket *b)
{
    return id_cmp(b->first, id) <= 0 && (b->next == NULL || id_cmp(id, b->next->first) < 0);
}

static struct bucket *find_bucket(dht_handle_t *h, unsigned const char *id, int af)
{
    struct bucket *b = af == AF_INET ? h->buckets : h->buckets6;

    if (b == NULL) {
        return NULL;
	}

    while (1) {
        if (b->next == NULL) {
            return b;
		}

        if (id_cmp(id, b->next->first) < 0) {
            return b;
		}

        b = b->next;
    }
}

static struct bucket *previous_bucket(dht_handle_t *h, struct bucket *b)
{
    struct bucket *p = b->af == AF_INET ? h->buckets : h->buckets6;

    if (b == p) {
        return NULL;
	}

    while (1) {
        if (p->next == NULL) {
            return NULL;
		}

        if (p->next == b) {
            return p;
		}

        p = p->next;
    }
}

/* Every bucket contains an unordered list of nodes. */
static struct node *find_node(dht_handle_t *h, const unsigned char *id, int af)
{
    struct bucket *b = find_bucket(h, id, af);
    struct node *n;

    if (b == NULL)
        return NULL;

    n = b->nodes;
    while (n) {
        if (id_cmp(n->id, id) == 0) {
            return n;
		}
        n = n->next;
    }
    return NULL;
}

/* Return a random node in a bucket. */
static struct node *random_node(struct bucket *b)
{
    struct node *n;
    int nn;

    if (b->count == 0) {
        return NULL;
	}

    nn = random() % b->count;
    n = b->nodes;
    while (nn > 0 && n) {
        n = n->next;
        nn--;
    }
    return n;
}

/* Return the middle id of a bucket. */
static int bucket_middle(struct bucket *b, unsigned char *id_return)
{
    int bit1 = lowbit(b->first);
    int bit2 = b->next ? lowbit(b->next->first) : -1;
    int bit = MAX(bit1, bit2) + 1;

    if (bit >= 160) {
        return -1;
	}

    memcpy(id_return, b->first, 20);
    id_return[bit / 8] |= (0x80 >> (bit % 8));
    return 1;
}

/* Return a random id within a bucket. */
static int bucket_random(struct bucket *b, unsigned char *id_return)
{
    int bit1 = lowbit(b->first);
    int bit2 = b->next ? lowbit(b->next->first) : -1;
    int bit = MAX(bit1, bit2) + 1;
    int i;

    if (bit >= 160) {
        memcpy(id_return, b->first, 20);
        return 1;
    }

    memcpy(id_return, b->first, bit / 8);
    id_return[bit / 8] = b->first[bit / 8] & (0xFF00 >> (bit % 8));
    id_return[bit / 8] |= random() & 0xFF >> (bit % 8);
    for (i = bit / 8 + 1; i < 20; i++) {
        id_return[i] = random() & 0xFF;
	}
    return 1;
}

/* Insert a new node into a bucket. */
static struct node *insert_node(dht_handle_t *h, struct node *node)
{
    struct bucket *b = find_bucket(h, node->id, node->ss.ss_family);

    if (b == NULL) {
        return NULL;
	}

    node->next = b->nodes;
    b->nodes = node;
    b->count++;
    return node;
}

/* This is our definition of a known-good node. */
static int node_good(dht_handle_t *h, struct node *node)
{
    return node->pinged <= 2 && node->reply_time >= h->now - 7200 && node->time >= h->now - 900;
}

/* Our transaction-ids are 4-bytes long, with the first two bytes identi-
   fying the kind of request, and the remaining two a sequence number in
   host order. */

static void make_tid(unsigned char *tid_return, const char *prefix, unsigned short seqno)
{
    tid_return[0] = prefix[0] & 0xFF;
    tid_return[1] = prefix[1] & 0xFF;
    memcpy(tid_return + 2, &seqno, 2);
}

static int tid_match(const unsigned char *tid, const char *prefix, unsigned short *seqno_return)
{
    if (tid[0] == (prefix[0] & 0xFF) && tid[1] == (prefix[1] & 0xFF)) {
        if (seqno_return) {
            memcpy(seqno_return, tid + 2, 2);
		}
        return 1;
    }

	return 0;
}

/* Every bucket caches the address of a likely node.  Ping it. */
static int send_cached_ping(dht_handle_t *h, struct bucket *b)
{
    unsigned char tid[4];
    int rc;
    /* We set family to 0 when there's no cached node. */
    if (b->cached.ss_family == 0) {
        return 0;
	}

    ks_log(KS_LOG_DEBUG, "Sending ping to cached node.\n");
    make_tid(tid, "pn", 0);
    rc = send_ping(h, (struct sockaddr*)&b->cached, b->cachedlen, tid, 4);
    b->cached.ss_family = 0;
    b->cachedlen = 0;
    return rc;
}

/* Called whenever we send a request to a node, increases the ping count
   and, if that reaches 3, sends a ping to a new candidate. */
static void pinged(dht_handle_t *h, struct node *n, struct bucket *b)
{
    n->pinged++;
    n->pinged_time = h->now;
    if (n->pinged >= 3) {
        send_cached_ping(h, b ? b : find_bucket(h, n->id, n->ss.ss_family));
	}
}

/* The internal blacklist is an LRU cache of nodes that have sent
   incorrect messages. */
static void blacklist_node(dht_handle_t *h, const unsigned char *id, const struct sockaddr *sa, int salen)
{
    int i;

    ks_log(KS_LOG_DEBUG, "Blacklisting broken node.\n");

    if (id) {
        struct node *n;
        struct search *sr;
        /* Make the node easy to discard. */
        n = find_node(h, id, sa->sa_family);
        if (n) {
            n->pinged = 3;
            pinged(h, n, NULL);
        }
        /* Discard it from any searches in progress. */
        sr = h->searches;
        while (sr) {
            for (i = 0; i < sr->numnodes; i++) {
                if (id_cmp(sr->nodes[i].id, id) == 0) {
                    flush_search_node(&sr->nodes[i], sr);
				}
			}
            sr = sr->next;
        }
    }
    /* And make sure we don't hear from it again. */
    memcpy(&h->blacklist[h->next_blacklisted], sa, salen);
    h->next_blacklisted = (h->next_blacklisted + 1) % DHT_MAX_BLACKLISTED;
}

static int node_blacklisted(dht_handle_t *h, const struct sockaddr *sa, int salen)
{
    int i;

    if ((unsigned)salen > sizeof(struct sockaddr_storage)) {
        abort();
	}

    if (dht_blacklisted(sa, salen)) {
        return 1;
	}

    for(i = 0; i < DHT_MAX_BLACKLISTED; i++) {
        if (memcmp(&h->blacklist[i], sa, salen) == 0) {
            return 1;
		}
    }

    return 0;
}

/* Split a bucket into two equal parts. */
static struct bucket *split_bucket(dht_handle_t *h, struct bucket *b)
{
    struct bucket *new;
    struct node *nodes;
    int rc;
    unsigned char new_id[20];

    if ((rc = bucket_middle(b, new_id)) < 0) {
        return NULL;
	}

    if (!(new = calloc(1, sizeof(struct bucket)))) {
        return NULL;
	}

    new->af = b->af;

    send_cached_ping(h, b);

    memcpy(new->first, new_id, 20);
    new->time = b->time;

    nodes = b->nodes;
    b->nodes = NULL;
    b->count = 0;
    new->next = b->next;
    b->next = new;
    while (nodes) {
        struct node *n;
        n = nodes;
        nodes = nodes->next;
        insert_node(h, n);
    }
    return b;
}

/* We just learnt about a node, not necessarily a new one.  Confirm is 1 if
   the node sent a message, 2 if it sent us a reply. */
static struct node *new_node(dht_handle_t *h, const unsigned char *id, const struct sockaddr *sa, int salen, int confirm)
{
    struct bucket *b = find_bucket(h, id, sa->sa_family);
    struct node *n;
    int mybucket, split;

    if (b == NULL) {
        return NULL;
	}

    if (id_cmp(id, h->myid) == 0) {
        return NULL;
	}

    if (is_martian(sa) || node_blacklisted(h, sa, salen)) {
        return NULL;
	}

    mybucket = in_bucket(h->myid, b);

    if (confirm == 2) {
        b->time = h->now;
	}

    n = b->nodes;
    while (n) {
        if (id_cmp(n->id, id) == 0) {
            if (confirm || n->time < h->now - 15 * 60) {
                /* Known node.  Update stuff. */
                memcpy((struct sockaddr*)&n->ss, sa, salen);
                if (confirm) {
                    n->time = h->now;
				}
                if (confirm >= 2) {
                    n->reply_time = h->now;
                    n->pinged = 0;
                    n->pinged_time = 0;
                }
            }
            return n;
        }
        n = n->next;
    }

    /* New node. */

    if (mybucket) {
        if (sa->sa_family == AF_INET) {
            h->mybucket_grow_time = h->now;
		} else {
            h->mybucket6_grow_time = h->now;
		}
    }

    /* First, try to get rid of a known-bad node. */
    n = b->nodes;
    while (n) {
        if (n->pinged >= 3 && n->pinged_time < h->now - 15) {
            memcpy(n->id, id, 20);
            memcpy((struct sockaddr*)&n->ss, sa, salen);
            n->time = confirm ? h->now : 0;
            n->reply_time = confirm >= 2 ? h->now : 0;
            n->pinged_time = 0;
            n->pinged = 0;
            return n;
        }
        n = n->next;
    }

    if (b->count >= 8) {
        /* Bucket full.  Ping a dubious node */
        int dubious = 0;
        n = b->nodes;
        while (n) {
            /* Pick the first dubious node that we haven't pinged in the
               last 15 seconds.  This gives nodes the time to reply, but
               tends to concentrate on the same nodes, so that we get rid
               of bad nodes fast. */
            if (!node_good(h, n)) {
                dubious = 1;
                if (n->pinged_time < h->now - 15) {
                    unsigned char tid[4];
                    ks_log(KS_LOG_DEBUG, "Sending ping to dubious node.\n");
                    make_tid(tid, "pn", 0);
                    send_ping(h, (struct sockaddr*)&n->ss, n->sslen, tid, 4);
                    n->pinged++;
                    n->pinged_time = h->now;
                    break;
                }
            }
            n = n->next;
        }

        split = 0;
        if (mybucket) {
            if (!dubious) {
                split = 1;
			}
            /* If there's only one bucket, split eagerly.  This is
               incorrect unless there's more than 8 nodes in the DHT. */
            else if (b->af == AF_INET && h->buckets->next == NULL) {
                split = 1;
			} else if (b->af == AF_INET6 && h->buckets6->next == NULL) {
                split = 1;
			}
        }

        if (split) {
            ks_log(KS_LOG_DEBUG, "Splitting.\n");
            b = split_bucket(h, b);
            return new_node(h, id, sa, salen, confirm);
        }

        /* No space for this node.  Cache it away for later. */
        if (confirm || b->cached.ss_family == 0) {
            memcpy(&b->cached, sa, salen);
            b->cachedlen = salen;
        }

        return NULL;
    }

    /* Create a new node. */
    if (!(n = calloc(1, sizeof(struct node)))) {
        return NULL;
	}

    memcpy(n->id, id, 20);
    memcpy(&n->ss, sa, salen);
    n->sslen = salen;
    n->time = confirm ? h->now : 0;
    n->reply_time = confirm >= 2 ? h->now : 0;
    n->next = b->nodes;
    b->nodes = n;
    b->count++;
    return n;
}

/* Called periodically to purge known-bad nodes.  Note that we're very
   conservative here: broken nodes in the table don't do much harm, we'll
   recover as soon as we find better ones. */
static int expire_buckets(dht_handle_t *h, struct bucket *b)
{
    while (b) {
        struct node *n, *p;
        int changed = 0;

        while (b->nodes && b->nodes->pinged >= 4) {
            n = b->nodes;
            b->nodes = n->next;
            b->count--;
            changed = 1;
            free(n);
        }

        p = b->nodes;
        while (p) {
            while (p->next && p->next->pinged >= 4) {
                n = p->next;
                p->next = n->next;
                b->count--;
                changed = 1;
                free(n);
            }
            p = p->next;
        }

        if (changed) {
            send_cached_ping(h, b);
		}

        b = b->next;
    }
    h->expire_stuff_time = h->now + 120 + random() % 240;
    return 1;
}

/* While a search is in progress, we don't necessarily keep the nodes being
   walked in the main bucket table.  A search in progress is identified by
   a unique transaction id, a short (and hence small enough to fit in the
   transaction id of the protocol packets). */

static struct search *find_search(dht_handle_t *h, unsigned short tid, int af)
{
    struct search *sr = h->searches;
    while (sr) {
        if (sr->tid == tid && sr->af == af) {
            return sr;
		}
        sr = sr->next;
    }
    return NULL;
}

/* A search contains a list of nodes, sorted by decreasing distance to the
   target.  We just got a new candidate, insert it at the right spot or
   discard it. */

static int insert_search_node(dht_handle_t *h, unsigned char *id,
                   const struct sockaddr *sa, int salen,
                   struct search *sr, int replied,
                   unsigned char *token, int token_len)
{
    struct search_node *n;
    int i, j;

    if (sa->sa_family != sr->af) {
        ks_log(KS_LOG_DEBUG, "Attempted to insert node in the wrong family.\n");
        return 0;
    }

    for(i = 0; i < sr->numnodes; i++) {
        if (id_cmp(id, sr->nodes[i].id) == 0) {
            n = &sr->nodes[i];
            goto found;
        }
        if (xorcmp(id, sr->nodes[i].id, sr->id) < 0) {
            break;
		}
    }

    if (i == SEARCH_NODES) {
        return 0;
	}

    if (sr->numnodes < SEARCH_NODES) {
        sr->numnodes++;
	}

    for (j = sr->numnodes - 1; j > i; j--) {
        sr->nodes[j] = sr->nodes[j - 1];
    }

    n = &sr->nodes[i];

    memset(n, 0, sizeof(struct search_node));
    memcpy(n->id, id, 20);

found:
    memcpy(&n->ss, sa, salen);
    n->sslen = salen;

    if (replied) {
        n->replied = 1;
        n->reply_time = h->now;
        n->request_time = 0;
        n->pinged = 0;
    }
    if (token) {
        if (token_len >= 40) {
            ks_log(KS_LOG_DEBUG, "Eek!  Overlong token.\n");
        } else {
            memcpy(n->token, token, token_len);
            n->token_len = token_len;
        }
    }

    return 1;
}

static void flush_search_node(struct search_node *n, struct search *sr)
{
    int i = n - sr->nodes, j;
    for (j = i; j < sr->numnodes - 1; j++) {
        sr->nodes[j] = sr->nodes[j + 1];
	}
    sr->numnodes--;
}

static void expire_searches(dht_handle_t *h)
{
    struct search *sr = h->searches, *previous = NULL;

    while (sr) {
        struct search *next = sr->next;
        if (sr->step_time < h->now - DHT_SEARCH_EXPIRE_TIME) {
            if (previous) {
                previous->next = next;
            } else {
                h->searches = next;
			}
            free(sr);
            h->numsearches--;
        } else {
            previous = sr;
        }
        sr = next;
    }
}

/* This must always return 0 or 1, never -1, not even on failure (see below). */
static int search_send_get_peers(dht_handle_t *h, struct search *sr, struct search_node *n)
{
    struct node *node;
    unsigned char tid[4];

    if (n == NULL) {
        int i;
        for (i = 0; i < sr->numnodes; i++) {
            if (sr->nodes[i].pinged < 3 && !sr->nodes[i].replied && sr->nodes[i].request_time < h->now - 15) {
                n = &sr->nodes[i];
			}
        }
    }

    if (!n || n->pinged >= 3 || n->replied || n->request_time >= h->now - 15) {
        return 0;
	}

    ks_log(KS_LOG_DEBUG, "Sending get_peers.\n");
    make_tid(tid, "gp", sr->tid);
    send_get_peers(h, (struct sockaddr*)&n->ss, n->sslen, tid, 4, sr->id, -1, n->reply_time >= h->now - 15);
    n->pinged++;
    n->request_time = h->now;
    /* If the node happens to be in our main routing table, mark it as pinged. */
    if ((node = find_node(h, n->id, n->ss.ss_family))) {
		pinged(h, node, NULL);
	}
    return 1;
}

/* When a search is in progress, we periodically call search_step to send
   further requests. */
static void search_step(dht_handle_t *h, struct search *sr, dht_callback *callback, void *closure)
{
    int i, j;
    int all_done = 1;

    /* Check if the first 8 live nodes have replied. */
    j = 0;
    for (i = 0; i < sr->numnodes && j < 8; i++) {
        struct search_node *n = &sr->nodes[i];
        if (n->pinged >= 3) {
            continue;
		}
        if (!n->replied) {
            all_done = 0;
            break;
        }
        j++;
    }

    if (all_done) {
		int all_acked = 1;
        if (sr->port == 0) {
            goto done;
        }

		j = 0;

		for (i = 0; i < sr->numnodes && j < 8; i++) {
			struct search_node *n = &sr->nodes[i];
			struct node *node;
			unsigned char tid[4];
			if (n->pinged >= 3) {
				continue;
			}
			/* A proposed extension to the protocol consists in omitting the token when storage tables are full.  While
			   I don't think this makes a lot of sense -- just sending a positive reply is just as good --, let's deal with it. */
			if (n->token_len == 0) {
				n->acked = 1;
			}
			if (!n->acked) {
				all_acked = 0;
				ks_log(KS_LOG_DEBUG, "Sending announce_peer.\n");
				make_tid(tid, "ap", sr->tid);
				send_announce_peer(h, (struct sockaddr*)&n->ss,
								   sizeof(struct sockaddr_storage),
								   tid, 4, sr->id, sr->port,
								   n->token, n->token_len,
								   n->reply_time < h->now - 15);
				n->pinged++;
				n->request_time = h->now;
				node = find_node(h, n->id, n->ss.ss_family);
				if (node) pinged(h, node, NULL);
			}
			j++;
		}
		if (all_acked) {
			goto done;
		}

        sr->step_time = h->now;
        return;
    }

    if (sr->step_time + 15 >= h->now) {
        return;
	}

    j = 0;
    for (i = 0; i < sr->numnodes; i++) {
        j += search_send_get_peers(h, sr, &sr->nodes[i]);
        if (j >= 3) {
            break;
		}
    }
    sr->step_time = h->now;
    return;

 done:
    sr->done = 1;
    if (callback) {
        (*callback)(closure, sr->af == AF_INET ? KS_DHT_EVENT_SEARCH_DONE : KS_DHT_EVENT_SEARCH_DONE6, sr->id, NULL, 0);
	}
    sr->step_time = h->now;
}

static struct search *new_search(dht_handle_t *h)
{
    struct search *sr, *oldest = NULL;

    /* Find the oldest done search */
    sr = h->searches;
    while (sr) {
        if (sr->done && (oldest == NULL || oldest->step_time > sr->step_time)) {
            oldest = sr;
		}
        sr = sr->next;
    }

    /* The oldest slot is expired. */
    if (oldest && oldest->step_time < h->now - DHT_SEARCH_EXPIRE_TIME) {
        return oldest;
	}

    /* Allocate a new slot. */
    if (h->numsearches < DHT_MAX_SEARCHES) {
        if ((sr = calloc(1, sizeof(struct search)))) {
            sr->next = h->searches;
            h->searches = sr;
            h->numsearches++;
            return sr;
        }
    }

    /* Oh, well, never mind.  Reuse the oldest slot. */
    return oldest;
}

/* Insert the contents of a bucket into a search structure. */
static void insert_search_bucket(dht_handle_t *h, struct bucket *b, struct search *sr)
{
    struct node *n;
    n = b->nodes;
    while (n) {
        insert_search_node(h, n->id, (struct sockaddr*)&n->ss, n->sslen, sr, 0, NULL, 0);
        n = n->next;
    }
}

/* Start a search.  If port is non-zero, perform an announce when the
   search is complete. */
KS_DECLARE(int) dht_search(dht_handle_t *h, const unsigned char *id, int port, int af, dht_callback *callback, void *closure)
{
    struct search *sr;
    struct storage *st;
    struct bucket *b = find_bucket(h, id, af);

    if (b == NULL) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    /* Try to answer this search locally.  In a fully grown DHT this
       is very unlikely, but people are running modified versions of
       this code in private DHTs with very few nodes.  What's wrong
       with flooding? */
    if (callback) {
        st = find_storage(h, id);
        if (st) {
            unsigned short swapped;
            unsigned char buf[18];
            int i;

            ks_log(KS_LOG_DEBUG, "Found local data (%d peers).\n", st->numpeers);

            for (i = 0; i < st->numpeers; i++) {
                swapped = htons(st->peers[i].port);
                if (st->peers[i].len == 4) {
                    memcpy(buf, st->peers[i].ip, 4);
                    memcpy(buf + 4, &swapped, 2);
                    (*callback)(closure, KS_DHT_EVENT_VALUES, id, (void*)buf, 6);
                } else if (st->peers[i].len == 16) {
                    memcpy(buf, st->peers[i].ip, 16);
                    memcpy(buf + 16, &swapped, 2);
                    (*callback)(closure, KS_DHT_EVENT_VALUES6, id, (void*)buf, 18);
                }
            }
        }
    }

    sr = h->searches;
    while (sr) {
        if (sr->af == af && id_cmp(sr->id, id) == 0) {
            break;
		}
        sr = sr->next;
    }

    if (sr) {
        /* We're reusing data from an old search.  Reusing the same tid
           means that we can merge replies for both searches. */
        int i;
        sr->done = 0;
    again:
        for (i = 0; i < sr->numnodes; i++) {
            struct search_node *n;
            n = &sr->nodes[i];
            /* Discard any doubtful nodes. */
            if (n->pinged >= 3 || n->reply_time < h->now - 7200) {
                flush_search_node(n, sr);
                goto again;
            }
            n->pinged = 0;
            n->token_len = 0;
            n->replied = 0;
            n->acked = 0;
        }
    } else {
        sr = new_search(h);
        if (sr == NULL) {
            errno = ENOSPC;
            return -1;
        }
        sr->af = af;
        sr->tid = h->search_id++;
        sr->step_time = 0;
        memcpy(sr->id, id, 20);
        sr->done = 0;
        sr->numnodes = 0;
    }

    sr->port = port;

    insert_search_bucket(h, b, sr);

    if (sr->numnodes < SEARCH_NODES) {
        struct bucket *p = previous_bucket(h, b);
        if (b->next) {
            insert_search_bucket(h, b->next, sr);
		}
        if (p) {
            insert_search_bucket(h, p, sr);
		}
    }
    if (sr->numnodes < SEARCH_NODES) {
        insert_search_bucket(h, find_bucket(h, h->myid, af), sr);
	}

    search_step(h, sr, callback, closure);
    h->search_time = h->now;
    return 1;
}

/* A struct storage stores all the stored peer addresses for a given info hash. */

static struct storage *find_storage(dht_handle_t *h, const unsigned char *id)
{
    struct storage *st = h->storage;

    while(st) {
        if (id_cmp(id, st->id) == 0) {
            break;
		}
        st = st->next;
    }
    return st;
}

static int storage_store(dht_handle_t *h, const unsigned char *id, const struct sockaddr *sa, unsigned short port)
{
    int i, len;
    struct storage *st;
    unsigned char *ip;

    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in*)sa;
        ip = (unsigned char*)&sin->sin_addr;
        len = 4;
    } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
        ip = (unsigned char*)&sin6->sin6_addr;
        len = 16;
    } else {
        return -1;
    }

    st = find_storage(h, id);

    if (st == NULL) {
        if (h->numstorage >= DHT_MAX_HASHES) {
            return -1;
		}
        if (!(st = calloc(1, sizeof(struct storage)))) {
			return -1;
		}
        memcpy(st->id, id, 20);
        st->next = h->storage;
        h->storage = st;
        h->numstorage++;
    }

    for(i = 0; i < st->numpeers; i++) {
        if (st->peers[i].port == port && st->peers[i].len == len && memcmp(st->peers[i].ip, ip, len) == 0) {
            break;
		}
    }

    if (i < st->numpeers) {
        /* Already there, only need to refresh */
        st->peers[i].time = h->now;
        return 0;
    } else {
        struct peer *p;
        if (i >= st->maxpeers) {
            /* Need to expand the array. */
            struct peer *new_peers;
            int n;
            if (st->maxpeers >= DHT_MAX_PEERS) {
                return 0;
			}
            n = st->maxpeers == 0 ? 2 : 2 * st->maxpeers;
            n = MIN(n, DHT_MAX_PEERS);
            
            if (!(new_peers = realloc(st->peers, n * sizeof(struct peer)))) {
                return -1;
			}
            st->peers = new_peers;
            st->maxpeers = n;
        }
        p = &st->peers[st->numpeers++];
        p->time = h->now;
        p->len = len;
        memcpy(p->ip, ip, len);
        p->port = port;
        return 1;
    }
}

static int expire_storage(dht_handle_t *h)
{
    struct storage *st = h->storage, *previous = NULL;

    while (st) {
        int i = 0;
        while (i < st->numpeers) {
            if (st->peers[i].time < h->now - 32 * 60) {
                if (i != st->numpeers - 1)
                    st->peers[i] = st->peers[st->numpeers - 1];
                st->numpeers--;
            } else {
                i++;
            }
        }

        if (st->numpeers == 0) {
            free(st->peers);
            if (previous) {
                previous->next = st->next;
				free(st);
                st = previous->next;
			} else {
                h->storage = st->next;
				free(st);
                st = h->storage;
			}

            h->numstorage--;
            if (h->numstorage < 0) {
                ks_log(KS_LOG_DEBUG, "Eek... numstorage became negative.\n");
                h->numstorage = 0;
            }
        } else {
            previous = st;
            st = st->next;
        }
    }
    return 1;
}

static int rotate_secrets(dht_handle_t *h)
{
    int rc;

    h->rotate_secrets_time = h->now + 900 + random() % 1800;

    memcpy(h->oldsecret, h->secret, sizeof(h->secret));
    rc = dht_random_bytes(h->secret, sizeof(h->secret));

    if (rc < 0) {
        return -1;
	}

    return 1;
}

#ifndef TOKEN_SIZE
#define TOKEN_SIZE 8
#endif

static void make_token(dht_handle_t *h, const struct sockaddr *sa, int old, unsigned char *token_return)
{
    void *ip;
    int iplen;
    unsigned short port;

    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in*)sa;
        ip = &sin->sin_addr;
        iplen = 4;
        port = htons(sin->sin_port);
    } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
        ip = &sin6->sin6_addr;
        iplen = 16;
        port = htons(sin6->sin6_port);
    } else {
        abort();
    }

    dht_hash(token_return, TOKEN_SIZE, old ? h->oldsecret : h->secret, sizeof(h->secret), ip, iplen, (unsigned char*)&port, 2);
}

static int token_match(dht_handle_t *h, const unsigned char *token, int token_len, const struct sockaddr *sa)
{
    unsigned char t[TOKEN_SIZE];

    if (token_len != TOKEN_SIZE) {
        return 0;
	}

    make_token(h, sa, 0, t);
    if (memcmp(t, token, TOKEN_SIZE) == 0) {
        return 1;
	}

    make_token(h, sa, 1, t);
    if (memcmp(t, token, TOKEN_SIZE) == 0) {
        return 1;
	}

    return 0;
}

KS_DECLARE(int) dht_nodes(dht_handle_t *h, int af, int *good_return, int *dubious_return, int *cached_return, int *incoming_return)
{
    int good = 0, dubious = 0, cached = 0, incoming = 0;
    struct bucket *b = af == AF_INET ? h->buckets : h->buckets6;

    while (b) {
        struct node *n = b->nodes;
        while (n) {
            if (node_good(h, n)) {
                good++;
                if (n->time > n->reply_time) {
                    incoming++;
				}
            } else {
                dubious++;
            }
            n = n->next;
        }
        if (b->cached.ss_family > 0) {
            cached++;
		}
        b = b->next;
    }

    if (good_return) {
        *good_return = good;
	}

    if (dubious_return) {
        *dubious_return = dubious;
	}

    if (cached_return) {
        *cached_return = cached;
	}

    if (incoming_return) {
        *incoming_return = incoming;
	}

    return good + dubious;
}

static void dump_bucket(dht_handle_t *h, FILE *f, struct bucket *b)
{
    struct node *n = b->nodes;
	int mine = in_bucket(h->myid, b);
	int age = (int)(h->now - b->time);
	int cached = b->cached.ss_family;
    fprintf(f, "Bucket ");
    print_hex(f, b->first, 20);
    fprintf(f, " count %d age %d%s%s:\n", b->count, age, mine ? " (mine)" : "", cached ? " (cached)" : "");

    while (n) {
        char buf[512];
        unsigned short port;
        fprintf(f, "    Node ");
        print_hex(f, n->id, 20);

        if (n->ss.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in*)&n->ss;
            inet_ntop(AF_INET, &sin->sin_addr, buf, 512);
            port = ntohs(sin->sin_port);
        } else if (n->ss.ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&n->ss;
            inet_ntop(AF_INET6, &sin6->sin6_addr, buf, 512);
            port = ntohs(sin6->sin6_port);
        } else {
            ks_snprintf(buf, 512, "unknown(%d)", n->ss.ss_family);
            port = 0;
        }

        if (n->ss.ss_family == AF_INET6) {
            fprintf(f, " [%s]:%d ", buf, port);
		} else {
            fprintf(f, " %s:%d ", buf, port);
		}

        if (n->time != n->reply_time) {
            fprintf(f, "age %ld, %ld", (long)(h->now - n->time), (long)(h->now - n->reply_time));
        } else {
            fprintf(f, "age %ld", (long)(h->now - n->time));
		}

        if (n->pinged) {
            fprintf(f, " (%d)", n->pinged);
		}

        if (node_good(h, n)) {
            fprintf(f, " (good)");
		}
        fprintf(f, "\n");
        n = n->next;
    }

}

KS_DECLARE(void) dht_dump_tables(dht_handle_t *h, FILE *f)
{
    int i;
    struct bucket *b;
    struct storage *st = h->storage;
    struct search *sr = h->searches;

    fprintf(f, "My id ");
    print_hex(f, h->myid, 20);
    fprintf(f, "\n");

    b = h->buckets;
    while (b) {
        dump_bucket(h, f, b);
        b = b->next;
    }

    fprintf(f, "\n");

    b = h->buckets6;
    while (b) {
        dump_bucket(h, f, b);
        b = b->next;
    }

    while (sr) {
        fprintf(f, "\nSearch%s id ", sr->af == AF_INET6 ? " (IPv6)" : "");
        print_hex(f, sr->id, 20);
        fprintf(f, " age %d%s\n", (int)(h->now - sr->step_time), sr->done ? " (done)" : "");
        for (i = 0; i < sr->numnodes; i++) {
            struct search_node *n = &sr->nodes[i];
            fprintf(f, "Node %d id ", i);
            print_hex(f, n->id, 20);
            fprintf(f, " bits %d age ", common_bits(sr->id, n->id));
            if (n->request_time) {
                fprintf(f, "%d, ", (int)(h->now - n->request_time));
			}
            fprintf(f, "%d", (int)(h->now - n->reply_time));
            if (n->pinged) {
                fprintf(f, " (%d)", n->pinged);
			}
            fprintf(f, "%s%s.\n", find_node(h, n->id, AF_INET) ? " (known)" : "", n->replied ? " (replied)" : "");
        }
        sr = sr->next;
    }

    while (st) {
        fprintf(f, "\nStorage ");
        print_hex(f, st->id, 20);
        fprintf(f, " %d/%d nodes:", st->numpeers, st->maxpeers);
        for (i = 0; i < st->numpeers; i++) {
            char buf[100];
            if (st->peers[i].len == 4) {
                inet_ntop(AF_INET, st->peers[i].ip, buf, 100);
            } else if (st->peers[i].len == 16) {
                buf[0] = '[';
                inet_ntop(AF_INET6, st->peers[i].ip, buf + 1, 98);
                strcat(buf, "]");
            } else {
                strcpy(buf, "???");
            }
            fprintf(f, " %s:%u (%ld)", buf, st->peers[i].port, (long)(h->now - st->peers[i].time));
        }
        st = st->next;
    }

    fprintf(f, "\n\n");
    fflush(f);
}

static void ks_dht_store_entry_destroy(struct ks_dht_store_entry_s **old_entry)
{
	struct ks_dht_store_entry_s *entry = *old_entry;
	ks_pool_t *pool = entry->pool;
	*old_entry = NULL;

	/* While setting these members to NULL is not required, defaulting to including them for easier debugging */
	entry->key = NULL;
	entry->content_type = NULL;
	entry->payload_raw = NULL;
	entry->pool = NULL;
	
	if ( entry->bencode_message_raw ) {
		ben_free(entry->bencode_message_raw);
		entry->bencode_message_raw = NULL;
	}

	if ( entry->payload_bencode ) {
		ben_free(entry->payload_bencode);
		entry->payload_bencode = NULL;
	}

	if ( entry->body ) {
		cJSON_Delete(entry->body);
		entry->body = NULL;
	}
	
	ks_pool_free(pool, entry);	
	return;
}

/* Entries can be created by a remote system 'pushing' a message to us, or the local system creating and sending the message. */

static int ks_dht_store_entry_create(ks_pool_t *pool, struct bencode *msg, struct ks_dht_store_entry_s **new_entry, ks_time_t life, ks_bool_t mine)
{
	struct ks_dht_store_entry_s *entry = NULL;
	ks_time_t now = ks_time_now_sec();

	entry = ks_pool_alloc(pool, sizeof(struct ks_dht_store_entry_s));
	entry->pool = pool;
	entry->received = now;
	entry->expiration = now + life;
	entry->last_announce = 0; /* TODO: Instead we should announce this one, and set to now */
	entry->serial = 1;
	entry->mine = mine;

	entry->bencode_message_raw = msg;
	entry->payload_raw = NULL;

	entry->content_type = NULL;
	entry->payload_bencode = NULL;
	entry->body = NULL;
	
	if ( msg ) {
		struct bencode *key_args = ben_dict_get_by_str(msg, "a");
		struct bencode *key_token = NULL;
		struct bencode *key_v = NULL;
		struct bencode *key_ct = NULL;

		if ( !key_args ) {
			ks_log(KS_LOG_ERROR, "dht_store_entry requires an 'a' key in the message\n");
			goto err;
		}

		key_token = ben_dict_get_by_str(key_args, "token");
		if ( !key_token ) {
			ks_log(KS_LOG_ERROR, "dht_store_entry requires an 'token' key in the message\n");
			goto err;
		}
		entry->key = ben_str_val(key_token);		
		
		key_v = ben_dict_get_by_str(key_args, "v");
		if ( !key_v ) {
			ks_log(KS_LOG_ERROR, "dht_store_entry requires an 'v' key in the message\n");
			goto err;
		}

		entry->payload_raw = ben_str_val(key_v);
		entry->payload_bencode = ben_decode(entry->payload_raw, ben_str_len(key_v));

		if ( !entry->payload_bencode ) {
			ks_log(KS_LOG_WARNING, "dht_store_entry payload failed to parse as bencode object\n");
			goto err;
		}

		ks_log(KS_LOG_DEBUG, "Payload: %s", ben_print(entry->payload_bencode));

		if ( ! ben_is_dict( entry->payload_bencode ) ) {
			ks_log(KS_LOG_DEBUG, "dht_store_entry is not a bencode dict. Legal, just not likely one of ours.\n");
			goto done;			
		}
		
		/* 
		   This is a custom key that SWITCHBLADE is adding to give the protocol decoder a hint as to the payload type. 
		   If this key is not set, then we need to assume that the payload is binary buffer of a known length, likely not from SWITCHBLADE.
		 */
		key_ct = ben_dict_get_by_str(entry->payload_bencode, "ct");
		if ( !key_ct ) {
			ks_log(KS_LOG_DEBUG, "dht_store_entry without a 'ct' key to hint at payload content type. Legal, just not likely one of ours.\n");
			goto done;
		}

		entry->content_type = ben_str_val(key_ct);
		
		if ( !ben_cmp_with_str(key_ct, "json") ) {
			struct bencode *key_b = ben_dict_get_by_str(entry->payload_bencode, "b");
			int buf_len = ben_str_len(key_b);
			char *buf = NULL;

			buf = calloc(1, buf_len);
			memcpy(buf, ben_str_val(key_b), buf_len);

			entry->body = cJSON_Parse(buf);
			free(buf);
			buf = NULL;

			if ( !entry->body ) {
				ks_log(KS_LOG_ERROR, "dht_store_entry with json payload failed to json parse. Someone sent and signed an invalid message.\n");
				goto err;
			}
		}
		
	}
	
 done:
	*new_entry = entry;
	return 0;
 err:
	ks_dht_store_entry_destroy(&entry);
	ben_free(msg);
	return -1;	
}

static int ks_dht_store_insert(struct ks_dht_store_s *store, struct ks_dht_store_entry_s *entry, ks_time_t now)
{
	(void) store;
	(void) entry;
	(void) now;
	return 0;
}
static void ks_dht_store_prune(struct ks_dht_store_s *store, ks_time_t now)
{
	(void) store;
	(void) now;
	return;
}

/* TODO: Look into using the ks_hash automatic destructor functionality. */
static int ks_dht_store_create(ks_pool_t *pool, struct ks_dht_store_s **new_store)
{
	struct ks_dht_store_s *store = NULL;

	store = ks_pool_alloc(pool, sizeof(struct ks_dht_store_s));
	store->next_expiring = 0;
	store->pool = pool;

	ks_hash_create(&store->hash, KS_HASH_MODE_DEFAULT, KS_HASH_FLAG_RWLOCK, pool);

	*new_store = store;
	return 0;
}

static void ks_dht_store_destroy(struct ks_dht_store_s **old_store)
{
	struct ks_dht_store_s *store = *old_store;
	ks_hash_iterator_t *itt = NULL;
	ks_pool_t *pool = store->pool;
	*old_store = NULL;

	ks_hash_write_lock(store->hash);
	for (itt = ks_hash_first(store->hash, KS_UNLOCKED); itt; itt = ks_hash_next(&itt)) {
		const void *key = NULL;
		struct ks_dht_store_entry_s *val = NULL;

		ks_hash_this(itt, &key, NULL, (void **) &val);
		ks_hash_remove(store->hash, (char *)key);

		ks_dht_store_entry_destroy(&val);
	}
	ks_hash_write_unlock(store->hash);

	ks_hash_destroy(&store->hash);

	ks_pool_free(pool, store);
	
	return;
}

KS_DECLARE(int) dht_init(dht_handle_t **handle, int s, int s6, const unsigned char *id, const unsigned char *v)
{
    int rc;
	dht_handle_t *h;

	*handle = h = calloc(sizeof(dht_handle_t), 1);
    h->searches = NULL;
    h->numsearches = 0;

    h->storage = NULL;
    h->numstorage = 0;

	h->buckets = NULL;
	h->buckets6 = NULL;

    if (s >= 0) {
        h->buckets = calloc(sizeof(struct bucket), 1);
        if (h->buckets == NULL) {
            return -1;
		}
        h->buckets->af = AF_INET;

        rc = set_nonblocking(s, 1);
        if (rc < 0) {
            goto fail;
		}
    }

    if (s6 >= 0) {
        h->buckets6 = calloc(sizeof(struct bucket), 1);
        if (h->buckets6 == NULL) {
            return -1;
		}
        h->buckets6->af = AF_INET6;

        rc = set_nonblocking(s6, 1);
        if (rc < 0) {
            goto fail;
		}
    }

	if (!id) {
		randombytes_buf(h->myid, 20);
	} else {
		memcpy(h->myid, id, 20);
	}

    if (v) {
        memcpy(h->my_v, "1:v4:", 5);
        memcpy(h->my_v + 5, v, 4);
        h->have_v = 1;
    } else {
        h->have_v = 0;
    }

	h->now = ks_time_now_sec();

    h->mybucket_grow_time = h->now;
    h->mybucket6_grow_time = h->now;
    h->confirm_nodes_time = h->now + random() % 3;

    h->search_id = random() & 0xFFFF;
    h->search_time = 0;

    h->next_blacklisted = 0;

    h->token_bucket_time = h->now;
    h->token_bucket_tokens = MAX_TOKEN_BUCKET_TOKENS;

    memset(h->secret, 0, sizeof(h->secret));
    rc = rotate_secrets(h);
    if (rc < 0)
        goto fail;

    h->dht_socket = s;
    h->dht_socket6 = s6;

    expire_buckets(h, h->buckets);
    expire_buckets(h, h->buckets6);

	ks_pool_open(&h->pool);
	ks_dht_store_create(h->pool, &h->store);

    return 1;

 fail:
    free(h->buckets);
    h->buckets = NULL;
    free(h->buckets6);
    h->buckets6 = NULL;
    return -1;
}

KS_DECLARE(int) dht_uninit(dht_handle_t **handle)
{
	dht_handle_t *h = *handle;
	*handle = NULL;

    if (h->dht_socket < 0 && h->dht_socket6 < 0) {
        errno = EINVAL;
        return -1;
    }

    h->dht_socket = -1;
    h->dht_socket6 = -1;

    while (h->buckets) {
        struct bucket *b = h->buckets;
        h->buckets = b->next;
        while (b->nodes) {
            struct node *n = b->nodes;
            b->nodes = n->next;
            free(n);
        }
        free(b);
    }

    while (h->buckets6) {
        struct bucket *b = h->buckets6;
        h->buckets6 = b->next;
        while (b->nodes) {
            struct node *n = b->nodes;
            b->nodes = n->next;
            free(n);
        }
        free(b);
    }

    while (h->storage) {
        struct storage *st = h->storage;
        h->storage = h->storage->next;
        free(st->peers);
        free(st);
    }

    while (h->searches) {
        struct search *sr = h->searches;
        h->searches = h->searches->next;
        free(sr);
    }

	ks_dht_store_destroy(&h->store);
	ks_pool_close(&h->pool);
	
	free(h);
    return 1;
}

/* Rate control for requests we receive. */

static int token_bucket(dht_handle_t *h)
{
    if (h->token_bucket_tokens == 0) {
        h->token_bucket_tokens = MIN(MAX_TOKEN_BUCKET_TOKENS, 100 * (h->now - h->token_bucket_time));
        h->token_bucket_time = h->now;
    }

    if (h->token_bucket_tokens == 0) {
        return 0;
	}

    h->token_bucket_tokens--;
    return 1;
}

static int neighbourhood_maintenance(dht_handle_t *h, int af)
{
    unsigned char id[20];
    struct bucket *b = find_bucket(h, h->myid, af);
    struct bucket *q;
    struct node *n;

    if (b == NULL) {
        return 0;
	}

    memcpy(id, h->myid, 20);
    id[19] = random() & 0xFF;
    q = b;

    if (q->next && (q->count == 0 || (random() & 7) == 0)) {
        q = b->next;
	}

    if (q->count == 0 || (random() & 7) == 0) {
        struct bucket *r;
        r = previous_bucket(h, b);
        if (r && r->count > 0) {
            q = r;
		}
    }

    if (q) {
        /* Since our node-id is the same in both DHTs, it's probably
           profitable to query both families. */
        int want = h->dht_socket >= 0 && h->dht_socket6 >= 0 ? (WANT4 | WANT6) : -1;
        n = random_node(q);
        if (n) {
            unsigned char tid[4];
            ks_log(KS_LOG_DEBUG, "Sending find_node for%s neighborhood maintenance.\n", af == AF_INET6 ? " IPv6" : "");
            make_tid(tid, "fn", 0);
            send_find_node(h, (struct sockaddr*)&n->ss, n->sslen, tid, 4, id, want, n->reply_time >= h->now - 15);
            pinged(h, n, q);
        }
        return 1;
    }
    return 0;
}

static int bucket_maintenance(dht_handle_t *h, int af)
{
    struct bucket *b;

    b = af == AF_INET ? h->buckets : h->buckets6;

    while (b) {
        struct bucket *q;
        if (b->time < h->now - 600) {
            /* This bucket hasn't seen any positive confirmation for a long
               time.  Pick a random id in this bucket's range, and send
               a request to a random node. */
            unsigned char id[20];
            struct node *n;
            int rc;

            rc = bucket_random(b, id);
            if (rc < 0) {
                memcpy(id, b->first, 20);
			}

            q = b;
            /* If the bucket is empty, we try to fill it from a neighbour.
               We also sometimes do it gratuitiously to recover from
               buckets full of broken nodes. */
            if (q->next && (q->count == 0 || (random() & 7) == 0)) {
                q = b->next;
			}

            if (q->count == 0 || (random() & 7) == 0) {
                struct bucket *r;
                r = previous_bucket(h, b);
                if (r && r->count > 0) {
                    q = r;
				}
            }

            if (q) {
                n = random_node(q);
                if (n) {
                    unsigned char tid[4];
                    int want = -1;

                    if (h->dht_socket >= 0 && h->dht_socket6 >= 0) {
                        struct bucket *otherbucket;
                        otherbucket = find_bucket(h, id, af == AF_INET ? AF_INET6 : AF_INET);
                        if (otherbucket && otherbucket->count < 8) {
                            /* The corresponding bucket in the other family is emptyish -- querying both is useful. */
                            want = WANT4 | WANT6;
                        } else if (random() % 37 == 0) {
                            /* Most of the time, this just adds overhead.
                               However, it might help stitch back one of
                               the DHTs after a network collapse, so query
                               both, but only very occasionally. */
                            want = WANT4 | WANT6;
						}
                    }

                    ks_log(KS_LOG_DEBUG, "Sending find_node for%s bucket maintenance.\n", af == AF_INET6 ? " IPv6" : "");
                    make_tid(tid, "fn", 0);
                    send_find_node(h, (struct sockaddr*)&n->ss, n->sslen, tid, 4, id, want, n->reply_time >= h->now - 15);
                    pinged(h, n, q);
                    /* In order to avoid sending queries back-to-back, give up for now and reschedule us soon. */
                    return 1;
                }
            }
        }
        b = b->next;
    }
    return 0;
}

KS_DECLARE(int) dht_periodic(dht_handle_t *h, const void *buf, size_t buflen, const struct sockaddr *from, int fromlen,
             time_t *tosleep, dht_callback *callback, void *closure)
{
	unsigned char *logmsg = NULL;
	h->now = ks_time_now_sec();

    if (buflen > 0) {
        dht_msg_type_t message;
        unsigned char tid[16], id[20], info_hash[20], target[20];
        unsigned char nodes[26*16], nodes6[38*16], token[128];
        int tid_len = 16, token_len = 128;
        int nodes_len = 26*16, nodes6_len = 38*16;
        unsigned short port = 0;
        unsigned char values[2048], values6[2048];
        int values_len = 2048, values6_len = 2048;
        int want = 0;
        unsigned short ttid;
		struct bencode *msg_ben = NULL;
		struct bencode *key_args = NULL; /* Request args */
		struct bencode *key_info_hash = NULL;
		struct bencode *key_want = NULL;
		struct bencode *key_token = NULL;
		struct bencode *key_port = NULL;
		struct bencode *key_target = NULL;

		struct bencode *key_resp = NULL; /* Response values */
		struct bencode *key_values = NULL;
		struct bencode *key_values6 = NULL;
		struct bencode *key_nodes = NULL;
		struct bencode *key_nodes6 = NULL;

        if (is_martian(from)) {
            goto dontread;
		}

        if (node_blacklisted(h, from, fromlen)) {
            ks_log(KS_LOG_DEBUG, "Received packet from blacklisted node.\n");
            goto dontread;
        }

        if (((char*)buf)[buflen] != '\0') {
            ks_log(KS_LOG_DEBUG, "Unterminated message.\n");
            errno = EINVAL;
            return -1;
        }

		msg_ben = ben_decode((const void *) buf, buflen);
		ks_log(KS_LOG_DEBUG, "Received bencode message: \n\n%s\n", ben_print(msg_ben));

        message = parse_message(msg_ben, tid, &tid_len, id);
		ks_log(KS_LOG_DEBUG, "Message type from parse_message %d\n", message);

        if (id_cmp(id, zeroes) == 0) {
			message = DHT_MSG_INVALID;
        } else if (id_cmp(id, h->myid) == 0) {
            ks_log(KS_LOG_DEBUG, "Received message from self.\n");
            goto dontread;
        }

        if (message > DHT_MSG_REPLY) {
            /* Rate limit requests. */
            if (!token_bucket(h)) {
                ks_log(KS_LOG_DEBUG, "Dropping request due to rate limiting.\n");
                goto dontread;
            }
        }

		key_args = ben_dict_get_by_str(msg_ben, "a");
		if ( key_args ) {
			key_info_hash = ben_dict_get_by_str(key_args, "info_hash");

			if ( key_info_hash ) {
				memcpy(info_hash, ben_str_val(key_info_hash), ben_str_len(key_info_hash));
			}

			key_want = ben_dict_get_by_str(key_args, "want");
			
			if ( key_want ) {
				if ( !ben_cmp_with_str(key_want, "n4") ) {
					want = WANT4;
				} else if ( !ben_cmp_with_str(key_want, "n6") ) {
					want = WANT6;
				} else {
					want = 0;
				}
			}

			key_target = ben_dict_get_by_str(key_args, "target");

			if ( key_target ) {
				memcpy(target, ben_str_val(key_target), ben_str_len(key_target));
			}


			key_token = ben_dict_get_by_str(key_args, "token");

			if ( key_token ) {
				token_len = ben_str_len(key_token);
				memcpy(token, ben_str_val(key_token), token_len);
			}

			key_port = ben_dict_get_by_str(key_args, "port");

			if ( key_port ) {
				port = ben_int_val(key_port);
			}
		}

		key_resp = ben_dict_get_by_str(msg_ben, "r");
		if ( key_resp ) {
			key_values = ben_dict_get_by_str(key_resp, "values");

			if ( key_values ) {
				values_len = ben_str_len(key_values);
				memcpy(values, ben_str_val(key_values), values_len);
			}

			key_values6 = ben_dict_get_by_str(key_resp, "values6");

			if ( key_values6 ) {
				values6_len = ben_str_len(key_values6);
				memcpy(values6, ben_str_val(key_values6), values6_len);
			}

			key_nodes = ben_dict_get_by_str(key_resp, "nodes");

			if ( key_nodes ) {
				nodes_len = ben_str_len(key_nodes);
				memcpy(nodes, ben_str_val(key_nodes), nodes_len);
				ks_log(KS_LOG_DEBUG, "Parsed nodes from response with length %d\n", nodes_len);
			}

			key_nodes6 = ben_dict_get_by_str(key_resp, "nodes6");

			if ( key_nodes6 ) {
				nodes6_len = ben_str_len(key_nodes6);
				memcpy(nodes6, ben_str_val(key_nodes6), nodes6_len);
			}
		}
		
		logmsg = calloc(1, buflen);
		ks_log(KS_LOG_DEBUG, "Message type %d\n", message);
        switch(message) {
		case DHT_MSG_STORE_PUT:
			if ( buf ) {
				struct ks_dht_store_entry_s *entry = NULL;
				struct bencode *sig = NULL, *salt = NULL;
				struct bencode *sig_ben = NULL, *pk_ben = NULL;
				unsigned char *data_sig = NULL;
				const char *sig_binary = NULL, *pk_binary = NULL;
				size_t data_sig_len = 0;

				/* Handle checking callback handler, and response */
				if ( !key_args ) {
					ks_log(KS_LOG_DEBUG, "Failed to locate 'a' field in message\n");
					goto dontread;
				} else {
					ks_log(KS_LOG_DEBUG, "Successfully located 'a' field in message\n");
				}

				ks_log(KS_LOG_DEBUG, "Received bencode store PUT: \n\n%s\n", ben_print(msg_ben));

				sig_ben = ben_dict_get_by_str(key_args, "sig");
				sig_binary = ben_str_val(sig_ben);
				
				pk_ben = ben_dict_get_by_str(key_args, "k");
				pk_binary = ben_str_val(pk_ben);
				
				sig = ben_dict();

				salt = ben_dict_get_by_str(key_args, "salt");
				if ( salt ) {
					ben_dict_set(sig, ben_blob("salt", 4), ben_blob(ben_str_val(salt), ben_str_len(salt)));
				}

				/* TODO: fix double reference here. Need to bencode duplicate these values, and then free sig when finished encoding it */
				ben_dict_set(sig, ben_blob("seq", 3), ben_dict_get_by_str(key_args, "seq"));
				ben_dict_set(sig, ben_blob("v", 1), ben_dict_get_by_str(key_args, "v"));

				data_sig = (unsigned char *) ben_encode(&data_sig_len, sig);

				if ( !data_sig ) {
					ks_log(KS_LOG_DEBUG, "Failed to encode message for signature validation\n");
					goto dontread;					
				}

				if (crypto_sign_verify_detached((unsigned char *)sig_binary, data_sig, data_sig_len, (unsigned char *) pk_binary) != 0) {
					ks_log(KS_LOG_DEBUG, "Signature failed to verify. Corrupted or malicious data suspected!\n");
					goto dontread;										
				} else {
					ks_log(KS_LOG_DEBUG, "Valid message store signature.\n");
				}

				ks_dht_store_entry_create(h->pool, msg_ben, &entry, 600, 0);
				ks_dht_store_insert(h->store, entry, h->now);
			}
			break;
		case DHT_MSG_INVALID:
		case DHT_MSG_ERROR:
            ks_log(KS_LOG_DEBUG, "Unparseable message: %s\n", debug_printable(buf, logmsg, buflen));
            goto dontread;
        case DHT_MSG_REPLY:
            if (tid_len != 4) {
                ks_log(KS_LOG_DEBUG, "Broken node truncates transaction ids: %s\n", debug_printable(buf, logmsg, buflen));
                /* This is really annoying, as it means that we will
                   time-out all our searches that go through this node.
                   Kill it. */
                blacklist_node(h, id, from, fromlen);
                goto dontread;
            }
            if (tid_match(tid, "pn", NULL)) {
                ks_log(KS_LOG_DEBUG, "Pong!\n");
                new_node(h, id, from, fromlen, 2);
            } else if (tid_match(tid, "fn", NULL) || tid_match(tid, "gp", NULL)) {
                int gp = 0;
                struct search *sr = NULL;
                if (tid_match(tid, "gp", &ttid)) {
                    gp = 1;
                    sr = find_search(h, ttid, from->sa_family);
                }
                ks_log(KS_LOG_DEBUG, "Nodes found (%d+%d)%s!\n", nodes_len/26, nodes6_len/38, gp ? " for get_peers" : "");
                if (nodes_len % 26 != 0 || nodes6_len % 38 != 0) {
                    ks_log(KS_LOG_DEBUG, "Unexpected length for node info!\n");
                    blacklist_node(h, id, from, fromlen);
                } else if (gp && sr == NULL) {
                    ks_log(KS_LOG_DEBUG, "Unknown search!\n");
                    new_node(h, id, from, fromlen, 1);
                } else {
                    int i;
                    new_node(h, id, from, fromlen, 2);
                    for (i = 0; i < nodes_len / 26; i++) {
                        unsigned char *ni = nodes + i * 26;
                        struct sockaddr_in sin;
                        if (id_cmp(ni, h->myid) == 0) {
                            continue;
						}
                        memset(&sin, 0, sizeof(sin));
                        sin.sin_family = AF_INET;
                        memcpy(&sin.sin_addr, ni + 20, 4);
                        memcpy(&sin.sin_port, ni + 24, 2);
                        new_node(h, ni, (struct sockaddr*)&sin, sizeof(sin), 0);
                        if (sr && sr->af == AF_INET) {
                            insert_search_node(h, ni, (struct sockaddr*)&sin, sizeof(sin), sr, 0, NULL, 0);
                        }
                    }
                    for (i = 0; i < nodes6_len / 38; i++) {
                        unsigned char *ni = nodes6 + i * 38;
                        struct sockaddr_in6 sin6;
                        if (id_cmp(ni, h->myid) == 0) {
                            continue;
						}
                        memset(&sin6, 0, sizeof(sin6));
                        sin6.sin6_family = AF_INET6;
                        memcpy(&sin6.sin6_addr, ni + 20, 16);
                        memcpy(&sin6.sin6_port, ni + 36, 2);
                        new_node(h, ni, (struct sockaddr*)&sin6, sizeof(sin6), 0);
                        if (sr && sr->af == AF_INET6) {
                            insert_search_node(h, ni, (struct sockaddr*)&sin6, sizeof(sin6), sr, 0, NULL, 0);
                        }
                    }
                    if (sr) {
                        /* Since we received a reply, the number of requests in flight has decreased.  Let's push another request. */
                        search_send_get_peers(h, sr, NULL);
					}
                }
                if (sr) {
                    insert_search_node(h, id, from, fromlen, sr, 1, token, token_len);
                    if (values_len > 0 || values6_len > 0) {
                        ks_log(KS_LOG_DEBUG, "Got values (%d+%d)!\n", values_len / 6, values6_len / 18);
                        if (callback) {
                            if (values_len > 0) {
                                (*callback)(closure, KS_DHT_EVENT_VALUES, sr->id, (void*)values, values_len);
							}
                            if (values6_len > 0) {
                                (*callback)(closure, KS_DHT_EVENT_VALUES6, sr->id, (void*)values6, values6_len);
							}
                        }
                    }
                }
            } else if (tid_match(tid, "ap", &ttid)) {
                struct search *sr;
                ks_log(KS_LOG_DEBUG, "Got reply to announce_peer.\n");
                sr = find_search(h, ttid, from->sa_family);
                if (!sr) {
                    ks_log(KS_LOG_DEBUG, "Unknown search!\n");
                    new_node(h, id, from, fromlen, 1);
                } else {
                    int i;
                    new_node(h, id, from, fromlen, 2);
                    for (i = 0; i < sr->numnodes; i++) {
                        if (id_cmp(sr->nodes[i].id, id) == 0) {
                            sr->nodes[i].request_time = 0;
                            sr->nodes[i].reply_time = h->now;
                            sr->nodes[i].acked = 1;
                            sr->nodes[i].pinged = 0;
                            break;
                        }
					}
                    /* See comment for gp above. */
                    search_send_get_peers(h, sr, NULL);
                }
            } else {
                ks_log(KS_LOG_DEBUG, "Unexpected reply: %s\n", debug_printable(buf, logmsg, buflen));
            }
            break;
        case DHT_MSG_PING:
            ks_log(KS_LOG_DEBUG, "Ping (%d)!\n", tid_len);
            new_node(h, id, from, fromlen, 1);
            ks_log(KS_LOG_DEBUG, "Sending pong.\n");
            send_pong(h, from, fromlen, tid, tid_len);
            break;
        case DHT_MSG_FIND_NODE:
			if ( key_args ) {
				/* 
				   http://www.bittorrent.org/beps/bep_0005.html
				   http://www.bittorrent.org/beps/bep_0032.html
				   
				   find_node Query = {"t":"aa", "y":"q", "q":"find_node", "a": {"id":"abcdefghij0123456789", "target":"mnopqrstuvwxyz123456"}}
				   bencoded = d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe
				*/
			
				ks_log(KS_LOG_DEBUG, "Find node!\n");
				/* Needs to fetch the from, and fromlen from the decoded message, as well as the target and want */
				new_node(h, id, from, fromlen, 1);
				ks_log(KS_LOG_DEBUG, "Sending closest nodes (%d).\n", want);
				send_closest_nodes(h, from, fromlen, tid, tid_len, target, want, 0, NULL, NULL, 0);
			} else {
				goto dontread;
			}
            break;
        case DHT_MSG_GET_PEERS:
			/* 
			   http://www.bittorrent.org/beps/bep_0005.html

			   get_peers Query = {"t":"aa", "y":"q", "q":"get_peers", "a": {"id":"abcdefghij0123456789", "info_hash":"mnopqrstuvwxyz123456"}}
			   bencoded = d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe
			 */

            ks_log(KS_LOG_DEBUG, "Get_peers!\n");
            new_node(h, id, from, fromlen, 1);
            if (id_cmp(info_hash, zeroes) == 0) {
                ks_log(KS_LOG_DEBUG, "Eek!  Got get_peers with no info_hash.\n");
                send_error(h, from, fromlen, tid, tid_len, 203, "Get_peers with no info_hash");
                break;
            } else {
                struct storage *st = find_storage(h, info_hash);
                unsigned char token[TOKEN_SIZE];
                make_token(h, from, 0, token);
                if (st && st->numpeers > 0) {
                     ks_log(KS_LOG_DEBUG, "Sending found%s peers.\n", from->sa_family == AF_INET6 ? " IPv6" : "");
                     send_closest_nodes(h, from, fromlen, tid, tid_len, info_hash, want, from->sa_family, st, token, TOKEN_SIZE);
                } else {
                    ks_log(KS_LOG_DEBUG, "Sending nodes for get_peers.\n");
                    send_closest_nodes(h, from, fromlen, tid, tid_len, info_hash, want, 0, NULL, token, TOKEN_SIZE);
                }
            }
            break;
        case DHT_MSG_ANNOUNCE_PEER:
            ks_log(KS_LOG_DEBUG, "Announce peer!\n");
            new_node(h, id, from, fromlen, 1);
            if (id_cmp(info_hash, zeroes) == 0) {
                ks_log(KS_LOG_DEBUG, "Announce_peer with no info_hash.\n");
                send_error(h, from, fromlen, tid, tid_len, 203, "Announce_peer with no info_hash");
                break;
            }
            if (!token_match(h, token, token_len, from)) {
                ks_log(KS_LOG_DEBUG, "Incorrect token for announce_peer.\n");
                send_error(h, from, fromlen, tid, tid_len, 203, "Announce_peer with wrong token");
                break;
            }
            if (port == 0) {
                ks_log(KS_LOG_DEBUG, "Announce_peer with forbidden port %d.\n", port);
                send_error(h, from, fromlen, tid, tid_len, 203, "Announce_peer with forbidden port number");
                break;
            }
            storage_store(h, info_hash, from, port);
            /* Note that if storage_store failed, we lie to the requestor. This is to prevent them from backtracking, and hence polluting the DHT. */
            ks_log(KS_LOG_DEBUG, "Sending peer announced.\n");
            send_peer_announced(h, from, fromlen, tid, tid_len);
        }
    }

 dontread:
    if (h->now >= h->rotate_secrets_time) {
        rotate_secrets(h);
	}

    if (h->now >= h->expire_stuff_time) {
        expire_buckets(h, h->buckets);
        expire_buckets(h, h->buckets6);
        expire_storage(h);
        expire_searches(h);
    }

    if (h->search_time > 0 && h->now >= h->search_time) {
        struct search *sr;
        sr = h->searches;
        while (sr) {
            if (!sr->done && sr->step_time + 5 <= h->now) {
                search_step(h, sr, callback, closure);
            }
            sr = sr->next;
        }

        h->search_time = 0;

        sr = h->searches;
        while (sr) {
            if (!sr->done) {
                time_t tm = sr->step_time + 15 + random() % 10;
                if (h->search_time == 0 || h->search_time > tm) {
                    h->search_time = tm;
				}
            }
            sr = sr->next;
        }
    }

    if (h->now >= h->confirm_nodes_time) {
        int soon = 0;

        soon |= bucket_maintenance(h, AF_INET);
        soon |= bucket_maintenance(h, AF_INET6);

        if (!soon) {
            if (h->mybucket_grow_time >= h->now - 150) {
                soon |= neighbourhood_maintenance(h, AF_INET);
			}
            if (h->mybucket6_grow_time >= h->now - 150) {
                soon |= neighbourhood_maintenance(h, AF_INET6);
			}
        }

        /* In order to maintain all buckets' age within 600 seconds, worst case is roughly 27 seconds, assuming the table is 22 bits deep.
           We want to keep a margin for neighborhood maintenance, so keep this within 25 seconds. */
        if (soon) {
            h->confirm_nodes_time = h->now + 5 + random() % 20;
		} else {
            h->confirm_nodes_time = h->now + 60 + random() % 120;
		}
    }

    if (h->confirm_nodes_time > h->now) {
        *tosleep = h->confirm_nodes_time - h->now;
    } else {
        *tosleep = 0;
	}

    if (h->search_time > 0) {
        if (h->search_time <= h->now) {
            *tosleep = 0;
        } else if (*tosleep > h->search_time - h->now) {
            *tosleep = h->search_time - h->now;
		}
    }
	free(logmsg);

	ks_dht_store_prune(h->store, h->now);

    return 1;
}

KS_DECLARE(int) dht_get_nodes(dht_handle_t *h, struct sockaddr_in *sin, int *num,
              struct sockaddr_in6 *sin6, int *num6)
{
    int i, j;
    struct bucket *b;
    struct node *n;

    i = 0;

    /* For restoring to work without discarding too many nodes, the list
       must start with the contents of our bucket. */
    b = find_bucket(h, h->myid, AF_INET);
    if (b == NULL) {
        goto no_ipv4;
	}

    n = b->nodes;
    while (n && i < *num) {
        if (node_good(h, n)) {
            sin[i] = *(struct sockaddr_in*)&n->ss;
            i++;
        }
        n = n->next;
    }

    b = h->buckets;
    while (b && i < *num) {
        if (!in_bucket(h->myid, b)) {
            n = b->nodes;
            while (n && i < *num) {
                if (node_good(h, n)) {
                    sin[i] = *(struct sockaddr_in*)&n->ss;
                    i++;
                }
                n = n->next;
            }
        }
        b = b->next;
    }

 no_ipv4:

    j = 0;

    b = find_bucket(h, h->myid, AF_INET6);
    if (b == NULL) {
        goto no_ipv6;
	}

    n = b->nodes;
    while (n && j < *num6) {
        if (node_good(h, n)) {
            sin6[j] = *(struct sockaddr_in6*)&n->ss;
            j++;
        }
        n = n->next;
    }

    b = h->buckets6;
    while (b && j < *num6) {
        if (!in_bucket(h->myid, b)) {
            n = b->nodes;
            while (n && j < *num6) {
                if (node_good(h, n)) {
                    sin6[j] = *(struct sockaddr_in6*)&n->ss;
                    j++;
                }
                n = n->next;
            }
        }
        b = b->next;
    }

 no_ipv6:

    *num = i;
    *num6 = j;
    return i + j;
}

KS_DECLARE(int) dht_insert_node(dht_handle_t *h, const unsigned char *id, struct sockaddr *sa, int salen)
{
    struct node *n;

    if (sa->sa_family != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    n = new_node(h, id, (struct sockaddr*)sa, salen, 0);
    return !!n;
}

KS_DECLARE(int) dht_ping_node(dht_handle_t *h, struct sockaddr *sa, int salen)
{
    unsigned char tid[4];

    ks_log(KS_LOG_DEBUG, "Sending ping.\n");
    make_tid(tid, "pn", 0);
    return send_ping(h, sa, salen, tid, 4);
}

/* We could use a proper bencoding printer and parser, but the format of
   DHT messages is fairly stylised, so this seemed simpler. */

#define CHECK(offset, delta, size)                      \
    if (delta < 0 || offset + delta > size) goto fail

#define INC(offset, delta, size)                        \
    CHECK(offset, delta, size);                         \
    offset += delta

#define COPY(buf, offset, src, delta, size)             \
    CHECK(offset, delta, size);                         \
    memcpy(buf + offset, src, delta);                   \
    offset += delta;

#define ADD_V(buf, offset, size)                        \
    if (h->have_v) {                                        \
        COPY(buf, offset, h->my_v, sizeof(h->my_v), size);    \
    }

static int dht_send(dht_handle_t *h, const void *buf, size_t len, int flags, const struct sockaddr *sa, int salen)
{
    int s;

    if (salen == 0) {
        abort();
	}

    if (node_blacklisted(h, sa, salen)) {
        ks_log(KS_LOG_DEBUG, "Attempting to send to blacklisted node.\n");
        errno = EPERM;
        return -1;
    }

    if (sa->sa_family == AF_INET) {
        s = h->dht_socket;
	} else if (sa->sa_family == AF_INET6) {
        s = h->dht_socket6;
	} else {
        s = -1;
	}

    if (s < 0) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    return sendto(s, buf, len, flags, sa, salen);
}

/* Sample ping packet '{"t":"aa", "y":"q", "q":"ping", "a":{"id":"abcdefghij0123456789"}}' */
/* http://www.bittorrent.org/beps/bep_0005.html */
int send_ping(dht_handle_t *h, const struct sockaddr *sa, int salen, const unsigned char *tid, int tid_len)
{
    char buf[512];
    int i = 0;
	struct bencode *bencode_p = ben_dict();
	struct bencode *bencode_a_p = ben_dict();

	ben_dict_set(bencode_p, ben_blob("t", 1), ben_blob(tid, tid_len));
	ben_dict_set(bencode_p, ben_blob("y", 1), ben_blob("q", 1));	
	ben_dict_set(bencode_p, ben_blob("q", 1), ben_blob("ping", 4));
	ben_dict_set(bencode_a_p, ben_blob("id", 2), ben_blob(h->myid, 20));
	ben_dict_set(bencode_p, ben_blob("a", 1), bencode_a_p);

	i = ben_encode2(buf, 512, bencode_p);
	ben_free(bencode_p); /* This SHOULD free the bencode_a_p as well */

    return dht_send(h, buf, i, 0, sa, salen);
}

/* Sample pong packet '{"t":"aa", "y":"r", "r": {"id":"mnopqrstuvwxyz123456"}}' */
/* http://www.bittorrent.org/beps/bep_0005.html */
int send_pong(dht_handle_t *h, const struct sockaddr *sa, int salen, const unsigned char *tid, int tid_len)
{
    char buf[512];
	int i = 0;
	struct bencode *bencode_p = ben_dict();
	struct bencode *bencode_a_p = ben_dict();

	ben_dict_set(bencode_p, ben_blob("t", 1), ben_blob(tid, tid_len));
	ben_dict_set(bencode_p, ben_blob("y", 1), ben_blob("r", 1));
	ben_dict_set(bencode_a_p, ben_blob("id", 2), ben_blob(h->myid, 20));
	ben_dict_set(bencode_p, ben_blob("r", 1), bencode_a_p);

	i = ben_encode2(buf, 512, bencode_p);
	ben_free(bencode_p); /* This SHOULD free the bencode_a_p as well */

	ks_log(KS_LOG_DEBUG, "Encoded PONG: %s\n\n", buf);
    return dht_send(h, buf, i, 0, sa, salen);
}

/* Sample find_node packet '{"t":"aa", "y":"q", "q":"find_node", "a": {"id":"abcdefghij0123456789", "target":"mnopqrstuvwxyz123456"}}' */
/* Sample find_node packet w/ want '{"t":"aa", "y":"q", "q":"find_node", "a": {"id":"abcdefghij0123456789", "target":"mnopqrstuvwxyz123456", "want":"n4"}}' */
/* http://www.bittorrent.org/beps/bep_0005.html */
/* http://www.bittorrent.org/beps/bep_0032.html for want parameter */
int send_find_node(dht_handle_t *h, const struct sockaddr *sa, int salen,
               const unsigned char *tid, int tid_len,
               const unsigned char *target, int want, int confirm)
{
    char buf[512];
	int i = 0;
	struct bencode *bencode_p = ben_dict();
	struct bencode *bencode_a_p = ben_dict();
	int target_len = target ? strlen((const char*)target) : 0;

	ben_dict_set(bencode_p, ben_blob("t", 1), ben_blob(tid, tid_len));
	ben_dict_set(bencode_p, ben_blob("y", 1), ben_blob("q", 1));
	ben_dict_set(bencode_p, ben_blob("q", 1), ben_blob("find_node", 9));
	ben_dict_set(bencode_a_p, ben_blob("id", 2), ben_blob(h->myid, 20));

	if (target) ben_dict_set(bencode_a_p, ben_blob("target", 6), ben_blob(target, target_len));

	if (want > 0) {
		char *w = NULL;
		if (want & WANT4) w = "n4";
		if (want & WANT6) w = "n6";
		if (w) ben_dict_set(bencode_a_p, ben_blob("want", 4), ben_blob(w, 2));
	}

	ben_dict_set(bencode_p, ben_blob("a", 1), bencode_a_p);

	i = ben_encode2(buf, 512, bencode_p);
	ben_free(bencode_p); /* This SHOULD free the bencode_a_p as well */

    return dht_send(h, buf, i, confirm ? MSG_CONFIRM : 0, sa, salen);
}

/* sample find_node response '{"t":"aa", "y":"r", "r": {"id":"0123456789abcdefghij", "nodes": "def456..."}}'*/
/* http://www.bittorrent.org/beps/bep_0005.html */
int send_nodes_peers(dht_handle_t *h, const struct sockaddr *sa, int salen,
                 const unsigned char *tid, int tid_len,
                 const unsigned char *nodes, int nodes_len,
                 const unsigned char *nodes6, int nodes6_len,
                 int af, struct storage *st,
                 const unsigned char *token, int token_len)
{
    char buf[2048];
    int i = 0, j0, j, k, len;
	struct bencode *bencode_p = ben_dict();
	struct bencode *bencode_a_p = ben_dict();
	struct bencode *ben_array = ben_list();

	ben_dict_set(bencode_p, ben_blob("t", 1), ben_blob(tid, tid_len));
	ben_dict_set(bencode_p, ben_blob("y", 1), ben_blob("r", 1));
	ben_dict_set(bencode_a_p, ben_blob("id", 2), ben_blob(h->myid, 20));
	if (token_len)  ben_dict_set(bencode_a_p, ben_blob("token",  5), ben_blob(token, token_len));
	if (nodes_len)  ben_dict_set(bencode_a_p, ben_blob("nodes",  5), ben_blob(nodes, nodes_len));
	if (nodes6_len) ben_dict_set(bencode_a_p, ben_blob("nodes6", 6), ben_blob(nodes6, nodes6_len));

	/* 
	   Response with peers = {"t":"aa", "y":"r", "r": {"id":"abcdefghij0123456789", "token":"aoeusnth", "values": ["axje.u", "idhtnm"]}}
	*/
	
    if (st && st->numpeers > 0) {
        // We treat the storage as a circular list, and serve a randomly
        //   chosen slice.  In order to make sure we fit within 1024 octets,
        //   we limit ourselves to 50 peers.

        len = af == AF_INET ? 4 : 16;
        j0 = random() % st->numpeers;
        j = j0;
        k = 0;

       do {
            if (st->peers[j].len == len) {
				char data[18];
				unsigned short swapped = htons(st->peers[j].port);
				memcpy(data, st->peers[j].ip, len);
				memcpy(data + len, &swapped, 2);
				ben_list_append(ben_array, ben_blob(data, len + 2));
                k++;
            }
            j = (j + 1) % st->numpeers;
        } while(j != j0 && k < 50);
	   ben_dict_set(bencode_a_p, ben_blob("values", 6), ben_array);
    }

	ben_dict_set(bencode_p, ben_blob("r", 1), bencode_a_p);
	i = ben_encode2(buf, 512, bencode_p);
	ben_free(bencode_p); /* This SHOULD free the bencode_a_p as well */
	
	return dht_send(h, buf, i, 0, sa, salen);
}

static int insert_closest_node(unsigned char *nodes, int numnodes,
                    const unsigned char *id, struct node *n)
{
    int i, size;

    if (n->ss.ss_family == AF_INET) {
        size = 26;
    } else if (n->ss.ss_family == AF_INET6) {
        size = 38;
    } else {
        abort();
	}

    for (i = 0; i< numnodes; i++) {
        if (id_cmp(n->id, nodes + size * i) == 0) {
            return numnodes;
		}
        if (xorcmp(n->id, nodes + size * i, id) < 0) {
            break;
		}
    }

    if (i == 8) {
        return numnodes;
	}

    if (numnodes < 8) {
        numnodes++;
	}

    if (i < numnodes - 1) {
        memmove(nodes + size * (i + 1), nodes + size * i, size * (numnodes - i - 1));
	}

    if (n->ss.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in*)&n->ss;
        memcpy(nodes + size * i, n->id, 20);
        memcpy(nodes + size * i + 20, &sin->sin_addr, 4);
        memcpy(nodes + size * i + 24, &sin->sin_port, 2);
    } else if (n->ss.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&n->ss;
        memcpy(nodes + size * i, n->id, 20);
        memcpy(nodes + size * i + 20, &sin6->sin6_addr, 16);
        memcpy(nodes + size * i + 36, &sin6->sin6_port, 2);
    } else {
        abort();
    }

    return numnodes;
}

static int buffer_closest_nodes(dht_handle_t *h, unsigned char *nodes, int numnodes, const unsigned char *id, struct bucket *b)
{
    struct node *n = b->nodes;
    while (n) {
        if (node_good(h, n)) {
            numnodes = insert_closest_node(nodes, numnodes, id, n);
		}
        n = n->next;
    }
    return numnodes;
}

int send_closest_nodes(dht_handle_t *h, const struct sockaddr *sa, int salen,
					   const unsigned char *tid, int tid_len,
					   const unsigned char *id, int want,
					   int af, struct storage *st,
					   const unsigned char *token, int token_len)
{
    unsigned char nodes[8 * 26];
    unsigned char nodes6[8 * 38];
    int numnodes = 0, numnodes6 = 0;
    struct bucket *b;

    if (want < 0) {
        want = sa->sa_family == AF_INET ? WANT4 : WANT6;
	}

    if ((want & WANT4)) {
        if ((b = find_bucket(h, id, AF_INET))) {
            numnodes = buffer_closest_nodes(h, nodes, numnodes, id, b);
            if (b->next) {
                numnodes = buffer_closest_nodes(h, nodes, numnodes, id, b->next);
			}
            if ((b = previous_bucket(h, b))) {
                numnodes = buffer_closest_nodes(h, nodes, numnodes, id, b);
			}
        }
    }

    if ((want & WANT6)) {
        if ((b = find_bucket(h, id, AF_INET6))) {
            numnodes6 = buffer_closest_nodes(h, nodes6, numnodes6, id, b);
            if (b->next) { 
                numnodes6 = buffer_closest_nodes(h, nodes6, numnodes6, id, b->next);
			}
            if ((b = previous_bucket(h, b))) {
                numnodes6 = buffer_closest_nodes(h, nodes6, numnodes6, id, b);
			}
        }
    }
    ks_log(KS_LOG_DEBUG, "  (%d+%d nodes.)\n", numnodes, numnodes6);

    return send_nodes_peers(h, sa, salen, tid, tid_len,
                            nodes, numnodes * 26,
                            nodes6, numnodes6 * 38,
                            af, st, token, token_len);
}

/* sample get_peers request '{"t":"aa", "y":"q", "q":"get_peers", "a": {"id":"abcdefghij0123456789", "info_hash":"mnopqrstuvwxyz123456"}}'*/
/* sample get_peers w/ want '{"t":"aa", "y":"q", "q":"get_peers", "a": {"id":"abcdefghij0123456789", "info_hash":"mnopqrstuvwxyz123456": "want":"n4"}}'*/
/* http://www.bittorrent.org/beps/bep_0005.html */
/* http://www.bittorrent.org/beps/bep_0032.html for want parameter */
int send_get_peers(dht_handle_t *h, const struct sockaddr *sa, int salen,
				   unsigned char *tid, int tid_len, unsigned char *infohash,
				   int want, int confirm)
{
    char buf[512];
    int i = 0;
	struct bencode *bencode_p = ben_dict();
	struct bencode *bencode_a_p = ben_dict();
	int infohash_len = infohash ? strlen((const char*)infohash) : 0;

	ben_dict_set(bencode_p, ben_blob("t", 1), ben_blob(tid, tid_len));
	ben_dict_set(bencode_p, ben_blob("y", 1), ben_blob("q", 1));
	ben_dict_set(bencode_p, ben_blob("q", 1), ben_blob("get_peers", 9));
	ben_dict_set(bencode_a_p, ben_blob("id", 2), ben_blob(h->myid, 20));
	if (want > 0) {
		char *w = NULL;
		if (want & WANT4) w = "n4";
		if (want & WANT6) w = "n6";
		if (w) ben_dict_set(bencode_a_p, ben_blob("want", 4), ben_blob(w, 2));
	}
	ben_dict_set(bencode_a_p, ben_blob("info_hash", 9), ben_blob(infohash, infohash_len));
	ben_dict_set(bencode_p, ben_blob("a", 1), bencode_a_p);

	i = ben_encode2(buf, 512, bencode_p);
	ben_free(bencode_p); /* This SHOULD free the bencode_a_p as well */
	
	ks_log(KS_LOG_DEBUG, "Encoded GET_PEERS: %s\n\n", buf);
    return dht_send(h, buf, i, confirm ? MSG_CONFIRM : 0, sa, salen);
}
/* '{"t":"aa", "y":"q", "q":"announce_peer", "a": {"id":"abcdefghij0123456789", "implied_port": 1, "info_hash":"mnopqrstuvwxyz123456", "port": 6881, "token": "aoeusnth"}}'*/
int send_announce_peer(dht_handle_t *h, const struct sockaddr *sa, int salen,
					   unsigned char *tid, int tid_len,
					   unsigned char *infohash, unsigned short port,
					   unsigned char *token, int token_len, int confirm)
{
    char buf[512];
    int i = 0;
	struct bencode *bencode_p = ben_dict();
	struct bencode *bencode_a_p = ben_dict();
	int infohash_len = infohash ? strlen((const char*)infohash) : 0;

	ben_dict_set(bencode_p, ben_blob("t", 1), ben_blob(tid, tid_len));
	ben_dict_set(bencode_p, ben_blob("y", 1), ben_blob("q", 1));
	ben_dict_set(bencode_p, ben_blob("q", 1), ben_blob("announce_peer", 13));
	ben_dict_set(bencode_a_p, ben_blob("id", 2), ben_blob(h->myid, 20));
	ben_dict_set(bencode_a_p, ben_blob("info_hash", 9), ben_blob(infohash, infohash_len));
	ben_dict_set(bencode_a_p, ben_blob("port", 5), ben_int(port));
	ben_dict_set(bencode_a_p, ben_blob("token", 5), ben_blob(token, token_len));
	ben_dict_set(bencode_p, ben_blob("a", 1), bencode_a_p);

	i = ben_encode2(buf, 512, bencode_p);
	ben_free(bencode_p); /* This SHOULD free the bencode_a_p as well */
	
	ks_log(KS_LOG_DEBUG, "Encoded ANNOUNCE_PEERS: %s\n\n", buf);
    return dht_send(h, buf, i, confirm ? MSG_CONFIRM : 0, sa, salen);
}
/* '{"t":"aa", "y":"r", "r": {"id":"mnopqrstuvwxyz123456"}}'*/
static int send_peer_announced(dht_handle_t *h, const struct sockaddr *sa, int salen, unsigned char *tid, int tid_len)
{
    char buf[512];
    int i = 0;
	struct bencode *bencode_p = ben_dict();
	struct bencode *bencode_a_p = ben_dict();

	ben_dict_set(bencode_p, ben_blob("t", 1), ben_blob(tid, tid_len));
	ben_dict_set(bencode_p, ben_blob("y", 1), ben_blob("r", 1));
	ben_dict_set(bencode_a_p, ben_blob("id", 2), ben_blob(h->myid, 20));
	ben_dict_set(bencode_p, ben_blob("r", 1), bencode_a_p);
	
	i = ben_encode2(buf, 512, bencode_p);
	ben_free(bencode_p); /* This SHOULD free the bencode_a_p as well */
	
	ks_log(KS_LOG_DEBUG, "Encoded peer_announced: %s\n\n", buf);
    return dht_send(h, buf, i, 0, sa, salen);
}

/* '{"t":"aa", "y":"e", "e":[201, "A Generic Error Ocurred"]}'*/
static int send_error(dht_handle_t *h, const struct sockaddr *sa, int salen,
					  unsigned char *tid, int tid_len,
					  int code, const char *message)
{
    char buf[512];
    int i = 0;
	struct bencode *bencode_p = ben_dict();
	struct bencode *ben_array = ben_list();

	ben_dict_set(bencode_p, ben_blob("t", 1), ben_blob(tid, tid_len));
	ben_dict_set(bencode_p, ben_blob("y", 1), ben_blob("e", 1));
	ben_list_append(ben_array, ben_int(code));
	ben_list_append(ben_array, ben_blob(message, strlen(message)));
	ben_dict_set(bencode_p, ben_blob("e", 1), ben_array);

	i = ben_encode2(buf, 512, bencode_p);
	ben_free(bencode_p);
	
	ks_log(KS_LOG_DEBUG, "Encoded error: %s\n\n", buf);
    return dht_send(h, buf, i, 0, sa, salen);
}

#undef CHECK
#undef INC
#undef COPY
#undef ADD_V

/*

#ifdef HAVE_MEMMEM

static void *dht_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
{
    return memmem(haystack, haystacklen, needle, needlelen);
}

#else

static void *dht_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
{
    const char *h = haystack;
    const char *n = needle;
    size_t i;

  
    if (needlelen > haystacklen)
        return NULL;

    for(i = 0; i <= haystacklen - needlelen; i++) {
        if (memcmp(h + i, n, needlelen) == 0) {
            return (void*)(h + i);
		}
    }
    return NULL;
}

#endif
*/
static dht_msg_type_t parse_message(struct bencode *bencode_p,
									unsigned char *tid_return, int *tid_len,
									unsigned char *id_return)
{
	//    const unsigned char *p;
	dht_msg_type_t type = DHT_MSG_INVALID;
	struct bencode *b_tmp = NULL;
	struct bencode *key_t = ben_dict_get_by_str(bencode_p, "t");
	struct bencode *key_args = ben_dict_get_by_str(bencode_p, "a");
	struct bencode *key_resp = ben_dict_get_by_str(bencode_p, "r");

	ks_log(KS_LOG_DEBUG, "decoded: %s \n", ben_print(bencode_p));
	/* Need to set tid, tid_len, and id_return. Then return the message type or msg_error. */

	if ( key_t ) {
		const char *tran = ben_str_val(key_t);
		int tran_len = ben_str_len(key_t);

		memcpy(tid_return, tran, (size_t) tran_len);
		*tid_len = tran_len;
		ks_log(KS_LOG_DEBUG, "Message transaction [%.*s]\n", tran_len, tran);
	}

	if ( key_args ) {
		struct bencode *b_id = ben_dict_get_by_str( key_args, "id");
		const char *id = b_id ? ben_str_val(b_id) : NULL;
		int id_len = ben_str_len(b_id);
		
		if ( id ) {
			memcpy(id_return, id, id_len);
		}
	}

	if ( key_resp ) {
		struct bencode *b_id = ben_dict_get_by_str( key_resp, "id");
		const char *id = b_id ? ben_str_val(b_id) : NULL;
		int id_len = ben_str_len(b_id);
		
		if ( id ) {
			memcpy(id_return, id, id_len);
		}
	}
	

	if ( ben_dict_get_by_str(bencode_p, "y") && key_t ){
		/* This message is a KRPC message(aka DHT message) */

		if ( ( b_tmp = ben_dict_get_by_str(bencode_p, "y") ) ) {
			if ( !ben_cmp_with_str(b_tmp, "q") ) { /* Inbound queries */
				struct bencode *b_query = NULL;
				const char *val = ben_str_val(b_tmp);
				ks_log(KS_LOG_DEBUG, "Message Query [%s]\n", val);

				if ( !( b_query = ben_dict_get_by_str(bencode_p, "q") ) ) {
					ks_log(KS_LOG_DEBUG, "Unable to locate query type field\n");
				} else { /* Has a query type */
					const char *query_type = ben_str_val(b_query);
					if (!ben_cmp_with_str(b_query, "get_peers")) {
						struct bencode *b_infohash = key_args ? ben_dict_get_by_str( key_args, "info_hash") : NULL;
						const char *infohash = b_infohash ? ben_str_val(b_infohash) : NULL;
						/*
						  {
						    'a': {
							      'id': '~\x12*\xe6L3\xba\x83\xafT\xe3\x02\x93\x0e\xae\xbd\xf8\xe1\x98\x87', 
							      'info_hash': 'w"E\x85\xdd97\xd1\xfe\x13Q\xfa\xdae\x9d\x8f\x86\xddN9'
							     }, 
							'q': 'get_peers', 
							't': '?\xf1', 
							'v': 'LT\x01\x00', 
							'y': 'q'
						  }
						 */
						
						ks_log(KS_LOG_DEBUG, "get_peers query recieved for info hash [%s] from client with id [%s]\n", infohash, id_return);
						type = DHT_MSG_GET_PEERS;
						goto done;
					} else if (!ben_cmp_with_str(b_query, "ping")) {
						/* 
						   {'a': {
						          'id': 'T\x1cd2\xc1\x85\xf4>?\x84#\xa8)\xd0`\x19y\xcf;\xda'
								 }, 
							'q': 'ping', 
							't': 'pn\x00\x00', 
							'v': 'JC\x00\x00', 
							'y': 'q'
						   }
						*/
						ks_log(KS_LOG_DEBUG, "ping query recieved from client with id [%s]\n", id_return);
						type = DHT_MSG_PING;
						goto done;
					} else if (!ben_cmp_with_str(b_query, "find_node")) {
						/*
						  {'a': {
						         'id': 'T\x1cq\x7f\xa9^\xf2\x97S\xceE\xad\xc9S\x9b\xa1\x1cCX\x8d',
								 'target': 'T\x1cq\x7f\xa9C{\x83\xf9\xf6i&\x8b\x87*\xa2\xad\xad\x1a\xdd'
								},
						   'q': 'find_node',
						   't': '\x915\xbe\xfb',
						   'v': 'UTu\x13',
						   'y': 'q'
						  }
						*/
						type = DHT_MSG_FIND_NODE;
						goto done;
					} else if (!ben_cmp_with_str(b_query, "put")) {
						ks_log(KS_LOG_DEBUG, "Recieved a store put request\n");
						ks_log(KS_LOG_DEBUG, "message [%s]\n", id_return);
						type = DHT_MSG_STORE_PUT;
						goto done;
					} else {
						ks_log(KS_LOG_DEBUG, "Unknown query type field [%s]\n", query_type);
					}
				}
				
			} else if ( !ben_cmp_with_str(b_tmp, "r") ) { /* Responses */
				const char *val = ben_str_val(b_tmp);
				ks_log(KS_LOG_DEBUG, "Message Response [%s]\n", val);
				type = DHT_MSG_REPLY;
				goto done;
			} else if ( !ben_cmp_with_str(b_tmp, "e") ) {
				const char *val = ben_str_val(b_tmp);
				ks_log(KS_LOG_DEBUG, "Message Error [%s]\n", val);
			} else {
				ks_log(KS_LOG_DEBUG, "Message Type Unknown!!!\n");
			}
		} else {
			ks_log(KS_LOG_DEBUG, "Message Type Unknown, has no 'y' key!!!\n");
		}
		
		/* 
		   Decode the request or response 
		   (b_tmp = ben_dict_get_by_str(bencode_p, "y"))) {
		   ks_log(KS_LOG_DEBUG, "query value: %s\n", ben_print(b_tmp));
		*/
	} else {
		ks_log(KS_LOG_DEBUG, "Message not a remote DHT request nor query\n");
	}

	/* Default to MSG ERROR */
	ks_log(KS_LOG_DEBUG, "Unknown or unsupported message type\n");
	return type;

 done:
	return type;

	/*
    if (dht_memmem(buf, buflen, "1:q4:ping", 9)) {
        return DHT_MSG_PING;
	}

    if (dht_memmem(buf, buflen, "1:q9:find_node", 14)) {
       return DHT_MSG_FIND_NODE;
	}

    if (dht_memmem(buf, buflen, "1:q9:get_peers", 14)) {
        return DHT_MSG_GET_PEERS;
	}

    if (dht_memmem(buf, buflen, "1:q13:announce_peer", 19)) {
       return DHT_MSG_ANNOUNCE_PEER;
	}

	char *val = ben_str_val(b_tmp);

	*/
	

	/*
	if (tid_return) {
        p = dht_memmem(buf, buflen, "1:t", 3);
        if (p) {
            long l;
            char *q;
            l = strtol((char*)p + 3, &q, 10);
            if (q && *q == ':' && l > 0 && l < *tid_len) {
                CHECK(q + 1, l);
                memcpy(tid_return, q + 1, l);
                *tid_len = l;
            } else
                *tid_len = 0;
        }
    }
    if (id_return) {
        p = dht_memmem(buf, buflen, "2:id20:", 7);
        if (p) {
            CHECK(p + 7, 20);
            memcpy(id_return, p + 7, 20);
        } else {
            memset(id_return, 0, 20);
        }
    }
    if (info_hash_return) {
        p = dht_memmem(buf, buflen, "9:info_hash20:", 14);
        if (p) {
            CHECK(p + 14, 20);
            memcpy(info_hash_return, p + 14, 20);
        } else {
            memset(info_hash_return, 0, 20);
        }
    }
    if (port_return) {
        p = dht_memmem(buf, buflen, "porti", 5);
        if (p) {
            long l;
            char *q;
            l = strtol((char*)p + 5, &q, 10);
            if (q && *q == 'e' && l > 0 && l < 0x10000) {
                *port_return = l;
            } else {
                *port_return = 0;
			}
        } else {
            *port_return = 0;
		}
    }
    if (target_return) {
        p = dht_memmem(buf, buflen, "6:target20:", 11);
        if (p) {
            CHECK(p + 11, 20);
            memcpy(target_return, p + 11, 20);
        } else {
            memset(target_return, 0, 20);
        }
    }
    if (token_return) {
        p = dht_memmem(buf, buflen, "5:token", 7);
        if (p) {
            long l;
            char *q;
            l = strtol((char*)p + 7, &q, 10);
            if (q && *q == ':' && l > 0 && l < *token_len) {
                CHECK(q + 1, l);
                memcpy(token_return, q + 1, l);
                *token_len = l;
            } else {
                *token_len = 0;
			}
        } else {
            *token_len = 0;
		}
    }

    if (nodes_len) {
        p = dht_memmem(buf, buflen, "5:nodes", 7);
        if (p) {
            long l;
            char *q;
            l = strtol((char*)p + 7, &q, 10);
            if (q && *q == ':' && l > 0 && l <= *nodes_len) {
                CHECK(q + 1, l);
                memcpy(nodes_return, q + 1, l);
                *nodes_len = l;
            } else {
                *nodes_len = 0;
			}
        } else {
            *nodes_len = 0;
		}
    }

    if (nodes6_len) {
        p = dht_memmem(buf, buflen, "6:nodes6", 8);
        if (p) {
            long l;
            char *q;
            l = strtol((char*)p + 8, &q, 10);
            if (q && *q == ':' && l > 0 && l <= *nodes6_len) {
                CHECK(q + 1, l);
                memcpy(nodes6_return, q + 1, l);
                *nodes6_len = l;
            } else {
                *nodes6_len = 0;
			}
        } else {
            *nodes6_len = 0;
		}
    }

    if (values_len || values6_len) {
        p = dht_memmem(buf, buflen, "6:valuesl", 9);
        if (p) {
            int i = p - buf + 9;
            int j = 0, j6 = 0;
            while (1) {
                long l;
                char *q;
                l = strtol((char*)buf + i, &q, 10);
                if (q && *q == ':' && l > 0) {
                    CHECK(q + 1, l);
                    i = q + 1 + l - (char*)buf;
                    if (l == 6) {
                        if (j + l > *values_len) {
                            continue;
						}
                        memcpy((char*)values_return + j, q + 1, l);
                        j += l;
                    } else if (l == 18) {
                        if (j6 + l > *values6_len) {
                            continue;
						}
                        memcpy((char*)values6_return + j6, q + 1, l);
                        j6 += l;
                    } else {
                        ks_log(KS_LOG_DEBUG, "Received weird value -- %d bytes.\n", (int)l);
                    }
                } else {
                    break;
                }
            }
            if (i >= buflen || buf[i] != 'e') {
                ks_log(KS_LOG_DEBUG, "eek... unexpected end for values.\n");
			}
            if (values_len) {
                *values_len = j;
			}
            if (values6_len) {
                *values6_len = j6;
			}
        } else {
            if (values_len) {
                *values_len = 0;
			}
            if (values6_len) {
                *values6_len = 0;
			}
        }
    }

    if (want_return) {
        p = dht_memmem(buf, buflen, "4:wantl", 7);
        if (p) {
            int i = p - buf + 7;
            *want_return = 0;
            while (buf[i] > '0' && buf[i] <= '9' && buf[i + 1] == ':' && i + 2 + buf[i] - '0' < buflen) {
                CHECK(buf + i + 2, buf[i] - '0');
                if (buf[i] == '2' && memcmp(buf + i + 2, "n4", 2) == 0) {
                    *want_return |= WANT4;
				} else if (buf[i] == '2' && memcmp(buf + i + 2, "n6", 2) == 0) {
                    *want_return |= WANT6;
                } else {
                    ks_log(KS_LOG_DEBUG, "eek... unexpected want flag (%c)\n", buf[i]);
				}
                i += 2 + buf[i] - '0';
            }
            if (i >= buflen || buf[i] != 'e') {
                ks_log(KS_LOG_DEBUG, "eek... unexpected end for want.\n");
			}
        } else {
            *want_return = -1;
        }
    }

#undef CHECK

    if (dht_memmem(buf, buflen, "1:y1:r", 6)) {
        return DHT_MSG_REPLY;
	}

    if (dht_memmem(buf, buflen, "1:y1:e", 6)) {
        return DHT_MSG_ERROR;
	}

    if (!dht_memmem(buf, buflen, "1:y1:q", 6)) {
        return DHT_MSG_INVALID;
	}

    if (dht_memmem(buf, buflen, "1:q4:ping", 9)) {
        return DHT_MSG_PING;
	}

    if (dht_memmem(buf, buflen, "1:q9:find_node", 14)) {
       return DHT_MSG_FIND_NODE;
	}

    if (dht_memmem(buf, buflen, "1:q9:get_peers", 14)) {
        return DHT_MSG_GET_PEERS;
	}

    if (dht_memmem(buf, buflen, "1:q13:announce_peer", 19)) {
       return DHT_MSG_ANNOUNCE_PEER;
	}

    return DHT_MSG_INVALID;

 overflow:
    ks_log(KS_LOG_DEBUG, "Truncated message.\n");
    return DHT_MSG_INVALID;
	*/
	
}

/* b64encode function taken from kws.c. Maybe worth exposing a function like this. */
static const char c64[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int b64encode(unsigned char *in, ks_size_t ilen, unsigned char *out, ks_size_t olen) 
{
	int y=0,bytes=0;
	ks_size_t x=0;
	unsigned int b=0,l=0;

	if(olen) {
	}

	for(x=0;x<ilen;x++) {
		b = (b<<8) + in[x];
		l += 8;
		while (l >= 6) {
			out[bytes++] = c64[(b>>(l-=6))%64];
			if(++y!=72) {
				continue;
			}
			//out[bytes++] = '\n';
			y=0;
		}
	}

	if (l > 0) {
		out[bytes++] = c64[((b%16)<<(6-l))%64];
	}
	if (l != 0) while (l < 6) {
		out[bytes++] = '=', l += 2;
	}

	return 0;
}


/* 
   This function should generate the fields needed for the mutable message.

   Save the sending for another api, and possibly a third to generate and send all in one.
   NOTE: 
   1. When sending a mutable message, CAS(compare and swap) values need to be validated.
   2. Mutable messages MUST have a new key pair generated for each different mutable message. 
      The announce key is generated as a hash from the public key. To use one key pair for multiple messages, 
	  a salt MUST be used that is unique and constant per message.
   3. The target hash will be generated here, and will be the hash that must be used for announcing the message, and updating it.

*/
int ks_dht_generate_mutable_storage_args(struct bencode *data, int64_t sequence, int cas,
										 unsigned char *id, int id_len, /* querying nodes id */
										 const unsigned char *sk, const unsigned char *pk,
										 unsigned char *salt, unsigned long long salt_length,
										 unsigned char *token, unsigned long long token_length,
										 unsigned char *signature, unsigned long long *signature_length,
										 struct bencode **arguments)
{
	struct bencode *arg = NULL, *sig = NULL;
	unsigned char *encoded_message = NULL, *encoded_data = NULL;
	size_t encoded_message_size = 0, encoded_data_size = 0;
	int err = 0;

	if ( !data || !sequence || !id || !id_len || !sk || !pk ||
		 !token || !token_length || !signature || !signature_length) {
		ks_log(KS_LOG_ERROR, "Missing required input\n");
		return -1;
	}

	if ( arguments && *arguments) {
		ks_log(KS_LOG_ERROR, "Arguments already defined.\n");
		return -1;
	}
	
	if ( salt && salt_length > 64 ) {
		ks_log(KS_LOG_ERROR, "Salt is too long. Can not be longer than 64 bytes\n");
		return -1;
	}

	if ( sequence && sequence < 0 ) {
		ks_log(KS_LOG_ERROR, "Sequence out of acceptable range\n");
		return -1;
	}

	encoded_data = (unsigned char *) ben_encode(&encoded_data_size, data);
	
	if ( encoded_data_size > 1000 ) {
		ks_log(KS_LOG_ERROR, "Message is too long. Max is 1000 bytes\n");
		free(encoded_data);
		return -1;
	}

	/* Need to dynamically allocate a bencoded object for the signature. */
	sig = ben_dict();

	if ( salt ) {
		ben_dict_set(sig, ben_blob("salt", 4), ben_blob(salt, salt_length));
	}
	
	ben_dict_set(sig, ben_blob("seq", 3), ben_int(sequence));
	ben_dict_set(sig, ben_blob("v", 1), ben_blob(encoded_data, encoded_data_size));

	encoded_message = ben_encode(&encoded_message_size, sig);
	ks_log(KS_LOG_DEBUG, "Encoded data %d [%.*s]\n", encoded_message_size, encoded_message_size, encoded_message);

	err = crypto_sign_detached(signature, NULL, encoded_message, encoded_message_size, sk);
	if ( err ) {
		ks_log(KS_LOG_ERROR, "Failed to sign message with provided secret key\n");
		return 1;
	}

	free(encoded_message);
	ben_free(sig);

	arg = ben_dict();

	if ( cas ) {
		ben_dict_set(arg, ben_blob("cas", 3), ben_int(cas));
	}

	ben_dict_set(arg, ben_blob("id", 2), ben_blob(id, id_len));
	ben_dict_set(arg, ben_blob("k", 1), ben_blob(pk, 32)); /* All ed25519 public keys are 32 bytes */

	if ( salt ) {
		ben_dict_set(arg, ben_blob("salt", 4), ben_blob(salt, salt_length));
	}
	
	ben_dict_set(arg, ben_blob("seq", 3), ben_int(sequence));
	ben_dict_set(arg, ben_blob("sig", 3), ben_blob(signature, (size_t) *signature_length));
	ben_dict_set(arg, ben_blob("token", 5), ben_blob(token, token_length));
	ben_dict_set(arg, ben_blob("v", 1), ben_blob(encoded_data, encoded_data_size));

	*arguments = arg;

	free(encoded_data);
	
	return 0;
}

int ks_dht_calculate_mutable_storage_target(unsigned char *pk, unsigned char *salt, int salt_length, unsigned char *target, int target_length)
{
	SHA_CTX sha;
	unsigned char sha1[20] = {0};

	/* Generate target sha-1 hash */
	SHA1_Init(&sha);
	SHA1_Update(&sha, pk, 32);

	if ( salt ) {
		SHA1_Update(&sha, salt, salt_length);
	}
	
	SHA1_Final(sha1, &sha);
	b64encode(sha1, 20, target, target_length);

	return 0;
}

KS_DECLARE(int) ks_dht_send_message_mutable(dht_handle_t *h, unsigned char *sk, unsigned char *pk, const struct sockaddr *sa, int salen,
											char *message_id, int sequence, char *message, ks_time_t life)
{
	unsigned char target[40], signature[crypto_sign_BYTES];
	unsigned long long signature_length = crypto_sign_BYTES;
	int message_length = strlen(message);
	unsigned char tid[4];
	unsigned char *salt = (unsigned char *)message_id;
	int salt_length = strlen(message_id);
	struct ks_dht_store_entry_s *entry = NULL;
	struct bencode *b_message = ben_blob(message, message_length);
	struct bencode *args = NULL, *data = NULL;
    char buf[1500];
	size_t buf_len = 0;
	int err = 0;
	h->now = ks_time_now_sec();

	if ( !life ) {
		/* Default to now plus 10 minutes */
		life = 600;
	}

	make_tid(tid, "mm", 0);
	
	ks_dht_calculate_mutable_storage_target(pk, salt, salt_length, target, 40);

	/*
int ks_dht_generate_mutable_storage_args(struct bencode *data, int64_t sequence, int cas,
										 unsigned char *id, int id_len, 
										 const unsigned char *sk, const unsigned char *pk,
										 unsigned char *salt, unsigned long long salt_length,
										 unsigned char *token, unsigned long long token_length,
										 unsigned char *signature, unsigned long long *signature_length,
										 struct bencode **arguments) */

	
	err = ks_dht_generate_mutable_storage_args(b_message, 1, 0,
											   h->myid, 20,
											   sk, pk,
											   salt, salt_length,
											   (unsigned char *) target, 40,
											   signature, &signature_length,
											   &args);
										 
	if ( err ) {
		return err;
	}

	data = ben_dict();
	ben_dict_set(data, ben_blob("a", 1), args);
	ben_dict_set(data, ben_blob("t", 1), ben_blob(tid, 4));
	ben_dict_set(data, ben_blob("y", 1), ben_blob("q", 1));
	ben_dict_set(data, ben_blob("q", 1), ben_blob("put", 3));

	buf_len = ben_encode2(buf, 1500, data);
	
	//	ks_dht_store_entry_create(h->pool, data, &entry, life, 1);
	// ks_dht_store_insert(h->store, entry, h->now);
	/* TODO: dht_search() announce of this hash */
	(void)entry;
	return dht_send(h, buf, buf_len, 0, sa, salen);
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
