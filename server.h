


#ifndef KEDIS_SERVER_H
#define KEDIS_SERVER_H

struct dict_type {
	int (*hash_function)(const void *key);
};


struct kedis_db {
	struct dict *dict;

	int id;
};

struct kedis_server {
	int index;
	struct socket *server_sock;

	struct work_struct accept_work;

	struct list_head clients;
	struct list_head clients_to_close;
};


/* this is for client, which connected to 
 * the kedis server. */
struct kedis_client {
	int			id;
	struct kref		kc_kref;
	struct socket		*new_sock;
	struct kedis_db		*db;

	struct list_head	client; //link itsel
	struct work_struct	kc_rx_work;


	/* original handlers for the sockets */
	void			(*kc_state_change)(struct sock *sk);
	void			(*kc_data_ready)(struct sock *sk);

	struct page		*kc_page;
	size_t			kc_page_off;
};



#endif /* KEDIS_SERVER_H */
