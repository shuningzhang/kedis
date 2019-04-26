#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <net/sock.h>
//#include <linux/rwlock.h>

#include "server.h"

struct kedis_server server;
struct workqueue_struct *kedis_wq;

static void kedis_listen_data_ready(struct sock *sk);
static void kedis_data_ready(struct sock *sk);
static void kedis_state_change(struct sock *sk);

static int kedis_advance_rx(struct kedis_client *kc)
{
	int ret = 0;
	void *data;
	size_t datalen;

	data = page_address(kc->kc_page);
	datalen = 5;
	kernel_recvmsg(kc->new_sock, );
}

static void kedis_rx_all_data(struct work_struct *work)
{
	struct kedis_client *kc = 
		container_of(work, struct kedis_client, kc_rx_work);
	int ret;

	do {
	
	} while (ret > 0);

	if (ret <= 0 && ret != -EAGAIN) {
		printk(KERN_ERR "Closing %d\n", ret);
	}

	kc_put(kc);
}

static void kc_kref_release(struct kref *kref)
{
	struct kedis_client *kc = container_of(kref,
				struct kedis_client, kc_kref);

	printk(KERN_NOTICE "kc_release\n");

	if (kc->new_sock) {
		sock_release(kc->new_sock);
		kc->new_sock = NULL;
	}

	list_del_init(kc->client);
	kfree(kc);
}

static void kc_get(struct kedis_client *kc)
{
	printk(KERN_NOTICE "kc_get");
	kref_get(&kc->kc_kref);
}

static void kc_put(struct kedis_client *kc)
{
	printk(KERN_NOTICE "kc_put");
	kref_put(&kc->kc_kref, kc_kref_release);
}

static void kedis_kc_queue_work(struct kedis_client *kc,
				struct work_struct *work)
{
	kc_get(kc);
	if (!queue_work(kedis_wq, work))
		kc_put;
}
static void kedis_register_callbacks(struct sock *sk, 
				     struct kedis_client *kc)
{
	write_lock_bh(&sk->sk_callback_lock);
	
	if (sk->sk_data_ready == kedis_listen_data_ready) {
		sk->sk_data_ready = sk->sk_user_data;
		sk->sk_user_data = NULL;
	}

	BUG_ON(sk->sk_user_data != NULL);
	sk->sk_user_data = kc;

	kc->kc_data_ready = sk->sk_data_ready;
	kc->kc_state_change = sk->sk_state_change;
	sk->sk_data_ready = kedis_data_ready;
	sk->sk_state_change = kedis_state_change;

	write_unlock_bh(&sk->sk_callback_lock);
}

/* When a client is connecting to this server, 
 * we create a client structure for it. */
static struct kedis_client *kedis_create_client(void)
{
	struct kedis_client *client = NULL;
	struct kedis_client *ret = NULL;
	struct page *page = NULL;

	page = alloc_page(GFP_NOFS);
	client = kmalloc(sizeof(*client), GFP_KERNEL);
	if (client == NULL || page == NULL) {
		printk(KERN_ERR "kedis: Error no memoery");
		goto out;
	}

	INIT_WORK(&client->kc_rx_work, kedis_rx_all_data);
	kref_init(&client->kc_kref);

	client->kc_page = page;
	ret = client;
	page = NULL;
	client = NULL;

out:
	if (page)
		__free_page(page);
	kfree(client);

	return ret;
}

static void kedis_state_change(struct sock *sk)
{
	void (*state_change)(struct sock *sk);
	struct kedis_client *kc;

	read_lock(&sk->sk_callback_lock);
	kc = sk->sk_user_data;
	if (kc == NULL) {
		state_change = sk->sk_state_change;
		goto out;
	}

	printk(KERN_ERR "state_change to %d\n", sk->sk_state);

	state_change = kc->kc_state_change;

	switch (sk->sk_state) {
		case TCP_SYN_SENT:
		case TCP_SYN_RECV:
			break;
		case TCP_ESTABLISHED:
			break;
		default:
			printk(KERN_NOTICE "S state_change %d\n",
					sk->sk_state);
			break;
	}

out:
	read_unlock(&sk->sk_callback_lock);
	state_change(sk);
}

static void kedis_data_ready(struct sock *sk)
{
	void (*ready)(struct sock *sk);

	read_lock(&sk->sk_callback_lock);
	if (sk->sk_user_data) {

		ready = ;
	} else {
	}
	read_unlock(&sk->sk_callback_lock);

	ready(sk);
}


static int kedis_accept_one(struct socket *sock, int *more)
{
	int ret = 0;
	struct socket *new_sock = NULL;
	struct kedis_client *client = NULL;

	*more = 0;
	ret = sock_create_lite(sock->sk->sk_family, sock->sk->sk_type,
			       sock->sk->sk_protocol, &new_sock);

	if (ret < 0) {
		printk(KERN_ERR "kedis: Error %d while creating socket\n",
				ret);
		goto out;
	}

	new_sock->type = sock->type;
	new_sock->ops = sock->ops;

	printk(KERN_NOTICE "Before accept the client socket\n");
	ret = sock->ops->accept(sock, new_sock, O_NONBLOCK);
	if (ret < 0) {
		goto out;
	}

	printk(KERN_NOTICE "After accept the client socket\n");
	*more = 1;

	new_sock->sk->sk_allocation = GFP_ATOMIC;

	client = kedis_create_client();
	if (client == NULL) {
		printk(KERN_ERR "kedis: create client error\n");
		goto out;
	}

	client->new_sock = new_sock;
	new_sock = NULL;

	kedis_register_callbacks(client->new_sock->sk, client);
	list_add_tail(&client->client, &server.clients);
	printk(KERN_NOTICE "Create new client!\n");
	kedis_kc_queue_work(client, &client->kc_rx_work);

out:
	if (new_sock)
		sock_release(new_sock);
	return ret;
}

static void kedis_accept_many(struct work_struct *work)
{
	struct socket *sock = server.server_sock;
	int err;
	int more;

	for(;;) {
		err = kedis_accept_one(sock, &more);
		if (!more)
			break;
		cond_resched();
	
	}
}


static void kedis_listen_data_ready(struct sock *sk)
{
	void (*ready)(struct sock *sk);

	read_lock(&sk->sk_callback_lock);
	ready = sk->sk_user_data;
	if (ready == NULL) {
		ready = sk->sk_data_ready;
		goto out;
	}

	if (sk->sk_state == TCP_LISTEN) {
		INIT_WORK(&server.accept_work, kedis_accept_many);
		schedule_work(&server.accept_work);

	} else {
		ready = NULL;
	}

out:
	read_unlock(&sk->sk_callback_lock);
	if (ready != NULL)
		ready(sk);
}

static int kedis_open_listening_sock(__be32 addr, __be16 port)
{
	int ret = 0;
	struct socket *sock = NULL;
	struct sockaddr_in sin = {
		.sin_family = PF_INET,
		.sin_addr = { .s_addr = addr},
		.sin_port = port,
	};

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (ret < 0) {
		printk(KERN_ERR "kedis: Error %d while creating socket\n", ret);
		goto out;
	}

	sock->sk->sk_allocation = GFP_ATOMIC;

	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_user_data = sock->sk->sk_data_ready;
	sock->sk->sk_data_ready = kedis_listen_data_ready;
	write_unlock_bh(&sock->sk->sk_callback_lock);

	server.server_sock = sock;

	sock->sk->sk_reuse = SK_CAN_REUSE;
	ret = sock->ops->bind(sock, (struct sockaddr *)&sin, sizeof(sin));
	if (ret < 0) {
		printk(KERN_ERR "kedis: Error %d while binding socket at "
				"%pI4:%u\n", ret, &addr, ntohs(port));
		goto out;
	}

	ret = sock->ops->listen(sock, 64);
	if (ret < 0) {
		printk(KERN_ERR "kedis: Error %d while listening on %pI4:%u\n",
				ret, &addr, ntohs(port));
		goto out;
	}

out:
	if (ret) {
		server.server_sock = NULL;
		if (sock)
			sock_release(sock);
	}
	return ret;
}

static int kedis_start_listening(void)
{
	int ret = 0;
	
	kedis_wq = create_singlethread_workqueue("kedis");
	if (kedis_wq == NULL) {
		printk(KERN_ERR "Error create workqueue error!\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = kedis_open_listening_sock(htonl(INADDR_ANY),
					htons(8000));
	if (ret) {
		destroy_workqueue(kedis_wq);
		kedis_wq = NULL;
	}

out:
	return ret;

}

void kedis_stop_listening(void)
{
	struct socket *sock = server.server_sock;

	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_data_ready = sock->sk->sk_user_data;
	sock->sk->sk_user_data = NULL;
	write_unlock_bh(&sock->sk->sk_callback_lock);

	destroy_workqueue(kedis_wq);

	sock_release(server.server_sock);
}

static int kedis_init(void)
{
	kedis_start_listening();
	
	return 0;
}

static void kedis_exit(void)
{
	kedis_stop_listening();
	printk("Bye!\n");

}

module_init(kedis_init);
module_exit(kedis_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SunnyZhang<shuningzhang@126.com>");

