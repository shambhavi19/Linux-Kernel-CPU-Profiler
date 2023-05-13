#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/stacktrace.h>
#include <linux/kallsyms.h>
#include <linux/jhash.h>
#include <linux/uaccess.h>


#define MAX_TRACE 16

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SHAMBHAVI KUTHE");
MODULE_DESCRIPTION("LKP PROJECT-3");

static unsigned int (*user_trace)(unsigned long*, unsigned int);
static unsigned long long hi;
static unsigned long long lo;
DEFINE_SPINLOCK(lock);

static char func_name[KSYM_NAME_LEN] = "pick_next_task_fair";

struct rb_entry {
	struct rb_node node;
	unsigned long jkey;
	unsigned long long time;
	unsigned int stacktrace_length;
	unsigned long stacktrace[MAX_TRACE];
};
static struct rb_root myrbtree = RB_ROOT;

struct my_data{
	unsigned long long data;
};


bool checkLess(struct rb_node* root, const struct rb_node* parent)
{
	if((rb_entry(root, struct rb_entry,node))->time > (rb_entry(parent, struct rb_entry,node))->time)
	{
		return false;
	}
	else
	{
		return true;
	}
}

static unsigned long long checkDuplicate(unsigned long key)
{
	struct rb_node *node;
	struct rb_entry *temp;
	unsigned long long val;
	for(node = rb_first(&myrbtree); node; node = rb_next(node))
	{
		if(key == (rb_entry(node, struct rb_entry, node))->jkey)
		{
			val = rb_entry(node, struct rb_entry, node)->time;
			temp = rb_entry(node, struct rb_entry, node);
			rb_erase(node, &myrbtree);
			kfree(temp);
			return val;
		}
	}
	return 0;
}

static int store_rbtree(unsigned long key, unsigned long long time, unsigned long trace[], unsigned int length)
{
	struct rb_entry *rb;
	unsigned long long val = checkDuplicate(key);
	val = val + time;
	rb = (struct rb_entry*)kmalloc(sizeof(*rb),GFP_KERNEL);
	if(!rb)
	{
		return -ENOMEM;
	}
	else
	{
		rb->time = val;
		rb->jkey = key;
		rb->stacktrace_length = length;
		for(int i=0; i<length; i++)
		{
			rb->stacktrace[i] = trace[i];
		}
		rb_add(&(rb->node), &myrbtree, checkLess);
		return 0;
	}
}

static void destroy_rbtree_and_free(void)
{
	struct rb_node *node;
	struct rb_entry *temp;
	for(node = rb_first(&myrbtree); node; node = rb_next(node))
	{
		temp = rb_entry(node, struct rb_entry, node);
		rb_erase(node, &myrbtree);
		kfree(temp);
	}
}

static int perftop_show(struct seq_file *m,void *v)
{
	struct rb_node *node;
	int rank = 1;
	for(node = rb_last(&myrbtree); node; node = rb_prev(node))
	{
		if(rank <=20)
		{
			seq_printf(m, "Rank: %d\n",rank);
			seq_printf(m, "Stack trace jhash key[%lu]    Time: %llu ticks\n", rb_entry(node, struct rb_entry, node)->jkey, rb_entry(node, struct rb_entry, node)->time);
			seq_printf(m, "Stack trace:\n");
			for(int i =0; i<4; i++)
			{
				seq_printf(m, "%p\n",(void *)rb_entry(node, struct rb_entry, node)->stacktrace[i]);
			}
			rank++;
		}
	}

	return 0;
}


static int perftop_open(struct inode *inode, struct file *file)
{
	return single_open(file,perftop_show,NULL);
}

static const struct proc_ops perftop_fops = {
	.proc_open = perftop_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static struct kprobe kp_kall = {
	.symbol_name = "kallsyms_lookup_name",
};

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct my_data *start;
	start = (struct my_data*)ri->data;
	start->data = rdtsc();
	lo = start->data;
	return 0;

}
NOKPROBE_SYMBOL(entry_handler);

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int err;
	u32 rb_key;
	static unsigned long long time;
	unsigned int stack_op;
	struct task_struct *task = current;
//	struct task_struct *task = (struct task_struct*)regs->si;
	static unsigned long stacktrace_store[MAX_TRACE];
	static unsigned long *stack_ptr = stacktrace_store;

	struct my_data *end = (struct my_data *)ri->data;
	end->data = rdtsc();
	hi = end->data;
	time = hi - lo;
		
	spin_lock(&lock);

	if(task->mm == NULL)
	{
		stack_op = stack_trace_save(stacktrace_store, MAX_TRACE, 2);
	}
	else
	{
		stack_op = user_trace(stacktrace_store, MAX_TRACE);
	}

	rb_key = jhash2((u32*)stack_ptr, stack_op, 0);
	err = store_rbtree(rb_key, time, stacktrace_store, stack_op);
	spin_unlock(&lock);
	if(err)
	{
		pr_info("Error storing rbtree\n");
		return 1;
	}

	return 0;
}
NOKPROBE_SYMBOL(ret_handler);

static struct kretprobe kretp = {
	.handler = ret_handler,
	.entry_handler = entry_handler,
	.data_size = sizeof(unsigned long long), 
	.maxactive = 20,
};



static int __init perftop_init(void)
{	
	int k_ret;
	int ret;
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	k_ret = register_kprobe(&kp_kall);
	kallsyms_lookup_name = (kallsyms_lookup_name_t)kp_kall.addr;
	unregister_kprobe(&kp_kall);
//	pr_info("Address : %lx\n", kallsyms_lookup_name);
	
	user_trace = kallsyms_lookup_name("stack_trace_save_user");
	
	kretp.kp.symbol_name = func_name;
	ret = register_kretprobe(&kretp);
	if (ret < 0) 
	{
		pr_err("register_kretprobe failed, returned %d\n", ret);
		return ret;
	}
	

	proc_create("perftop",0,NULL,&perftop_fops);
	pr_info("Planted kprobe at %p\n",kretp.kp.addr);

	return 0;

}

static void __exit perftop_exit(void)
{
	unregister_kretprobe(&kretp);
	pr_info("kprobe at %p unregistered\n", kretp.kp.addr);
	destroy_rbtree_and_free();
	remove_proc_entry("perftop",NULL);
	return;
}

module_init(perftop_init);
module_exit(perftop_exit);

