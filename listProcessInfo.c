#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/sched.h>
#include<linux/syscalls.h>
#include<linux/fcntl.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/string.h>

/* Skcipher kernel crypto API */
#include <crypto/skcipher.h>
/* Scatterlist manipulation */
#include <linux/scatterlist.h>
/* Error macros */
#include <linux/err.h>
#include <linux/random.h>

#include <crypto/internal/hash.h>
#include <linux/crypto.h>

#include "processInfo.h"


static char key[16] = "abcdefghijklmnop"; 
static char iv[16] = "abcdefghijklmnop"; 


char encript[32];
static int  majorNumber;
static char   message[256] = {0};           ///< Memory for the string that is passed from userspace
static short  size_of_message;              ///< Used to remember the size of the string stored
static int    numberOpens = 0;              ///< Counts the number of times the device is opened
static struct class*  ebbcharClass  = NULL; ///< The device-driver class struct pointer
static struct device* ebbcharDevice = NULL; ///< The device-driver device struct pointer

///////INICIO DA ENCRIPTATION///////////////////////////////////////////////////////////////

struct tcrypt_result {
    struct completion completion;
    int err;
};

/* tie all data structures together */
struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
};

/* Callback function */
static void test_skcipher_cb(struct crypto_async_request *req, int error)
{
    struct tcrypt_result *result = req->data;

    if (error == -EINPROGRESS)
        return;
    result->err = error;
    complete(&result->completion);
    pr_info("Encryption finished successfully\n");
}

/* Perform cipher operation */
static unsigned int test_skcipher_encdec(struct skcipher_def *sk, int enc)
{
    int rc = 0;

    if (enc)
        rc = crypto_skcipher_encrypt(sk->req);
    else
        rc = crypto_skcipher_decrypt(sk->req);

    switch (rc) {
    case 0:
        break;
    case -EINPROGRESS:
    case -EBUSY:
        rc = wait_for_completion_interruptible(
            &sk->result.completion);
        if (!rc && !sk->result.err) {
            reinit_completion(&sk->result.completion);
            break;
        }
    default:
        pr_info("skcipher encrypt returned with %d result %d\n",
            rc, sk->result.err);
        break;
    }
    init_completion(&sk->result.completion);

    return rc;
}


/* Initialize and trigger cipher operation */
static int test_skcipher(int size, char *varEncript, char option)
{
    struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    char *scratchpad = NULL;
    char *ivdata = NULL;
    unsigned char keyC[17];
    int ret = -EFAULT;
  
    skcipher = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(skcipher)) {
        pr_info("could not allocate skcipher handle\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                      test_skcipher_cb,
                      &sk.result);

    /* passando a key para a variavel local da função */
	strcpy(keyC, key);
    if (crypto_skcipher_setkey(skcipher, keyC, 16)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }
    ivdata = vmalloc(16);
    if (!ivdata) {
        pr_info("could not allocate ivdata\n");
        goto out;
    }
    strcpy(ivdata, iv);
    

    /* Input data will be random */
    scratchpad = vmalloc(16);
    if (!scratchpad) {
        pr_info("could not allocate scratchpad\n");
        goto out;
    }
    strcpy(scratchpad, varEncript);

    sk.tfm = skcipher;
    sk.req = req;

    /* We encrypt one block */
    sg_init_one(&sk.sg, scratchpad, 16);
    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, ivdata);
    init_completion(&sk.result.completion);


	if(option == 'e'){
    ret = test_skcipher_encdec(&sk, 1);//1 encripta 0 desencripta
}
	if(option == 'd'){
    ret = test_skcipher_encdec(&sk, 0);//1 encripta 0 desencripta
}
    
    if (ret)
        goto out;
    char *resultdata = sg_virt(&sk.sg);

//print_hex_dump(KERN_DEBUG, "texto: ", DUMP_PREFIX_NONE, 16,1, resultdata, 16, true);
strcpy(encript, resultdata);
int w=0;
while(w<strlen(resultdata)){printk(KERN_INFO "Encriptedddd: %x", resultdata[w]); w++;}
    pr_info("Encryption triggered successfully\n");

out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (ivdata)
        vfree(ivdata);
    if (scratchpad)
        vfree(scratchpad);
    return ret;
}
//////FIM DA ENCRIPTATION////////////////////////////////////////////////////////////////////////////////////

//de decimal para hexa
void converter(char* vet){
int i=0, j=0;
unsigned char num;
while(i<16){
num=(unsigned char)encript[i]/16;
if(num>9) {num= num + 87;}
else{num=num +'0';}
vet[j] = num;
j++;
num=(unsigned char)encript[i]%16;
if(num>9){num =num+ 87;}
else{num= num + '0';}
vet[j]=num;
i++;
j++;
}

}

//de hexa para decimal
void hex_to_string( char vet[], char result[] )
{
    int pos=0,i=0,valor=0;
    while(pos<32)
    {

        if(vet[pos]>=97 && vet[pos]<=122)
        {
            valor+=(vet[pos]-87)*16;
        }

        else if(vet[pos]>=65 && vet[pos]<=90)
        {
            valor+=(vet[pos]-55)*16;
        }
        else
        {
            valor+=(vet[pos]-48)*16;
        }
        //-----------------------------------------------------------------------------------------------------------------------------
        if(vet[pos+1]>=97 && vet[pos+1]<=122)
        {
            valor+=(vet[pos+1]-87);
        }
        else if(vet[pos+1]>=65 && vet[pos+1]<=90)
        {
            valor+=(vet[pos+1]-55);
        }
        else
        {
            valor+=(vet[pos+1]-48);
        }
        result[i]=valor;
        valor=0;
        i=i+1;
        pos=pos+2;

    }
    result[i]='\0';

}

asmlinkage ssize_t write_cript(int fd, const void *buf, size_t nbytes) {
    char vet[32];
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

test_skcipher(16, buf, 'e');
converter(vet);
ret = sys_write(fd, vet, nbytes);
    set_fs(oldfs);

printk("VALOR: [ %s ]\n", vet);
  
  return 0;
}

asmlinkage ssize_t read_cript(int fd, const void *buf, size_t nbytes) {
unsigned char vet[32];
mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

ret = sys_read(fd, vet, nbytes);
test_skcipher(32, vet, 'd');

set_fs(oldfs);
strcpy(buf, encript);
  
printk("o meu encript: %s \n", encript);

  return 0;
}

