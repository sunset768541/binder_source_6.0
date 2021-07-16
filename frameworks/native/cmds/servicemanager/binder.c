/* Copyright 2008 The Android Open Source Project
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "binder.h"

#define MAX_BIO_SIZE (1 << 30)

#define TRACE 0

#define LOG_TAG "Binder"
#include <cutils/log.h>


void bio_init_from_txn(struct binder_io *io, struct binder_transaction_data *txn);

#if TRACE
void hexdump(void *_data, size_t len)
{
    unsigned char *data = _data;
    size_t count;

    for (count = 0; count < len; count++) {
        if ((count & 15) == 0)
            fprintf(stderr,"%04zu:", count);
        fprintf(stderr," %02x %c", *data,
                (*data < 32) || (*data > 126) ? '.' : *data);
        data++;
        if ((count & 15) == 15)
            fprintf(stderr,"\n");
    }
    if ((count & 15) != 0)
        fprintf(stderr,"\n");
}

void binder_dump_txn(struct binder_transaction_data *txn)
{
    struct flat_binder_object *obj;
    binder_size_t *offs = (binder_size_t *)(uintptr_t)txn->data.ptr.offsets;
    size_t count = txn->offsets_size / sizeof(binder_size_t);

    fprintf(stderr,"  target %016"PRIx64"  cookie %016"PRIx64"  code %08x  flags %08x\n",
            (uint64_t)txn->target.ptr, (uint64_t)txn->cookie, txn->code, txn->flags);
    fprintf(stderr,"  pid %8d  uid %8d  data %"PRIu64"  offs %"PRIu64"\n",
            txn->sender_pid, txn->sender_euid, (uint64_t)txn->data_size, (uint64_t)txn->offsets_size);
    hexdump((void *)(uintptr_t)txn->data.ptr.buffer, txn->data_size);
    while (count--) {
        obj = (struct flat_binder_object *) (((char*)(uintptr_t)txn->data.ptr.buffer) + *offs++);
        fprintf(stderr,"  - type %08x  flags %08x  ptr %016"PRIx64"  cookie %016"PRIx64"\n",
                obj->type, obj->flags, (uint64_t)obj->binder, (uint64_t)obj->cookie);
    }
}

#define NAME(n) case n: return #n
const char *cmd_name(uint32_t cmd)
{
    switch(cmd) {
        NAME(BR_NOOP);
        NAME(BR_TRANSACTION_COMPLETE);
        NAME(BR_INCREFS);
        NAME(BR_ACQUIRE);
        NAME(BR_RELEASE);
        NAME(BR_DECREFS);
        NAME(BR_TRANSACTION);
        NAME(BR_REPLY);
        NAME(BR_FAILED_REPLY);
        NAME(BR_DEAD_REPLY);
        NAME(BR_DEAD_BINDER);
    default: return "???";
    }
}
#else
#define hexdump(a,b) do{} while (0)
#define binder_dump_txn(txn)  do{} while (0)
#endif

#define BIO_F_SHARED    0x01  /* needs to be buffer freed */
#define BIO_F_OVERFLOW  0x02  /* ran out of space */
#define BIO_F_IOERROR   0x04
#define BIO_F_MALLOCED  0x08  /* needs to be free()'d */

struct binder_state
{
    int fd;
    void *mapped;
    size_t mapsize;
};


//在servicemanager中打开binder驱动并进行mmap 只有在这一个地方，需要看哪些地方调用了这个方法，传入的mapsize是多大
struct binder_state *binder_open(size_t mapsize)
{
    struct binder_state *bs;
    struct binder_version vers;

    bs = malloc(sizeof(*bs));
    if (!bs) {
        errno = ENOMEM;
        return NULL;
    }

    bs->fd = open("/dev/binder", O_RDWR);//打开binder mmap
    if (bs->fd < 0) {
        fprintf(stderr,"binder: cannot open device (%s)\n",
                strerror(errno));
        goto fail_open;
    }

    if ((ioctl(bs->fd, BINDER_VERSION, &vers) == -1) ||
        (vers.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION)) {
        fprintf(stderr,
                "binder: kernel driver version (%d) differs from user space version (%d)\n",
                vers.protocol_version, BINDER_CURRENT_PROTOCOL_VERSION);
        goto fail_open;
    }

    bs->mapsize = mapsize;//128*1024
    //PROT_READ //页内容可以被读取
    //MAP_PRIVATE //建立一个写入时拷贝的私有映射。内存区域的写入不会影响到原文件。这个标志和以上标志是互斥的，只能使用其中一个。
    //fd：有效的文件描述词。一般是由open()函数返回，其值也可以设置为-1，此时需要指定flags参数中的MAP_ANON,表明进行的是匿名映射。
    //成功执行时，mmap()返回被映射区的指针，munmap()返回0。失败时，mmap()返回MAP_FAILED[其值为(void *)-1]，munmap返回-1。errno被设为以下的某个值
    //
    bs->mapped = mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0);
    if (bs->mapped == MAP_FAILED) {
        fprintf(stderr,"binder: cannot map device (%s)\n",
                strerror(errno));
        goto fail_map;
    }

    return bs;

fail_map:
    close(bs->fd);
fail_open:
    free(bs);
    return NULL;
}

void binder_close(struct binder_state *bs)
{
    munmap(bs->mapped, bs->mapsize);
    close(bs->fd);
    free(bs);
}

//和DNS类似，SMgr的作用是将字符形式的Binder名字转化成Client中对该Binder的引用，使得Client能够通过Binder名字获得对Server中Binder实体的引用。
//注册了名字的Binder叫实名Binder，就象每个网站除了有IP地址外还有自己的网址。Server创建了Binder实体，为其取一个字符形式，可读易记的名字，
//将这个Binder连同名字以数据包的形式通过Binder驱动发送给SMgr，通知SMgr注册一个名叫张三的Binder，它位于某个Server中。
//驱动为这个穿过进程边界的Binder创建位于内核中的实体节点以及SMgr对实体的引用，将名字及新建的引用打包传递给SMgr。SMgr收数据包后，从中取出名字和引用填入一张查找表中。
//细心的读者可能会发现其中的蹊跷：SMgr是一个进程，Server是另一个进程，Server向SMgr注册Binder必然会涉及进程间通信。当前实现的是进程间通信却又要用到进程间通信，
//这就好象蛋可以孵出鸡前提却是要找只鸡来孵蛋。Binder的实现比较巧妙：预先创造一只鸡来孵蛋：SMgr和其它进程同样采用Binder通信，SMgr是Server端，有自己的Binder对象（实体），其它进程都是Client，
//需要通过这个Binder的引用来实现Binder的注册，查询和获取。SMgr提供的Binder比较特殊，它没有名字也不需要注册，
//当一个进程使用BINDER_SET_CONTEXT_MGR命令将自己注册成SMgr时Binder驱动会自动为它创建Binder实体（这就是那只预先造好的鸡）。
//其次这个Binder的引用在所有Client中都固定为0而无须通过其它手段获得。
//也就是说，一个Server若要向SMgr注册自己Binder就必需通过0这个引用号和SMgr的Binder通信。
//类比网络通信，0号引用就好比域名服务器的地址，你必须预先手工或动态配置好。要注意这里说的Client是相对SMgr而言的，一个应用程序可能是个提供服务的Server，但对SMgr来说它仍然是个Client。

int binder_become_context_manager(struct binder_state *bs)
{
    return ioctl(bs->fd, BINDER_SET_CONTEXT_MGR, 0);//将ServerManager注册为第一个Binder Server服务端，用于管理其他Binder Server
}

int binder_write(struct binder_state *bs, void *data, size_t len)
{
    struct binder_write_read bwr;
    int res;

    bwr.write_size = len;
    bwr.write_consumed = 0;
    bwr.write_buffer = (uintptr_t) data;
    bwr.read_size = 0;
    bwr.read_consumed = 0;
    bwr.read_buffer = 0;
    res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
    if (res < 0) {
        fprintf(stderr,"binder_write: ioctl failed (%s)\n",
                strerror(errno));
    }
    return res;
}

void binder_send_reply(struct binder_state *bs,
                       struct binder_io *reply,
                       binder_uintptr_t buffer_to_free,
                       int status)
{
    struct {
        uint32_t cmd_free;
        binder_uintptr_t buffer;
        uint32_t cmd_reply;
        struct binder_transaction_data txn;
    } __attribute__((packed)) data;

    data.cmd_free = BC_FREE_BUFFER;
    data.buffer = buffer_to_free;
    data.cmd_reply = BC_REPLY;
    data.txn.target.ptr = 0;
    data.txn.cookie = 0;
    data.txn.code = 0;
    if (status) {
        data.txn.flags = TF_STATUS_CODE;
        data.txn.data_size = sizeof(int);
        data.txn.offsets_size = 0;
        data.txn.data.ptr.buffer = (uintptr_t)&status;
        data.txn.data.ptr.offsets = 0;
    } else {
        data.txn.flags = 0;
        data.txn.data_size = reply->data - reply->data0;//replay->data存储了数据指针 得到数据大小
        data.txn.offsets_size = ((char*) reply->offs) - ((char*) reply->offs0);//
        data.txn.data.ptr.buffer = (uintptr_t)reply->data0;//查看replay->data0是什么  data=data0+data_size  data0就是数据的开始指针
        data.txn.data.ptr.offsets = (uintptr_t)reply->offs0;
    }
    binder_write(bs, &data, sizeof(data));
}
//ptr为读取的数据readbuf指针,func为svcmgr_handler
int binder_parse(struct binder_state *bs, struct binder_io *bio,
                 uintptr_t ptr, size_t size, binder_handler func)
{
    int r = 1;
    uintptr_t end = ptr + (uintptr_t) size;

    while (ptr < end) {
        uint32_t cmd = *(uint32_t *) ptr;
        ptr += sizeof(uint32_t);
#if TRACE
        fprintf(stderr,"%s:\n", cmd_name(cmd));
#endif
        switch(cmd) {
        case BR_NOOP:
            break;
        case BR_TRANSACTION_COMPLETE:
            break;
        case BR_INCREFS:
        case BR_ACQUIRE:
        case BR_RELEASE:
        case BR_DECREFS:
#if TRACE
            fprintf(stderr,"  %p, %p\n", (void *)ptr, (void *)(ptr + sizeof(void *)));
#endif
            ptr += sizeof(struct binder_ptr_cookie);
            break;
        case BR_TRANSACTION: {
            struct binder_transaction_data *txn = (struct binder_transaction_data *) ptr;
            if ((end - ptr) < sizeof(*txn)) {
                ALOGE("parse: txn too small!\n");
                return -1;
            }
            binder_dump_txn(txn);
            if (func) {
                unsigned rdata[256/4];
                struct binder_io msg;
                struct binder_io reply;
                int res;

                bio_init(&reply, rdata, sizeof(rdata), 4);
                //msg.data =  txn->data.ptr.buffer
                bio_init_from_txn(&msg, txn);//初始化bio
                res = func(bs, txn, &msg, &reply);
                //reply->data存储handle
                binder_send_reply(bs, &reply, txn->data.ptr.buffer, res);//发送reply数据
            }
            ptr += sizeof(*txn);
            break;
        }
        case BR_REPLY: {
            struct binder_transaction_data *txn = (struct binder_transaction_data *) ptr;
            if ((end - ptr) < sizeof(*txn)) {
                ALOGE("parse: reply too small!\n");
                return -1;
            }
            binder_dump_txn(txn);
            if (bio) {
                bio_init_from_txn(bio, txn);
                bio = 0;
            } else {
                /* todo FREE BUFFER */
            }
            ptr += sizeof(*txn);
            r = 0;
            break;
        }
        case BR_DEAD_BINDER: {
            struct binder_death *death = (struct binder_death *)(uintptr_t) *(binder_uintptr_t *)ptr;
            ptr += sizeof(binder_uintptr_t);
            death->func(bs, death->ptr);
            break;
        }
        case BR_FAILED_REPLY:
            r = -1;
            break;
        case BR_DEAD_REPLY:
            r = -1;
            break;
        default:
            ALOGE("parse: OOPS %d\n", cmd);
            return -1;
        }
    }

    return r;
}

void binder_acquire(struct binder_state *bs, uint32_t target)
{
    uint32_t cmd[2];
    cmd[0] = BC_ACQUIRE;
    cmd[1] = target;
    binder_write(bs, cmd, sizeof(cmd));
}

void binder_release(struct binder_state *bs, uint32_t target)
{
    uint32_t cmd[2];
    cmd[0] = BC_RELEASE;
    cmd[1] = target;
    binder_write(bs, cmd, sizeof(cmd));
}

void binder_link_to_death(struct binder_state *bs, uint32_t target, struct binder_death *death)
{
    struct {
        uint32_t cmd;
        struct binder_handle_cookie payload;
    } __attribute__((packed)) data;

    data.cmd = BC_REQUEST_DEATH_NOTIFICATION;
    data.payload.handle = target;
    data.payload.cookie = (uintptr_t) death;
    binder_write(bs, &data, sizeof(data));
}

int binder_call(struct binder_state *bs,
                struct binder_io *msg, struct binder_io *reply,
                uint32_t target, uint32_t code)
{
    int res;
    struct binder_write_read bwr;
    struct {
        uint32_t cmd;
        struct binder_transaction_data txn;
    } __attribute__((packed)) writebuf;
    unsigned readbuf[32];

    if (msg->flags & BIO_F_OVERFLOW) {
        fprintf(stderr,"binder: txn buffer overflow\n");
        goto fail;
    }

    writebuf.cmd = BC_TRANSACTION;
    writebuf.txn.target.handle = target;
    writebuf.txn.code = code;
    writebuf.txn.flags = 0;
    writebuf.txn.data_size = msg->data - msg->data0;
    writebuf.txn.offsets_size = ((char*) msg->offs) - ((char*) msg->offs0);
    writebuf.txn.data.ptr.buffer = (uintptr_t)msg->data0;
    writebuf.txn.data.ptr.offsets = (uintptr_t)msg->offs0;

    bwr.write_size = sizeof(writebuf);
    bwr.write_consumed = 0;
    bwr.write_buffer = (uintptr_t) &writebuf;

    hexdump(msg->data0, msg->data - msg->data0);
    for (;;) {
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
        bwr.read_buffer = (uintptr_t) readbuf;

        res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);

        if (res < 0) {
            fprintf(stderr,"binder: ioctl failed (%s)\n", strerror(errno));
            goto fail;
        }

        res = binder_parse(bs, reply, (uintptr_t) readbuf, bwr.read_consumed, 0);
        if (res == 0) return 0;
        if (res < 0) goto fail;
    }

fail:
    memset(reply, 0, sizeof(*reply));
    reply->flags |= BIO_F_IOERROR;
    return -1;
}

void binder_loop(struct binder_state *bs, binder_handler func)
{
    int res;
    struct binder_write_read bwr;
    uint32_t readbuf[32];

    bwr.write_size = 0;
    bwr.write_consumed = 0;
    bwr.write_buffer = 0;

    readbuf[0] = BC_ENTER_LOOPER;
    binder_write(bs, readbuf, sizeof(uint32_t));

    for (;;) {
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
        bwr.read_buffer = (uintptr_t) readbuf;

        res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);//读取数据到bwr指针

        if (res < 0) {
            ALOGE("binder_loop: ioctl failed (%s)\n", strerror(errno));
            break;
        }

        //readbuf就是读取到的数据
        res = binder_parse(bs, 0, (uintptr_t) readbuf, bwr.read_consumed, func);
        if (res == 0) {
            ALOGE("binder_loop: unexpected reply?!\n");
            break;
        }
        if (res < 0) {
            ALOGE("binder_loop: io error %d %s\n", res, strerror(errno));
            break;
        }
    }
}

void bio_init_from_txn(struct binder_io *bio, struct binder_transaction_data *txn)
{
    bio->data = bio->data0 = (char *)(intptr_t)txn->data.ptr.buffer;
    bio->offs = bio->offs0 = (binder_size_t *)(intptr_t)txn->data.ptr.offsets;
    bio->data_avail = txn->data_size;
    bio->offs_avail = txn->offsets_size / sizeof(size_t);
    bio->flags = BIO_F_SHARED;
}

void bio_init(struct binder_io *bio, void *data,
              size_t maxdata, size_t maxoffs)
{
    size_t n = maxoffs * sizeof(size_t);

    if (n > maxdata) {
        bio->flags = BIO_F_OVERFLOW;
        bio->data_avail = 0;
        bio->offs_avail = 0;
        return;
    }

    bio->data = bio->data0 = (char *) data + n;
    bio->offs = bio->offs0 = data;
    bio->data_avail = maxdata - n;
    bio->offs_avail = maxoffs;
    bio->flags = 0;
}

static void *bio_alloc(struct binder_io *bio, size_t size)
{
    size = (size + 3) & (~3);
    if (size > bio->data_avail) {
        bio->flags |= BIO_F_OVERFLOW;
        return NULL;
    } else {
        void *ptr = bio->data;
        bio->data += size;
        bio->data_avail -= size;
        return ptr;
    }
}

void binder_done(struct binder_state *bs,
                 struct binder_io *msg,
                 struct binder_io *reply)
{
    struct {
        uint32_t cmd;
        uintptr_t buffer;
    } __attribute__((packed)) data;

    if (reply->flags & BIO_F_SHARED) {
        data.cmd = BC_FREE_BUFFER;
        data.buffer = (uintptr_t) reply->data0;
        binder_write(bs, &data, sizeof(data));
        reply->flags = 0;
    }
}

static struct flat_binder_object *bio_alloc_obj(struct binder_io *bio)
{
    struct flat_binder_object *obj;

    obj = bio_alloc(bio, sizeof(*obj));

    if (obj && bio->offs_avail) {
        bio->offs_avail--;
        *bio->offs++ = ((char*) obj) - ((char*) bio->data0);
        return obj;
    }

    bio->flags |= BIO_F_OVERFLOW;
    return NULL;
}

void bio_put_uint32(struct binder_io *bio, uint32_t n)
{
    uint32_t *ptr = bio_alloc(bio, sizeof(n));
    if (ptr)
        *ptr = n;
}

void bio_put_obj(struct binder_io *bio, void *ptr)
{
    struct flat_binder_object *obj;

    obj = bio_alloc_obj(bio);
    if (!obj)
        return;

    obj->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    obj->type = BINDER_TYPE_BINDER;
    obj->binder = (uintptr_t)ptr;
    obj->cookie = 0;
}

void bio_put_ref(struct binder_io *bio, uint32_t handle)
{
    struct flat_binder_object *obj;

    if (handle)
        obj = bio_alloc_obj(bio);
    else
        obj = bio_alloc(bio, sizeof(*obj));

    if (!obj)
        return;

    obj->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;//bio给bio中的obj赋值
    obj->type = BINDER_TYPE_HANDLE;//bio->data replay->data
    obj->handle = handle;
    obj->cookie = 0;
}

void bio_put_string16(struct binder_io *bio, const uint16_t *str)
{
    size_t len;
    uint16_t *ptr;

    if (!str) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    len = 0;
    while (str[len]) len++;

    if (len >= (MAX_BIO_SIZE / sizeof(uint16_t))) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    /* Note: The payload will carry 32bit size instead of size_t */
    bio_put_uint32(bio, (uint32_t) len);
    len = (len + 1) * sizeof(uint16_t);
    ptr = bio_alloc(bio, len);
    if (ptr)
        memcpy(ptr, str, len);
}

void bio_put_string16_x(struct binder_io *bio, const char *_str)
{
    unsigned char *str = (unsigned char*) _str;
    size_t len;
    uint16_t *ptr;

    if (!str) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    len = strlen(_str);

    if (len >= (MAX_BIO_SIZE / sizeof(uint16_t))) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    /* Note: The payload will carry 32bit size instead of size_t */
    bio_put_uint32(bio, len);
    ptr = bio_alloc(bio, (len + 1) * sizeof(uint16_t));
    if (!ptr)
        return;

    while (*str)
        *ptr++ = *str++;
    *ptr++ = 0;
}

static void *bio_get(struct binder_io *bio, size_t size)
{
    size = (size + 3) & (~3);

    if (bio->data_avail < size){
        bio->data_avail = 0;
        bio->flags |= BIO_F_OVERFLOW;
        return NULL;
    }  else {
        void *ptr = bio->data;
        bio->data += size;
        bio->data_avail -= size;
        return ptr;
    }
}

uint32_t bio_get_uint32(struct binder_io *bio)
{
    uint32_t *ptr = bio_get(bio, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

uint16_t *bio_get_string16(struct binder_io *bio, size_t *sz)
{
    size_t len;

    /* Note: The payload will carry 32bit size instead of size_t */
    len = (size_t) bio_get_uint32(bio);//len为bio的负载
    if (sz)
        *sz = len;
    return bio_get(bio, (len + 1) * sizeof(uint16_t));//读取第一个字符串
}

static struct flat_binder_object *_bio_get_obj(struct binder_io *bio)
{
    size_t n;
    size_t off = bio->data - bio->data0;

    /* TODO: be smarter about this? */
    for (n = 0; n < bio->offs_avail; n++) {
        if (bio->offs[n] == off)
            return bio_get(bio, sizeof(struct flat_binder_object));
    }

    bio->data_avail = 0;
    bio->flags |= BIO_F_OVERFLOW;
    return NULL;
}
//obj->type的值是BINDER_TYPE_HANDLE。
//原来ActivityManagerService对应的type是BINDER_TYPE_BINDER，
//但在Binder驱动的binder_transaction()中，将type修改成了BINDER_TYPE_HANDLE。
//因此，返回obj->pointer，而obj->pointer实际上是flat_binder_object中的handle，
//而该handle在Binder驱动中被赋值为"ActivityManagerService对应的Binder引用的描述，
//即binder_ref->desc"。根据该引用描述，
//可以在Binder驱动中找到ActivityManagerService对应的Binder实体以及ActivityManagerService对应的进程上下文信息，进而可以给ActivityManagerService发送消息。

uint32_t bio_get_ref(struct binder_io *bio)
{
    struct flat_binder_object *obj;

    obj = _bio_get_obj(bio);
    if (!obj)
        return 0;

    if (obj->type == BINDER_TYPE_HANDLE)
        return obj->handle;

    return 0;
}
