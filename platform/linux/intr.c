#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"

#include "util.h"
#include "net.h"

// 割り込み要求構造体
struct irq_entry {
    // 次の割り込み要求へのポインタ
    struct irq_entry *next;
    // 割り込み番号
    unsigned int irq;
    // 割り込みハンドラの関数ポインタ
    int (*handler)(unsigned int irq, void *dev);
    // フラグ
    int flags;
    // デバッグ出力で識別するための名前
    char name[16];
    // 割り込みの発生元となるデバイス（net_device等）
    void *dev;
};

/* NOTE: if you want to add/delete the entries after intr_run(), you need to protect these lists with a mutex. */
static struct irq_entry *irqs;

static sigset_t sigmask;

static pthread_t tid;
static pthread_barrier_t barrier;

// 割り込み要求をリストに登録します。
int
intr_request_irq(unsigned int irq, int (*handler)(unsigned int irq, void *dev), int flags, const char *name, void *dev)
{
    struct irq_entry *entry;

    debugf("irq=%u, flags=%d, name=%s", irq, flags, name);
    for (entry = irqs; entry; entry = entry->next) {
        if (entry->irq == irq) {
            if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED) {
                errorf("conflicts with already registered IRQs");
                return -1;
            }
        }
    }
    entry = memory_alloc(sizeof(*entry));
    if (!entry) {
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->irq = irq;
    entry->handler = handler;
    entry->flags = flags;
    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->dev = dev;
    entry->next = irqs;
    irqs = entry;
    sigaddset(&sigmask, irq);
    debugf("registered: irq=%u, name=%s", irq, name);
    return 0;
}

// 割り込み処理スレッドにシグナルを送信します。
int
intr_raise_irq(unsigned int irq)
{
    return pthread_kill(tid, (int)irq);
}

static int
intr_timer_setup(struct itimerspec *interval)
{
}

// 割り込み処理スレッドです。
static void *
intr_thread(void *arg)
{
    int terminate = 0, sig, err;
    struct irq_entry *entry;

    debugf("start...");
    pthread_barrier_wait(&barrier);
    while (!terminate) {
        // シグナルを受信します。
        err = sigwait(&sigmask, &sig);
        if (err) {
            errorf("sigwait() %s", strerror(err));
            break;
        }
        switch (sig) {
        case SIGHUP:
            terminate = 1;
            break;
        case SIGUSR1:
            // ソフトウェア割り込みハンドラを呼び出します。
            net_softirq_handler();
            break;
        default:
            // 割り込み要求リストを走査し、割り込み番号が一致する割り込み要求があれば
            // その割り込みハンドラを呼び出す。
            for (entry = irqs; entry; entry = entry->next) {
                if (entry->irq == (unsigned int)sig) {
                    debugf("irq=%d, name=%s", entry->irq, entry->name);
                    entry->handler(entry->irq, entry->dev);
                }
            }
            break;
        }
    }
    debugf("terminated");
    return NULL;
}

// 割り込み機構を起動します。
int
intr_run(void)
{
    int err;

    err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
    if (err) {
        errorf("pthread_sigmask() %s", strerror(err));
        return -1;
    }
    // 割り込み処理スレッドを起動します。
    err = pthread_create(&tid, NULL, intr_thread, NULL);
    if (err) {
        errorf("pthread_create() %s", strerror(err));
        return -1;
    }
    pthread_barrier_wait(&barrier);
    return 0;
}

// 割り込み機構を停止します。
void
intr_shutdown(void)
{
    if (pthread_equal(tid, pthread_self() != 0)) {
        /* Thread not created. */
        return;
    }
    pthread_kill(tid, SIGHUP);
    pthread_join(tid, NULL);
}

// 割り込み機構を初期化します。
int
intr_init(void)
{
    tid = pthread_self();
    pthread_barrier_init(&barrier, NULL, 2);
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGHUP);
    sigaddset(&sigmask, SIGUSR1);
    return 0;
}