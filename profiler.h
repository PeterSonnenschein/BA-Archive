enum Type {
    SCHED = 1,
    RW,
    ANB,
};

struct report_event {
    enum Type type;
    pid_t pid;
    uint32_t thread_nid;
    uint32_t folio_nid;
    uint32_t nr;
    uint64_t latency;
    uint64_t time;
};

