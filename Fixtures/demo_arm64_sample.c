#include <stdint.h>
#include <stdio.h>

uint32_t demo_fnv1a32(const char *data) {
    uint32_t hash = 2166136261u;
    while (*data != '\0') {
        hash ^= (uint8_t)(*data++);
        hash *= 16777619u;
    }
    return hash;
}

int demo_classify_packet(int opcode, uint32_t payload) {
    if (opcode == 1) {
        return (payload > 100u) ? 10 : 20;
    }
    if (opcode == 2) {
        return (int)(payload & 0xffu);
    }
    return -1;
}

int main(int argc, const char **argv) {
    const char *label = (argc > 1) ? argv[1] : "machgraph-demo-fixture";
    uint32_t digest = demo_fnv1a32(label);
    int code = demo_classify_packet(argc, digest);
    printf("[DEMO] digest=0x%08x class=%d\n", digest, code);
    return 0;
}
