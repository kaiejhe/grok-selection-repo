#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <stdint.h>
#include <string.h>
#include "dobby.h"

namespace {

constexpr uintptr_t kFirstOffset  = 0x22f6c38;
constexpr uintptr_t kSecondOffset = 0x22fc3e8;

constexpr char kSource[] = "grok.pro.monthly.30";
constexpr char kTarget[] = "grok.pro.monthly.30.legacy";

struct DecodedString {
    char bytes[64];
    size_t length;
    bool valid;
};

bool safeRead(uintptr_t address, void *destination, size_t size) {
    vm_size_t copied = 0;
    const kern_return_t result = vm_read_overwrite(
        mach_task_self(),
        static_cast<vm_address_t>(address),
        static_cast<vm_size_t>(size),
        reinterpret_cast<vm_address_t>(destination),
        &copied
    );
    return result == KERN_SUCCESS && copied == size;
}

DecodedString decode(uint64_t a, uint64_t b) {
    DecodedString result = {};
    const uint64_t top = a >> 56;

    if (top == 0xd0 || top == 0xc0) {
        const uint64_t length = a & 0x00ffffffffffffffULL;
        if (length >= sizeof(result.bytes)) {
            return result;
        }

        const uintptr_t object = static_cast<uintptr_t>(b & 0x0000ffffffffffffULL);
        const uintptr_t data   = object + (top == 0xd0 ? 0x20 : 0x11);

        if (!safeRead(data, result.bytes, static_cast<size_t>(length))) {
            return result;
        }

        result.length = static_cast<size_t>(length);
        result.valid  = true;
        return result;
    }

    if (top == 0xe0 || top == 0xa0) {
        const size_t length = static_cast<size_t>((b >> 56) & 0x0f);
        if (length > 15 || length >= sizeof(result.bytes)) {
            return result;
        }

        for (size_t i = 0; i < 8; ++i) {
            result.bytes[i] = static_cast<char>((a >> (i * 8)) & 0xff);
        }
        for (size_t i = 0; i < 7; ++i) {
            result.bytes[i + 8] = static_cast<char>((b >> (i * 8)) & 0xff);
        }

        result.length = length;
        result.valid  = true;
    }

    return result;
}

template <size_t N>
bool equals(const DecodedString &value, const char (&expected)[N]) {
    constexpr size_t expectedLength = N - 1;
    return value.valid &&
           value.length == expectedLength &&
           memcmp(value.bytes, expected, expectedLength) == 0;
}

// 核心替换逻辑（对应原来 JS 的 this.context[wantedA] = actualA）
__attribute__((noinline))
void doSubstitution(uint64_t *regA, uint64_t *regB,
                    uint64_t actualA, uint64_t actualB) {
    //这里是判断---不要删除注释
    *regA = actualA;
    *regB = actualB;
}

void firstCallback(void *, DobbyRegisterContext *context) {
    const uint64_t actualA = context->general.regs.x0;
    const uint64_t actualB = context->general.regs.x1;
    const uint64_t wantedA = context->general.regs.x24;
    const uint64_t wantedB = context->general.regs.x27;

    const DecodedString wanted = decode(wantedA, wantedB);
    const DecodedString actual = decode(actualA, actualB);

    if (!equals(wanted, kSource) || !equals(actual, kTarget)) {
        return;
    }

    // 对应原来 JS：this.context.x24 = actualA; this.context.x27 = actualB;
    doSubstitution(&context->general.regs.x24,
                   &context->general.regs.x27,
                   actualA, actualB);
}

void secondCallback(void *, DobbyRegisterContext *context) {
    const uint64_t actualA = context->general.regs.x0;
    const uint64_t actualB = context->general.regs.x1;
    const uint64_t wantedA = context->general.regs.x25;
    const uint64_t wantedB = context->general.regs.x28;

    const DecodedString wanted = decode(wantedA, wantedB);
    const DecodedString actual = decode(actualA, actualB);

    if (!equals(wanted, kSource) || !equals(actual, kTarget)) {
        return;
    }

    // 对应原来 JS：this.context.x25 = actualA; this.context.x28 = actualB;
    doSubstitution(&context->general.regs.x25,
                   &context->general.regs.x28,
                   actualA, actualB);
}

} // namespace

__attribute__((constructor))
static void installGrokLegacySelectionHooks() {
    const mach_header *header = _dyld_get_image_header(0);
    if (header == nullptr) {
        return;
    }

    const uintptr_t base = reinterpret_cast<uintptr_t>(header);

    DobbyInstrument(reinterpret_cast<void *>(base + kFirstOffset),  firstCallback);
    DobbyInstrument(reinterpret_cast<void *>(base + kSecondOffset), secondCallback);
}
