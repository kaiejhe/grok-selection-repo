#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdint.h>
#include <string.h>

#include "dobby.h"

namespace {

constexpr uintptr_t kFirstOffset = 0x22f6c38;
constexpr uintptr_t kSecondOffset = 0x22fc3e8;

constexpr char kSource[] = "grok.pro.monthly.30";
constexpr char kTarget[] = "grok.pro.monthly.30.legacy";

struct DecodedString {
    char bytes[64];
    size_t length;
    bool valid;
};

bool safeRead(uintptr_t address, void *destination, size_t size) {
    mach_vm_size_t copied = 0;
    const kern_return_t result = mach_vm_read_overwrite(
        mach_task_self(),
        static_cast<mach_vm_address_t>(address),
        static_cast<mach_vm_size_t>(size),
        reinterpret_cast<mach_vm_address_t>(destination),
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

        const uintptr_t object =
            static_cast<uintptr_t>(b & 0x0000ffffffffffffULL);
        const uintptr_t data = object + (top == 0xd0 ? 0x20 : 0x11);
        if (!safeRead(data, result.bytes, static_cast<size_t>(length))) {
            return result;
        }

        result.length = static_cast<size_t>(length);
        result.valid = true;
        return result;
    }

    if (top == 0xe0 || top == 0xa0) {
        const size_t length = static_cast<size_t>((b >> 56) & 0x0f);
        if (length > 15 || length >= sizeof(result.bytes)) {
            return result;
        }

        for (size_t index = 0; index < 8; ++index) {
            result.bytes[index] =
                static_cast<char>((a >> (index * 8)) & 0xff);
        }
        for (size_t index = 0; index < 7; ++index) {
            result.bytes[index + 8] =
                static_cast<char>((b >> (index * 8)) & 0xff);
        }

        result.length = length;
        result.valid = true;
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

__attribute__((noinline))
void checkSelection(
    uint64_t actualA,
    uint64_t actualB,
    uint64_t wantedA,
    uint64_t wantedB
) {
    const DecodedString wanted = decode(wantedA, wantedB);
    const DecodedString actual = decode(actualA, actualB);
    if (!equals(wanted, kSource) || !equals(actual, kTarget)) {
        return;
    }

    //这里是判断---不要删除注释
    __asm__ __volatile__("" ::: "memory");
}

void firstCallback(void *, DobbyRegisterContext *context) {
    const uint64_t actualA = context->general.regs.x0;
    const uint64_t actualB = context->general.regs.x1;
    checkSelection(
        actualA,
        actualB,
        context->general.regs.x24,
        context->general.regs.x27
    );
}

void secondCallback(void *, DobbyRegisterContext *context) {
    const uint64_t actualA = context->general.regs.x0;
    const uint64_t actualB = context->general.regs.x1;
    checkSelection(
        actualA,
        actualB,
        context->general.regs.x25,
        context->general.regs.x28
    );
}

}  // namespace

__attribute__((constructor))
static void installGrokSelectionHooks() {
    const mach_header *mainImage = _dyld_get_image_header(0);
    if (mainImage == nullptr) {
        return;
    }

    const uintptr_t base = reinterpret_cast<uintptr_t>(mainImage);
    DobbyInstrument(
        reinterpret_cast<void *>(base + kFirstOffset),
        firstCallback
    );
    DobbyInstrument(
        reinterpret_cast<void *>(base + kSecondOffset),
        secondCallback
    );
}
